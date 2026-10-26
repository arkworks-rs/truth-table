//! TruthTable++ Lexicographic Sort Check (appendix §13, PIOP 27), run inline: every
//! pair `j` with `t_0[j] = 1` has
//! `(d_1[j], …, d_m[j]) ≤_lex (d'_1[j], …, d'_m[j])`, strictly in strict
//! mode, each key in its own direction. Step 2(a), the Rotation Check that
//! binds `d'_i`, is the caller's
//! ([`contig_sort::rotation`](crate::irs::nodes::utils::contig_sort::rotation)),
//! so that one multiset check covers every column a caller rotates.
//!
//! For each key `i` the prover commits `t_i = t_{i−1}·1[d_i = d'_i]`, and the
//! check proves (b) `Bool(t_i)` and `t_i·(1 − t_{i−1}) = 0`, (c)
//! `t_i·(d'_i − d_i) = 0` and (d) that `(d'_i − d_i − 1)·t_{i−1}·(1 − t_i)`
//! is in `[0, 2^{w_i})` (`d_i − d'_i` for a descending key). Two deviations
//! from the paper: (d) is a range check that certifies `[1, 2^{w_i}]`, which
//! needs no NoZero check; and strict mode does not commit `t_m` and sumcheck
//! it, it substitutes `t_m = 0`, so (b) and (c) vanish for the last key and
//! (d) runs under `t_{m−1}` (with no keys it is the zerocheck `t_0 = 0`).
//!
//! Every claim carries a factor `t_i` or `t_{i−1}`, both at most `t_0`, so
//! the rows of `d'` the Rotation Check leaves free are never read.
//! Soundness needs `|d'_i − d_i| < 2^{w_i}` on the compared pairs.

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::{One, Zero};
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{ArgVerifier, errors::VerifierError, structs::oracle::TrackedOracle},
};
use datafusion::arrow::datatypes::DataType;
use either::Either;

use crate::irs::nodes::utils::{contig_sort::difference_sign_type, sign::range};

pub mod character_projection;
pub mod rank_certification;
pub mod sortedness;
pub mod string_sort;

/// The width of a character projection key, whose values are in
/// `[−1, 2^α)` with `α = 8` (§7.2): `α + 1`.
pub const PROJECTION_WIDTH: usize = 9;

/// The width bounding the adjacent difference of an integer sort key, from
/// [`difference_sign_type`]; `None` for a key whose encoding does not
/// preserve its order.
pub fn integer_key_width(data_type: &DataType) -> Option<usize> {
    match difference_sign_type(data_type)? {
        DataType::UInt8 => Some(8),
        DataType::UInt16 => Some(16),
        DataType::UInt32 => Some(32),
        DataType::UInt64 => Some(64),
        DataType::Decimal128(..) => Some(128),
        _ => None,
    }
}

/// A tie indicator over `2^log_size` rows of which the first `active_rows`
/// are active: Boolean and at most `C_{µ,s−1}`, so it marks a subset of the
/// adjacent pairs `(j, j + 1)`. A check takes one as `t_0` and returns its
/// `t_m` as one. Only [`Tie::mask`] and the checks of this module and its
/// children build one, each from a column they have certified: a committed
/// column the prover chose would let it switch comparisons off.
#[derive(Clone)]
pub struct Tie<P> {
    poly: P,
    log_size: usize,
    active_rows: usize,
}

impl<P> Tie<P> {
    fn new(poly: P, log_size: usize, active_rows: usize) -> Self {
        Self {
            poly,
            log_size,
            active_rows,
        }
    }

    pub fn poly(&self) -> &P {
        &self.poly
    }

    pub fn log_size(&self) -> usize {
        self.log_size
    }

    pub fn active_rows(&self) -> usize {
        self.active_rows
    }
}

impl<B: SnarkBackend> Tie<TrackedPoly<B>> {
    /// The public `C_{µ,s−1}`: every adjacent pair of the `s` active rows.
    pub fn mask(
        prover: &mut ArgProver<B>,
        log_size: usize,
        active_rows: usize,
    ) -> SnarkResult<Self> {
        let poly = prover.get_or_build_contig_one_poly(log_size, active_rows.saturating_sub(1))?;
        Ok(Self::new(poly, log_size, active_rows))
    }

    fn zero(&self) -> Self {
        let poly = TrackedPoly::new(
            Either::Right(B::F::zero()),
            self.log_size,
            self.poly.tracker(),
        );
        Self::new(poly, self.log_size, self.active_rows)
    }
}

impl<B: SnarkBackend> Tie<TrackedOracle<B>> {
    pub fn mask_oracle(
        verifier: &mut ArgVerifier<B>,
        log_size: usize,
        active_rows: usize,
    ) -> SnarkResult<Self> {
        let poly =
            verifier.get_or_build_contig_one_poly(log_size, active_rows.saturating_sub(1))?;
        Ok(Self::new(poly, log_size, active_rows))
    }

    fn zero(&self) -> Self {
        let poly = TrackedOracle::new(
            Either::Right(B::F::zero()),
            self.poly.tracker(),
            self.log_size,
        );
        Self::new(poly, self.log_size, self.active_rows)
    }
}

/// One sort key: its column, the rotated copy `next[j] = data[j + 1]` the
/// caller has bound, its direction, and a width bounding `|next − data|` on
/// the compared pairs.
pub struct SortKey<P> {
    pub data: P,
    pub next: P,
    pub asc: bool,
    pub width: usize,
}

fn check_failed(message: &str) -> SnarkError {
    SnarkError::VerifierError(VerifierError::VerifierCheckFailed(message.to_string()))
}

/// How many tie indicators the prover commits: `t_m` is not committed in
/// strict mode.
fn committed_ties(keys: usize, strict: bool) -> usize {
    if strict { keys.saturating_sub(1) } else { keys }
}

/// Proves the check on `keys` from `tie` and returns `t_m`, the pairs still
/// tied after the last key. In strict mode `t_m = 0` is proved and returned.
/// With fewer than two active rows there is no pair and nothing is proved.
pub fn prove<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    keys: &[SortKey<TrackedPoly<B>>],
    tie: Tie<TrackedPoly<B>>,
    strict: bool,
) -> SnarkResult<Tie<TrackedPoly<B>>> {
    if tie.active_rows <= 1 {
        return Ok(tie.zero());
    }
    let mut previous = tie.poly.evaluations();
    let ties = keys[..committed_ties(keys.len(), strict)]
        .iter()
        .map(|key| {
            let data = key.data.evaluations();
            let next = key.next.evaluations();
            for (j, t) in previous.iter_mut().enumerate() {
                if data[j] != next[j] {
                    *t = B::F::zero();
                }
            }
            previous.clone()
        })
        .collect();
    prove_with_ties(prover, keys, tie, strict, ties)
}

/// [`prove`] on at least two active rows, with the committed tie indicators
/// `ties` given.
fn prove_with_ties<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    keys: &[SortKey<TrackedPoly<B>>],
    tie: Tie<TrackedPoly<B>>,
    strict: bool,
    ties: Vec<Vec<B::F>>,
) -> SnarkResult<Tie<TrackedPoly<B>>> {
    let ties = ties
        .into_iter()
        .map(|evals| {
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(tie.log_size, evals))
        })
        .collect::<SnarkResult<Vec<_>>>()?;
    if keys.is_empty() && strict {
        prover.add_mv_zerocheck_claim(tie.poly.id())?;
    }
    let one = B::F::one();
    let mut previous = tie.poly.clone();
    for (key, current) in keys.iter().zip(ties.iter().map(Some).chain([None])) {
        let step = if key.asc {
            &key.next - &key.data
        } else {
            &key.data - &key.next
        };
        let broken = match current {
            Some(current) => {
                let not_current = current.mul_scalar_poly(-one).add_scalar_poly(one);
                prover.add_mv_zerocheck_claim((current * &not_current).id())?;
                let not_previous = previous.mul_scalar_poly(-one).add_scalar_poly(one);
                prover.add_mv_zerocheck_claim((current * &not_previous).id())?;
                prover.add_mv_zerocheck_claim((current * &step).id())?;
                &previous * &not_current
            }
            None => previous.clone(),
        };
        let gap = TrackedCol::new(step.sub_scalar_poly(one), Some(broken), None);
        range::prove(prover, &gap, key.width)?;
        if let Some(current) = current {
            previous = current.clone();
        }
    }
    Ok(if strict {
        tie.zero()
    } else {
        Tie::new(previous, tie.log_size, tie.active_rows)
    })
}

pub fn verify<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    keys: &[SortKey<TrackedOracle<B>>],
    tie: Tie<TrackedOracle<B>>,
    strict: bool,
) -> SnarkResult<Tie<TrackedOracle<B>>> {
    if tie.active_rows <= 1 {
        return Ok(tie.zero());
    }
    let ties = (0..committed_ties(keys.len(), strict))
        .map(|_| verifier.track_next_mv_com())
        .collect::<SnarkResult<Vec<_>>>()?;
    if keys.is_empty() && strict {
        verifier.add_mv_zerocheck_claim(tie.poly.id());
    }
    let one = B::F::one();
    let mut previous = tie.poly.clone();
    for (key, current) in keys.iter().zip(ties.iter().map(Some).chain([None])) {
        let step = if key.asc {
            &key.next - &key.data
        } else {
            &key.data - &key.next
        };
        let broken = match current {
            Some(current) => {
                let not_current = current.mul_scalar_oracle(-one).add_scalar_oracle(one);
                verifier.add_mv_zerocheck_claim((current * &not_current).id());
                let not_previous = previous.mul_scalar_oracle(-one).add_scalar_oracle(one);
                verifier.add_mv_zerocheck_claim((current * &not_previous).id());
                verifier.add_mv_zerocheck_claim((current * &step).id());
                &previous * &not_current
            }
            None => previous.clone(),
        };
        let gap = TrackedColOracle::new(step.sub_scalar_oracle(one), Some(broken), None);
        range::verify(verifier, &gap, key.width)?;
        if let Some(current) = current {
            previous = current.clone();
        }
    }
    Ok(if strict {
        tie.zero()
    } else {
        Tie::new(previous, tie.log_size, tie.active_rows)
    })
}

#[cfg(test)]
mod tests;
