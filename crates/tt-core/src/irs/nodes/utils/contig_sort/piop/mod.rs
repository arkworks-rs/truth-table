//! The sort check (eprint PIOP 7) run inline: every adjacent pair `j` with
//! `t_0[j] = 1` has `(d_1[j], …, d_m[j]) ≤_lex (d'_1[j], …, d'_m[j])`,
//! strictly in strict mode, each key in its own direction. `t_0` is the
//! caller's: `C_{µ,s−1}` for a whole table, or the pairs an earlier check
//! left tied (TruthTable++ PIOPs 10 and 11). Binding `d'_k` is the caller's
//! ([`rotation`](super::rotation)), so that one multiset check covers every
//! column a caller rotates.
//!
//! The prover commits Boolean tie indicators (3(b)), `t_k[j] = 1` claiming
//! pair `j` equal on the first `k` keys. With `δ_k` the step of key `k`
//! (`d'_k − d_k`, negated for a descending key) and `C = C_{µ,s−1}`, the
//! check proves
//! - 3(e): `δ_k ≠ 0` where `t_{k−1}·(1 − t_k)·C = 1` (NoZero);
//! - 3(f): `t_{k−1}·δ_k ∈ [0, 2^{w_k})` under `C` for every key. In strict
//!   mode the last key has `t_{m−1}·(δ_m − 1)` instead, in place of step 4's
//!   committed `t_m = 0`.
//!
//! In the order alone, `t_1, …, t_{m−1}` are committed and 3(c), `t_k ≤
//! t_{k−1}`, and 3(d), `t_k·δ_k = 0`, are not checked: the first `k` with
//! `t_k = 0` on a pair with `t_0 = 1` has `δ_1, …, δ_{k−1} ≥ 0` and `δ_k > 0`,
//! which orders the pair whatever the other ties say. [`End::Tied`] also
//! commits `t_m` and checks 3(c) and 3(d) for every key, which makes `t_m`
//! exactly the pairs tied on every key; a caller that goes on comparing those
//! pairs needs it. Soundness needs `|δ_k| < 2^{w_k}` on the compared pairs.

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

use super::difference_sign_type;
use crate::irs::nodes::utils::sign::range;

const TIE_BREAK_LABEL: &[u8] = b"sort_tie_break";

/// The width bounding the adjacent difference of a sort key whose encoding
/// preserves its order; `None` for one whose encoding does not.
pub fn key_width(data_type: &DataType) -> Option<usize> {
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
/// adjacent pairs `(j, j + 1)`. A check takes one as `t_0`, and
/// [`End::Tied`] returns its `t_m` as one. Only [`Tie::mask`] and the checks
/// that certify a column build one: a committed column the prover chose
/// would let it switch comparisons off.
#[derive(Clone)]
pub struct Tie<P> {
    poly: P,
    log_size: usize,
    active_rows: usize,
}

impl<P> Tie<P> {
    pub(crate) fn new(poly: P, log_size: usize, active_rows: usize) -> Self {
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

    /// No pair: the tie of fewer than two active rows.
    pub(crate) fn zero(&self) -> Self {
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

    pub(crate) fn zero(&self) -> Self {
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

/// What the check proves after the last key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum End {
    NonStrict,
    /// No pair is tied on every key.
    Strict,
    /// Non-strict, and the pairs tied on every key are returned.
    Tied,
}

/// How many tie indicators the prover commits for `keys` keys.
pub fn committed_ties(keys: usize, end: End) -> usize {
    match end {
        End::Tied => keys,
        End::NonStrict | End::Strict => keys.saturating_sub(1),
    }
}

/// Commits the tie indicators of `keys` from `start` and proves the check;
/// returns `t_m` for [`End::Tied`]. With fewer than two active rows there is
/// no pair and nothing is proved.
pub fn prove<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    keys: &[SortKey<TrackedPoly<B>>],
    start: Tie<TrackedPoly<B>>,
    end: End,
) -> SnarkResult<Option<Tie<TrackedPoly<B>>>> {
    if start.active_rows <= 1 {
        return Ok((end == End::Tied).then_some(start));
    }
    let mut previous = start.poly.evaluations();
    let mut ties = Vec::with_capacity(committed_ties(keys.len(), end));
    for key in &keys[..committed_ties(keys.len(), end)] {
        let data = key.data.evaluations();
        let next = key.next.evaluations();
        for (j, t) in previous.iter_mut().enumerate() {
            if data[j] != next[j] {
                *t = B::F::zero();
            }
        }
        ties.push(
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
                start.log_size,
                previous.clone(),
            ))?,
        );
    }
    prove_with_ties(prover, keys, start, end, &ties)
}

/// The check with the committed tie indicators `ties` given:
/// [`committed_ties`] of them.
pub fn prove_with_ties<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    keys: &[SortKey<TrackedPoly<B>>],
    start: Tie<TrackedPoly<B>>,
    end: End,
    ties: &[TrackedPoly<B>],
) -> SnarkResult<Option<Tie<TrackedPoly<B>>>> {
    if ties.len() != committed_ties(keys.len(), end) {
        return Err(SnarkError::VerifierError(
            VerifierError::VerifierCheckFailed(format!(
                "{} keys need {} tie indicators, got {}",
                keys.len(),
                committed_ties(keys.len(), end),
                ties.len()
            )),
        ));
    }
    if start.active_rows <= 1 {
        return Ok((end == End::Tied).then_some(start));
    }
    let one = B::F::one();
    let mask = prover.get_or_build_contig_one_poly(start.log_size, start.active_rows - 1)?;
    for tie in ties {
        let not_tie = tie.mul_scalar_poly(-one).add_scalar_poly(one);
        prover.add_mv_zerocheck_claim((tie * &not_tie).id())?;
    }
    if keys.is_empty() && end == End::Strict {
        prover.add_mv_zerocheck_claim(start.poly.id())?;
    }
    let c = match ties.is_empty() {
        true => B::F::zero(),
        false => prover.get_and_append_challenge(TIE_BREAK_LABEL)?,
    };
    let before: Vec<&TrackedPoly<B>> = std::iter::once(&start.poly).chain(ties).collect();
    for (k, key) in keys.iter().enumerate() {
        let step = if key.asc {
            &key.next - &key.data
        } else {
            &key.data - &key.next
        };
        let tie = before[k];
        let checked = match end == End::Strict && k + 1 == keys.len() {
            true => tie * &step.sub_scalar_poly(one),
            false => tie * &step,
        };
        range::prove(
            prover,
            &TrackedCol::new(checked, Some(mask.clone()), None),
            key.width,
        )?;
        let Some(after) = before.get(k + 1) else {
            continue;
        };
        let not_after = after.mul_scalar_poly(-one).add_scalar_poly(one);
        let broken = &(tie * &not_after) * &mask;
        let lifted = &(&broken * &step) + &broken.mul_scalar_poly(-c).add_scalar_poly(c);
        prover.add_mv_nozerocheck_claim(lifted.id())?;
        if end == End::Tied {
            let not_tie = tie.mul_scalar_poly(-one).add_scalar_poly(one);
            prover.add_mv_zerocheck_claim((*after * &not_tie).id())?;
            prover.add_mv_zerocheck_claim((*after * &step).id())?;
        }
    }
    Ok((end == End::Tied).then(|| {
        let last = (*before.last().expect("t_0")).clone();
        Tie::new(last, start.log_size, start.active_rows)
    }))
}

pub fn verify<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    keys: &[SortKey<TrackedOracle<B>>],
    start: Tie<TrackedOracle<B>>,
    end: End,
) -> SnarkResult<Option<Tie<TrackedOracle<B>>>> {
    if start.active_rows <= 1 {
        return Ok((end == End::Tied).then_some(start));
    }
    let ties = (0..committed_ties(keys.len(), end))
        .map(|_| verifier.track_next_mv_com())
        .collect::<SnarkResult<Vec<_>>>()?;
    verify_with_ties(verifier, keys, start, end, &ties)
}

pub fn verify_with_ties<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    keys: &[SortKey<TrackedOracle<B>>],
    start: Tie<TrackedOracle<B>>,
    end: End,
    ties: &[TrackedOracle<B>],
) -> SnarkResult<Option<Tie<TrackedOracle<B>>>> {
    if ties.len() != committed_ties(keys.len(), end) {
        return Err(SnarkError::VerifierError(
            VerifierError::VerifierCheckFailed(format!(
                "{} keys need {} tie indicators, got {}",
                keys.len(),
                committed_ties(keys.len(), end),
                ties.len()
            )),
        ));
    }
    if start.active_rows <= 1 {
        return Ok((end == End::Tied).then_some(start));
    }
    let one = B::F::one();
    let mask = verifier.get_or_build_contig_one_poly(start.log_size, start.active_rows - 1)?;
    for tie in ties {
        let not_tie = tie.mul_scalar_oracle(-one).add_scalar_oracle(one);
        verifier.add_mv_zerocheck_claim((tie * &not_tie).id());
    }
    if keys.is_empty() && end == End::Strict {
        verifier.add_mv_zerocheck_claim(start.poly.id());
    }
    let c = match ties.is_empty() {
        true => B::F::zero(),
        false => verifier.get_and_append_challenge(TIE_BREAK_LABEL)?,
    };
    let before: Vec<&TrackedOracle<B>> = std::iter::once(&start.poly).chain(ties).collect();
    for (k, key) in keys.iter().enumerate() {
        let step = if key.asc {
            &key.next - &key.data
        } else {
            &key.data - &key.next
        };
        let tie = before[k];
        let checked = match end == End::Strict && k + 1 == keys.len() {
            true => tie * &step.sub_scalar_oracle(one),
            false => tie * &step,
        };
        range::verify(
            verifier,
            &TrackedColOracle::new(checked, Some(mask.clone()), None),
            key.width,
        )?;
        let Some(after) = before.get(k + 1) else {
            continue;
        };
        let not_after = after.mul_scalar_oracle(-one).add_scalar_oracle(one);
        let broken = &(tie * &not_after) * &mask;
        let lifted = &(&broken * &step) + &broken.mul_scalar_oracle(-c).add_scalar_oracle(c);
        verifier.add_mv_nozerocheck_claim(lifted.id());
        if end == End::Tied {
            let not_tie = tie.mul_scalar_oracle(-one).add_scalar_oracle(one);
            verifier.add_mv_zerocheck_claim((*after * &not_tie).id());
            verifier.add_mv_zerocheck_claim((*after * &step).id());
        }
    }
    Ok((end == End::Tied).then(|| {
        let last = (*before.last().expect("t_0")).clone();
        Tie::new(last, start.log_size, start.active_rows)
    }))
}

#[cfg(test)]
mod tests;
