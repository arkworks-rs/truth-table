//! TruthTable++ Character Projection Check (§4.4, PIOP 5), batched over `R`
//! positions and run inline: for every active string row `i` and `k < R`,
//! `c_k[i]` is the `k`-th character of string `i` if `l[i] > k`, and
//! `⊥ = −1` otherwise.
//!
//! Per position the prover commits `g_k = a·1[l > k]`, and the check proves
//! `Bool(g_k)`, `g_k·(1 − a) = 0`, and the Pos check on `(g_k, l − k)` and
//! the NonPos check on `(a·(1 − g_k), l − k)` as range checks of
//! `(l − k − 1)·g_k` and `(k − l)·a·(1 − g_k)` of width `m + 1`, `m` the
//! character domain's log size: `l ≤ 2^m` in a well-formed table and the
//! caller keeps `R ≤ 2^m + 1`. Then one lookup with the `R` included columns
//! `(g_k, ix + r·k + r²·c_k)` against
//! `(char-act, orig-ind + r·int-ind + r²·char)` proves the present
//! characters (§4.4, "Batching across positions"), and
//! `a·(1 − g_k)·(c_k + 1) = 0` forces `⊥` on the rest.
//!
//! Soundness needs a well-formed character table: `char-act` Boolean, the
//! active `(orig-ind, int-ind)` pairs distinct, the active characters of row
//! `i` numbering `a[i]·l[i]`, and every character in `[0, 255]`, so that none
//! equals `⊥`. `r` is drawn here, so the `c_k` must be committed before the
//! call.

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::{One, Zero};
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::SnarkResult,
    piop::PIOP,
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};

use crate::irs::nodes::utils::{
    field_to_usize,
    lookup::piop::{LookupPIOP, LookupProverInput, LookupVerifierInput},
    sign::range,
};

const CHALLENGE_LABEL: &[u8] = b"character_projection_r";

/// The string side under its activator `a`. `index` is the `orig-ind` of
/// each row's characters: the public identity when the characters are the
/// column's own, or a committed source column the caller binds.
pub struct Strings<P> {
    pub index: P,
    pub length: P,
    pub activator: P,
}

/// The character table under its activator `char-act`.
pub struct Characters<P> {
    pub orig_ind: P,
    pub int_ind: P,
    pub chars: P,
    pub activator: P,
}

/// Proves that `projections[k]` is the projection of `strings` onto position
/// `k`.
pub fn prove<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    strings: &Strings<TrackedPoly<B>>,
    chars: &Characters<TrackedPoly<B>>,
    projections: &[TrackedPoly<B>],
) -> SnarkResult<()> {
    if projections.is_empty() {
        return Ok(());
    }
    let length = strings.length.evaluations();
    let activator = strings.activator.evaluations();
    let mut lengths = Vec::with_capacity(length.len());
    for (l, a) in length.iter().zip(&activator) {
        lengths.push(if a.is_zero() {
            0
        } else {
            field_to_usize(*l, "a string length")?
        });
    }
    let indicators = (0..projections.len())
        .map(|k| {
            lengths
                .iter()
                .zip(&activator)
                .map(|(l, a)| if *l > k { *a } else { B::F::zero() })
                .collect()
        })
        .collect();
    prove_with_indicators(prover, strings, chars, projections, indicators)
}

/// [`prove`] for at least one position, with the committed length
/// indicators `g_k` given.
fn prove_with_indicators<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    strings: &Strings<TrackedPoly<B>>,
    chars: &Characters<TrackedPoly<B>>,
    projections: &[TrackedPoly<B>],
    indicators: Vec<Vec<B::F>>,
) -> SnarkResult<()> {
    let row_log_size = strings.index.log_size();
    let width = chars.orig_ind.log_size() + 1;
    let one = B::F::one();
    let indicators = indicators
        .into_iter()
        .map(|evals| {
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(row_log_size, evals))
        })
        .collect::<SnarkResult<Vec<_>>>()?;
    let not_active = strings.activator.mul_scalar_poly(-one).add_scalar_poly(one);
    let mut absent = Vec::with_capacity(indicators.len());
    for (k, g) in indicators.iter().enumerate() {
        let k = B::F::from(k as u64);
        let not_g = g.mul_scalar_poly(-one).add_scalar_poly(one);
        prover.add_mv_zerocheck_claim((g * &not_g).id())?;
        prover.add_mv_zerocheck_claim((g * &not_active).id())?;
        let longer = TrackedCol::new(
            strings.length.sub_scalar_poly(k + one),
            Some(g.clone()),
            None,
        );
        range::prove(prover, &longer, width)?;
        let short = &strings.activator * &not_g;
        let not_longer = TrackedCol::new(
            strings.length.mul_scalar_poly(-one).add_scalar_poly(k),
            Some(short.clone()),
            None,
        );
        range::prove(prover, &not_longer, width)?;
        absent.push(short);
    }
    let r = prover.get_and_append_challenge(CHALLENGE_LABEL)?;
    let included_cols = indicators
        .iter()
        .zip(projections)
        .enumerate()
        .map(|(k, (g, c))| {
            let key = &strings.index.add_scalar_poly(r * B::F::from(k as u64))
                + &c.mul_scalar_poly(r * r);
            TrackedCol::new(key, Some(g.clone()), None)
        })
        .collect();
    let super_key = &(&chars.orig_ind + &chars.int_ind.mul_scalar_poly(r))
        + &chars.chars.mul_scalar_poly(r * r);
    LookupPIOP::<B>::prove(
        prover,
        LookupProverInput {
            included_cols,
            super_col: TrackedCol::new(super_key, Some(chars.activator.clone()), None),
        },
    )?;
    for (short, c) in absent.iter().zip(projections) {
        prover.add_mv_zerocheck_claim((short * &c.add_scalar_poly(one)).id())?;
    }
    Ok(())
}

pub fn verify<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    strings: &Strings<TrackedOracle<B>>,
    chars: &Characters<TrackedOracle<B>>,
    projections: &[TrackedOracle<B>],
) -> SnarkResult<()> {
    if projections.is_empty() {
        return Ok(());
    }
    let width = chars.orig_ind.log_size() + 1;
    let one = B::F::one();
    let indicators = projections
        .iter()
        .map(|_| verifier.track_next_mv_com())
        .collect::<SnarkResult<Vec<_>>>()?;
    let not_active = strings
        .activator
        .mul_scalar_oracle(-one)
        .add_scalar_oracle(one);
    let mut absent = Vec::with_capacity(indicators.len());
    for (k, g) in indicators.iter().enumerate() {
        let k = B::F::from(k as u64);
        let not_g = g.mul_scalar_oracle(-one).add_scalar_oracle(one);
        verifier.add_mv_zerocheck_claim((g * &not_g).id());
        verifier.add_mv_zerocheck_claim((g * &not_active).id());
        let longer = TrackedColOracle::new(
            strings.length.sub_scalar_oracle(k + one),
            Some(g.clone()),
            None,
        );
        range::verify(verifier, &longer, width)?;
        let short = &strings.activator * &not_g;
        let not_longer = TrackedColOracle::new(
            strings.length.mul_scalar_oracle(-one).add_scalar_oracle(k),
            Some(short.clone()),
            None,
        );
        range::verify(verifier, &not_longer, width)?;
        absent.push(short);
    }
    let r = verifier.get_and_append_challenge(CHALLENGE_LABEL)?;
    let included_tracked_col_oracles = indicators
        .iter()
        .zip(projections)
        .enumerate()
        .map(|(k, (g, c))| {
            let key = &strings.index.add_scalar_oracle(r * B::F::from(k as u64))
                + &c.mul_scalar_oracle(r * r);
            TrackedColOracle::new(key, Some(g.clone()), None)
        })
        .collect();
    let super_key = &(&chars.orig_ind + &chars.int_ind.mul_scalar_oracle(r))
        + &chars.chars.mul_scalar_oracle(r * r);
    LookupPIOP::<B>::verify(
        verifier,
        LookupVerifierInput {
            included_tracked_col_oracles,
            super_tracked_col_oracle: TrackedColOracle::new(
                super_key,
                Some(chars.activator.clone()),
                None,
            ),
        },
    )?;
    for (short, c) in absent.iter().zip(projections) {
        verifier.add_mv_zerocheck_claim((short * &c.add_scalar_oracle(one)).id());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
