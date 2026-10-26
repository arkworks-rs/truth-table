//! TruthTable++ Range Check (appendix §8, PIOP 22), run inline: every active entry of
//! a column lies in `[0, 2^w)`.
//!
//! A width of at most 16 is one lookup of the activated column into
//! `range_w`. A wider column is split into `k` 16-bit limbs and a β-bit
//! residual, `16k + β = w` with `1 ≤ β ≤ 16`: the prover commits the limbs
//! (little-endian), a zerocheck pins `a·d` to their recomposition, and each
//! limb is looked up in `range_16` (the residual in `range_β`).
//! `w + 1 < MODULUS_BIT_SIZE − 2` keeps `[0, 2^w)` apart from the negations
//! of `[1, 2^w]` in the field, which a sign check built on this relies on.

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{ArgVerifier, errors::VerifierError, structs::oracle::TrackedOracle},
};

use super::SignNode;

const LIMB_BITS: usize = 16;

/// Whether the field holds `[0, 2^width)` with room to spare.
fn width_fits<F: PrimeField>(width: usize) -> bool {
    width + 1 < (F::MODULUS_BIT_SIZE as usize).saturating_sub(2)
}

/// The limb widths of `width > 16`, least significant first.
fn limb_widths(width: usize) -> Vec<usize> {
    let full = (width - 1) / LIMB_BITS;
    let mut widths = vec![LIMB_BITS; full];
    widths.push(width - LIMB_BITS * full);
    widths
}

pub fn prove<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    col: &TrackedCol<B>,
    width: usize,
) -> SnarkResult<()> {
    assert!(
        width_fits::<B::F>(width),
        "a range check of width {width} does not fit the field"
    );
    if width <= LIMB_BITS {
        return SignNode::<B>::add_range_inclusion(prover, col, width);
    }
    let widths = limb_widths(width);
    let activated = col.activated_data_tracked_poly();
    let values = activated.evaluations();
    let mut limb_values = vec![Vec::with_capacity(values.len()); widths.len()];
    for value in &values {
        let bigint = value.into_bigint();
        let words = bigint.as_ref();
        for (i, limb_width) in widths.iter().enumerate() {
            let offset = i * LIMB_BITS;
            let word = words.get(offset / 64).copied().unwrap_or(0);
            let limb = (word >> (offset % 64)) & ((1u64 << limb_width) - 1);
            limb_values[i].push(B::F::from(limb));
        }
    }
    let log_size = activated.log_size();
    let limbs = limb_values
        .into_iter()
        .map(|evals| {
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, evals))
        })
        .collect::<SnarkResult<Vec<TrackedPoly<B>>>>()?;
    let shift = B::F::from(1u64 << LIMB_BITS);
    let (top, lower) = limbs.split_last().expect("a wide range has limbs");
    let recomposed = lower
        .iter()
        .rev()
        .fold(top.clone(), |acc, limb| &acc.mul_scalar_poly(shift) + limb);
    prover.add_mv_zerocheck_claim((&activated - &recomposed).id())?;
    for (limb, limb_width) in limbs.into_iter().zip(widths) {
        SignNode::<B>::add_range_inclusion(prover, &TrackedCol::new(limb, None, None), limb_width)?;
    }
    Ok(())
}

pub fn verify<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    col: &TrackedColOracle<B>,
    width: usize,
) -> SnarkResult<()> {
    if !width_fits::<B::F>(width) {
        return Err(SnarkError::VerifierError(
            VerifierError::VerifierCheckFailed(format!(
                "a range check of width {width} does not fit the field"
            )),
        ));
    }
    if width <= LIMB_BITS {
        return SignNode::<B>::add_range_inclusion_oracle(verifier, col, width);
    }
    let widths = limb_widths(width);
    let activated = col.activated_data_tracked_oracle();
    let limbs = widths
        .iter()
        .map(|_| verifier.track_next_mv_com())
        .collect::<SnarkResult<Vec<TrackedOracle<B>>>>()?;
    let shift = B::F::from(1u64 << LIMB_BITS);
    let (top, lower) = limbs.split_last().expect("a wide range has limbs");
    let recomposed = lower.iter().rev().fold(top.clone(), |acc, limb| {
        &acc.mul_scalar_oracle(shift) + limb
    });
    verifier.add_mv_zerocheck_claim((&activated - &recomposed).id());
    for (limb, limb_width) in limbs.into_iter().zip(widths) {
        SignNode::<B>::add_range_inclusion_oracle(
            verifier,
            &TrackedColOracle::new(limb, None, None),
            limb_width,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
