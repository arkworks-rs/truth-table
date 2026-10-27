//! TruthTable++ Rotation Check (appendix §12, PIOP 26) run inline, for checks that
//! compare each active row with the next: for pairs `(d, d')` it proves
//! `d'[j] = d[j + 1]` for every `j < s − 1`, with one multiset check of the
//! sort check's shift tables `(C_{µ,s−1}, [idx + 1, d'…])` and
//! `(C_{µ,s} − eq(X, 0), [idx, d…])` over all pairs together. The paper's
//! cyclic wrap-around is not proved: every activator a caller compares under
//! is at most `C_{µ,s−1}`, so row `s − 1` of `d'` is never read.

use ark_ff::One;
use ark_piop::{
    SnarkBackend,
    errors::SnarkResult,
    piop::PIOP,
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};

use crate::irs::nodes::utils::nodup::perm_check::{
    PermPIOP, PermPIOPProverInput, PermPIOPVerifierInput,
};

const FOLD_CHALLENGE_LABEL: &[u8] = b"rotation_fold";

/// `columns` are `(d, d')` pairs over `2^log_size` rows of which the first
/// `s` are active. The fold challenges are drawn here, so every `d'` must be
/// committed before the call. With fewer than two active rows there is no
/// pair and nothing is proved.
pub fn prove<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    columns: &[(TrackedPoly<B>, TrackedPoly<B>)],
    log_size: usize,
    s: usize,
) -> SnarkResult<()> {
    if s <= 1 || columns.is_empty() {
        return Ok(());
    }
    let mask = prover.get_or_build_contig_one_poly(log_size, s - 1)?;
    let (left, right) = super::shift_tables_prover(prover, columns, &mask, s)?;
    let mut challenges = vec![B::F::one()];
    for _ in columns {
        challenges.push(prover.get_and_append_challenge(FOLD_CHALLENGE_LABEL)?);
    }
    PermPIOP::<B>::prove(
        prover,
        PermPIOPProverInput {
            left_col: left.fold(&left.data_tracked_polys_indices(), &challenges),
            right_col: right.fold(&right.data_tracked_polys_indices(), &challenges),
        },
    )
}

pub fn verify<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    columns: &[(TrackedOracle<B>, TrackedOracle<B>)],
    log_size: usize,
    s: usize,
) -> SnarkResult<()> {
    if s <= 1 || columns.is_empty() {
        return Ok(());
    }
    let mask = verifier.get_or_build_contig_one_poly(log_size, s - 1)?;
    let (left, right) = super::shift_tables_verifier(verifier, columns, &mask, s)?;
    let mut challenges = vec![B::F::one()];
    for _ in columns {
        challenges.push(verifier.get_and_append_challenge(FOLD_CHALLENGE_LABEL)?);
    }
    PermPIOP::<B>::verify(
        verifier,
        PermPIOPVerifierInput {
            left_tracked_col_oracle: left.fold(&left.data_tracked_oracles_indices(), &challenges),
            right_tracked_col_oracle: right
                .fold(&right.data_tracked_oracles_indices(), &challenges),
        },
    )
}
