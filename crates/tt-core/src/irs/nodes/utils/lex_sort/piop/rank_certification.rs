//! TruthTable++ Rank Certification Check (§7.3, PIOP 12): the rank column
//! `rk` of a string column `s` is monotone in the lexicographic order and
//! separates exactly the distinct strings.
//!
//! 1. The prover commits `n`, the sorted copy `s^π` (`src^π`, every hash slot
//!    `h^π`, `l^π`) and `rk^π`, its rows the active rows of `s` by rank then
//!    index. A lookup `(src^π, h^π…, l^π, rk^π)` under `C_{µ,n}` ⊑
//!    `(idx, h…, l, rk)` under `a` takes each row from the base, and the
//!    multiset check of `src^π` under `C_{µ,n}` against `idx` under `a` makes
//!    `src^π` a bijection onto the active rows.
//! 2. The paper's NonNeg check on `rk^{π,next} − rk^π` is implied by step 4
//!    and dropped.
//! 3. The Lexicographic Sortedness Check on `s^π` with `index = src^π`, which
//!    rotates `rk^π` with the hash and returns `same^π` and `rk^{π,next}`.
//! 4. `same^π·(rk^{π,next} − rk^π) = 0`, and `rk^{π,next} − rk^π − 1` is in
//!    `[0, 2^µ)` under `C_{µ,n−1}·(1 − same^π)`: a rank of a table of `2^µ`
//!    rows is below `2^µ`.
//!
//! `idx` is the public identity, which the character table's `orig-ind`
//! refers to. The check reads the characters, so it certifies `rk` only
//! against a character table the verifier trusts.

use arithmetic::col::TrackedCol;
use arithmetic::col_oracle::TrackedColOracle;
use ark_ff::{One, PrimeField, Zero};
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::SnarkResult,
    piop::PIOP,
    prover::{
        ArgProver,
        structs::polynomial::{TrackedPoly, get_or_insert_shift_poly},
    },
    verifier::{
        ArgVerifier,
        structs::oracle::{TrackedOracle, get_or_insert_shift_oracle},
    },
};

use super::{
    character_projection::Characters,
    check_failed,
    sortedness::{self, SortedStrings, Witness},
};
use crate::irs::nodes::utils::{
    contig_sort::piop::Tie,
    field_to_usize,
    lookup::piop::{LookupPIOP, LookupProverInput, LookupVerifierInput},
    nodup::perm_check::{PermPIOP, PermPIOPProverInput, PermPIOPVerifierInput},
    sign::range,
};

const FOLD_LABEL: &[u8] = b"rank_certification_fold";

/// The base string column under its activator `a`.
pub struct RankedStrings<P> {
    pub hash: Vec<P>,
    pub length: P,
    pub rank: P,
    pub activator: P,
}

pub fn prove<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    strings: &RankedStrings<TrackedPoly<B>>,
    chars: &Characters<TrackedPoly<B>>,
    log_size: usize,
) -> SnarkResult<()> {
    let activator = strings.activator.evaluations();
    let rank = strings.rank.evaluations();
    let mut order: Vec<usize> = (0..activator.len())
        .filter(|&i| !activator[i].is_zero())
        .collect();
    order.sort_by_key(|&i| (rank[i].into_bigint(), i));
    prove_in_order(prover, strings, chars, log_size, order, |_| {})
}

/// [`prove`] with the rows of the sorted copy given, and `forge` applied to
/// the Lexicographic Sortedness Check's witness.
fn prove_in_order<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    strings: &RankedStrings<TrackedPoly<B>>,
    chars: &Characters<TrackedPoly<B>>,
    log_size: usize,
    order: Vec<usize>,
    forge: impl FnOnce(&mut Witness<B::F>),
) -> SnarkResult<()> {
    let n = order.len();
    prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(0, vec![B::F::from(n as u64)]))?;
    let mut commit = |values: Vec<B::F>| {
        let mut sorted: Vec<B::F> = order.iter().map(|&i| values[i]).collect();
        sorted.resize(1 << log_size, B::F::zero());
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, sorted))
    };
    let src = commit((0..1 << log_size).map(|i| B::F::from(i as u64)).collect())?;
    let hash = strings
        .hash
        .iter()
        .map(|h| commit(h.evaluations()))
        .collect::<SnarkResult<Vec<_>>>()?;
    let length = commit(strings.length.evaluations())?;
    let rank = commit(strings.rank.evaluations())?;

    let index = get_or_insert_shift_poly(prover, log_size, 0, true);
    let sorted_activator = prover.get_or_build_contig_one_poly(log_size, n)?;
    let mut included = src.clone();
    let mut base = index.clone();
    for (copy, column) in hash
        .iter()
        .chain([&length, &rank])
        .zip(strings.hash.iter().chain([&strings.length, &strings.rank]))
    {
        let beta = prover.get_and_append_challenge(FOLD_LABEL)?;
        included = &included + &copy.mul_scalar_poly(beta);
        base = &base + &column.mul_scalar_poly(beta);
    }
    LookupPIOP::<B>::prove(
        prover,
        LookupProverInput {
            included_cols: vec![TrackedCol::new(
                included,
                Some(sorted_activator.clone()),
                None,
            )],
            super_col: TrackedCol::new(base, Some(strings.activator.clone()), None),
        },
    )?;
    PermPIOP::<B>::prove(
        prover,
        PermPIOPProverInput {
            left_col: TrackedCol::new(src.clone(), Some(sorted_activator), None),
            right_col: TrackedCol::new(index, Some(strings.activator.clone()), None),
        },
    )?;

    let tie = Tie::mask(prover, log_size, n)?;
    let sorted = SortedStrings {
        index: src,
        hash,
        length,
    };
    let extras = [rank.clone()];
    let mut witness = sortedness::witness(&sorted, chars, &tie, &extras)?;
    forge(&mut witness);
    let output = sortedness::prove_with_witness(
        prover,
        &sorted,
        chars,
        tie.clone(),
        &extras,
        true,
        witness,
    )?;
    if n <= 1 {
        return Ok(());
    }
    let one = B::F::one();
    let step = &output.extras_next[0] - &rank;
    prover.add_mv_zerocheck_claim((output.same.poly() * &step).id())?;
    let not_same = output
        .same
        .poly()
        .mul_scalar_poly(-one)
        .add_scalar_poly(one);
    let gap = TrackedCol::new(
        step.sub_scalar_poly(one),
        Some(tie.poly() * &not_same),
        None,
    );
    range::prove(prover, &gap, log_size)
}

pub fn verify<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    strings: &RankedStrings<TrackedOracle<B>>,
    chars: &Characters<TrackedOracle<B>>,
    log_size: usize,
) -> SnarkResult<()> {
    let committed = verifier.track_next_mv_com()?;
    let n = match committed.as_constant() {
        Some(value) if committed.log_size() == 0 => field_to_usize(value, "the active-row count")?,
        _ => {
            return Err(check_failed(
                "the active-row count is not a committed scalar",
            ));
        }
    };
    if n > 1 << log_size {
        return Err(check_failed("the active-row count exceeds the table"));
    }
    let src = verifier.track_next_mv_com()?;
    let hash = strings
        .hash
        .iter()
        .map(|_| verifier.track_next_mv_com())
        .collect::<SnarkResult<Vec<_>>>()?;
    let length = verifier.track_next_mv_com()?;
    let rank = verifier.track_next_mv_com()?;

    let index = get_or_insert_shift_oracle(verifier, log_size, 0, true);
    let sorted_activator = verifier.get_or_build_contig_one_poly(log_size, n)?;
    let mut included = src.clone();
    let mut base = index.clone();
    for (copy, column) in hash
        .iter()
        .chain([&length, &rank])
        .zip(strings.hash.iter().chain([&strings.length, &strings.rank]))
    {
        let beta = verifier.get_and_append_challenge(FOLD_LABEL)?;
        included = &included + &copy.mul_scalar_oracle(beta);
        base = &base + &column.mul_scalar_oracle(beta);
    }
    LookupPIOP::<B>::verify(
        verifier,
        LookupVerifierInput {
            included_tracked_col_oracles: vec![TrackedColOracle::new(
                included,
                Some(sorted_activator.clone()),
                None,
            )],
            super_tracked_col_oracle: TrackedColOracle::new(
                base,
                Some(strings.activator.clone()),
                None,
            ),
        },
    )?;
    PermPIOP::<B>::verify(
        verifier,
        PermPIOPVerifierInput {
            left_tracked_col_oracle: TrackedColOracle::new(
                src.clone(),
                Some(sorted_activator),
                None,
            ),
            right_tracked_col_oracle: TrackedColOracle::new(
                index,
                Some(strings.activator.clone()),
                None,
            ),
        },
    )?;

    let tie = Tie::mask_oracle(verifier, log_size, n)?;
    let sorted = SortedStrings {
        index: src,
        hash,
        length,
    };
    let extras = [rank.clone()];
    let output = sortedness::verify(verifier, &sorted, chars, tie.clone(), &extras, true)?;
    if n <= 1 {
        return Ok(());
    }
    let one = B::F::one();
    let step = &output.extras_next[0] - &rank;
    verifier.add_mv_zerocheck_claim((output.same.poly() * &step).id());
    let not_same = output
        .same
        .poly()
        .mul_scalar_oracle(-one)
        .add_scalar_oracle(one);
    let gap = TrackedColOracle::new(
        step.sub_scalar_oracle(one),
        Some(tie.poly() * &not_same),
        None,
    );
    range::verify(verifier, &gap, log_size)
}

#[cfg(test)]
mod tests;
