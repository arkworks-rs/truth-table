//! TruthTable++ String Sort Check (§7.2, PIOP 11), run inline: the output
//! rows, the first `s` under `C_{µ,s}`, are the input's active rows sorted on
//! the keys, a string key in the lexicographic order of its characters.
//!
//! Deviation: the output keeps no character columns, since the ORDER BY is
//! the last white-box use of its strings (§3.2, "Dropping Auxiliary
//! Columns"); the output strings' characters are the input's, re-indexed
//! through `src`. So step 1 is
//! 1. P commits `src`, and a lookup proves `(src, hash slots…, length)` under
//!    `C_{µ,s}` in `(idx, hash slots…, length)` under the input's activator,
//!    over every string key at once (PIOP 3, step 3, with no a-priori source);
//! 2. the multiset of `src` under `C_{µ,s}` equals that of `idx` under the
//!    input's activator. The caller may prove the output a permutation of the
//!    input already; this step is kept for fidelity;
//! 3. the Lexicographic Sortedness Check (PIOP 10) runs on each string key
//!    with `index = src` over the input's character table.
//!
//! The keys are checked in order under one tie indicator `t`, starting at
//! `C_{µ,s−1}`: a run of consecutive value keys is rotated (PIOP 26) and
//! checked by the sort check from `t` (the Lexicographic Sort Check, PIOP
//! 27, non-strict); before a string key the run's `t_m` becomes `t`, and a
//! string key's PIOP 10 runs from `t`, whose `same` becomes `t`.
//!
//! Soundness needs the input's rows indexed by `idx` as its character table's
//! `orig-ind` indexes them, and that character table bound to the input's
//! strings: nothing here binds characters to a hash.

use std::collections::HashMap;

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
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
    sortedness::{self, SortedStrings},
};
use crate::irs::nodes::utils::{
    contig_sort::{
        piop::{self as sort, End, SortKey, Tie},
        rotation,
    },
    lookup::piop::{LookupPIOP, LookupProverInput, LookupVerifierInput},
    nodup::perm_check::{PermPIOP, PermPIOPProverInput, PermPIOPVerifierInput},
};

const SOURCE_FOLD_LABEL: &[u8] = b"string_sort_source_fold";

/// One sort key's output columns.
pub enum Key<P> {
    /// An ordered value whose adjacent differences fit in `width` bits.
    Value { data: P, asc: bool, width: usize },
    /// A string: its output identity `[hash slots…, length]`, the input's,
    /// and the input's character table.
    String {
        identity: Vec<P>,
        input_identity: Vec<P>,
        chars: Characters<P>,
        asc: bool,
    },
}

/// The string identities of every string key, output side and input side.
fn identities<P: Clone>(keys: &[Key<P>]) -> (Vec<P>, Vec<P>) {
    let mut output = Vec::new();
    let mut input = Vec::new();
    for key in keys {
        if let Key::String {
            identity,
            input_identity,
            ..
        } = key
        {
            output.extend(identity.iter().cloned());
            input.extend(input_identity.iter().cloned());
        }
    }
    (output, input)
}

/// `src`: each active output row's input row, distinct rows for repeated
/// identities, so `src` is a bijection between the active rows when the
/// output permutes the input. 0 on the other rows.
fn source_rows<F: ark_ff::Field>(
    output: &[Vec<F>],
    output_active: &[F],
    input: &[Vec<F>],
    input_active: &[F],
) -> Vec<F> {
    let identity = |columns: &[Vec<F>], row: usize| -> Vec<F> {
        columns.iter().map(|column| column[row]).collect()
    };
    let mut rows: HashMap<Vec<F>, Vec<usize>> = HashMap::new();
    for row in (0..input_active.len()).rev() {
        if !input_active[row].is_zero() {
            rows.entry(identity(input, row)).or_default().push(row);
        }
    }
    (0..output_active.len())
        .map(|row| {
            if output_active[row].is_zero() {
                return F::zero();
            }
            rows.get_mut(&identity(output, row))
                .and_then(Vec::pop)
                .map_or(F::zero(), |source| F::from(source as u64))
        })
        .collect()
}

/// The sort check on a run of value keys `(data, asc, width)` from `tie`,
/// with the run's own rotation; returns its `t_m` for [`End::Tied`]. With
/// fewer than two active rows there is no pair and nothing is proved.
fn prove_value_keys<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    run: &[(TrackedPoly<B>, bool, usize)],
    tie: Tie<TrackedPoly<B>>,
    end: End,
) -> SnarkResult<Option<Tie<TrackedPoly<B>>>> {
    let (log_size, s) = (tie.log_size(), tie.active_rows());
    if run.is_empty() || s <= 1 {
        return Ok((end == End::Tied).then_some(tie));
    }
    let mut keys = Vec::with_capacity(run.len());
    for (data, asc, width) in run {
        let next = prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
            log_size,
            sortedness::rotate(&data.evaluations()),
        ))?;
        keys.push(SortKey {
            data: data.clone(),
            next,
            asc: *asc,
            width: *width,
        });
    }
    let pairs: Vec<_> = keys
        .iter()
        .map(|key| (key.data.clone(), key.next.clone()))
        .collect();
    rotation::prove(prover, &pairs, log_size, s)?;
    sort::prove(prover, &keys, tie, end)
}

fn verify_value_keys<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    run: &[(TrackedOracle<B>, bool, usize)],
    tie: Tie<TrackedOracle<B>>,
    end: End,
) -> SnarkResult<Option<Tie<TrackedOracle<B>>>> {
    let (log_size, s) = (tie.log_size(), tie.active_rows());
    if run.is_empty() || s <= 1 {
        return Ok((end == End::Tied).then_some(tie));
    }
    let mut keys = Vec::with_capacity(run.len());
    for (data, asc, width) in run {
        keys.push(SortKey {
            data: data.clone(),
            next: verifier.track_next_mv_com()?,
            asc: *asc,
            width: *width,
        });
    }
    let pairs: Vec<_> = keys
        .iter()
        .map(|key| (key.data.clone(), key.next.clone()))
        .collect();
    rotation::verify(verifier, &pairs, log_size, s)?;
    sort::verify(verifier, &keys, tie, end)
}

/// Proves the check on `keys`, with `s` the active output rows.
pub fn prove<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    keys: &[Key<TrackedPoly<B>>],
    input_active: &TrackedPoly<B>,
    output_active: &TrackedPoly<B>,
    s: usize,
) -> SnarkResult<()> {
    let (identity, input_identity) = identities(keys);
    let evaluations =
        |columns: &[TrackedPoly<B>]| columns.iter().map(|c| c.evaluations()).collect::<Vec<_>>();
    let src = source_rows(
        &evaluations(&identity),
        &output_active.evaluations(),
        &evaluations(&input_identity),
        &input_active.evaluations(),
    );
    prove_with_source(prover, keys, input_active, output_active, s, src)
}

/// [`prove`] with `src` given.
pub(super) fn prove_with_source<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    keys: &[Key<TrackedPoly<B>>],
    input_active: &TrackedPoly<B>,
    output_active: &TrackedPoly<B>,
    s: usize,
    src: Vec<B::F>,
) -> SnarkResult<()> {
    let log_size = output_active.log_size();
    let (identity, input_identity) = identities(keys);
    let src = prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, src))?;
    let index = get_or_insert_shift_poly(prover, log_size, 0, true);
    let mut included = src.clone();
    let mut super_key = index.clone();
    for (output_column, input_column) in identity.iter().zip(&input_identity) {
        let challenge = prover.get_and_append_challenge(SOURCE_FOLD_LABEL)?;
        included = &included + &output_column.mul_scalar_poly(challenge);
        super_key = &super_key + &input_column.mul_scalar_poly(challenge);
    }
    LookupPIOP::<B>::prove(
        prover,
        LookupProverInput {
            included_cols: vec![TrackedCol::new(included, Some(output_active.clone()), None)],
            super_col: TrackedCol::new(super_key, Some(input_active.clone()), None),
        },
    )?;
    PermPIOP::<B>::prove(
        prover,
        PermPIOPProverInput {
            left_col: TrackedCol::new(src.clone(), Some(output_active.clone()), None),
            right_col: TrackedCol::new(index, Some(input_active.clone()), None),
        },
    )?;

    let mut tie = Tie::mask(prover, log_size, s)?;
    let mut run = Vec::new();
    for key in keys {
        match key {
            Key::Value { data, asc, width } => run.push((data.clone(), *asc, *width)),
            Key::String {
                identity,
                chars,
                asc,
                ..
            } => {
                tie = prove_value_keys(prover, &std::mem::take(&mut run), tie, End::Tied)?
                    .expect("t_m");
                let (length, hash) = identity.split_last().expect("a string's length");
                let strings = SortedStrings {
                    index: src.clone(),
                    hash: hash.to_vec(),
                    length: length.clone(),
                };
                tie = sortedness::prove(prover, &strings, chars, tie, &[], *asc)?.same;
            }
        }
    }
    prove_value_keys(prover, &run, tie, End::NonStrict)?;
    Ok(())
}

pub fn verify<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    keys: &[Key<TrackedOracle<B>>],
    input_active: &TrackedOracle<B>,
    output_active: &TrackedOracle<B>,
    s: usize,
) -> SnarkResult<()> {
    let log_size = output_active.log_size();
    let (identity, input_identity) = identities(keys);
    let src = verifier.track_next_mv_com()?;
    let index = get_or_insert_shift_oracle(verifier, log_size, 0, true);
    let mut included = src.clone();
    let mut super_key = index.clone();
    for (output_column, input_column) in identity.iter().zip(&input_identity) {
        let challenge = verifier.get_and_append_challenge(SOURCE_FOLD_LABEL)?;
        included = &included + &output_column.mul_scalar_oracle(challenge);
        super_key = &super_key + &input_column.mul_scalar_oracle(challenge);
    }
    LookupPIOP::<B>::verify(
        verifier,
        LookupVerifierInput {
            included_tracked_col_oracles: vec![TrackedColOracle::new(
                included,
                Some(output_active.clone()),
                None,
            )],
            super_tracked_col_oracle: TrackedColOracle::new(
                super_key,
                Some(input_active.clone()),
                None,
            ),
        },
    )?;
    PermPIOP::<B>::verify(
        verifier,
        PermPIOPVerifierInput {
            left_tracked_col_oracle: TrackedColOracle::new(
                src.clone(),
                Some(output_active.clone()),
                None,
            ),
            right_tracked_col_oracle: TrackedColOracle::new(
                index,
                Some(input_active.clone()),
                None,
            ),
        },
    )?;

    let mut tie = Tie::mask_oracle(verifier, log_size, s)?;
    let mut run = Vec::new();
    for key in keys {
        match key {
            Key::Value { data, asc, width } => run.push((data.clone(), *asc, *width)),
            Key::String {
                identity,
                chars,
                asc,
                ..
            } => {
                tie = verify_value_keys(verifier, &std::mem::take(&mut run), tie, End::Tied)?
                    .expect("t_m");
                let (length, hash) = identity.split_last().expect("a string's length");
                let strings = SortedStrings {
                    index: src.clone(),
                    hash: hash.to_vec(),
                    length: length.clone(),
                };
                tie = sortedness::verify(verifier, &strings, chars, tie, &[], *asc)?.same;
            }
        }
    }
    verify_value_keys(verifier, &run, tie, End::NonStrict)?;
    Ok(())
}

#[cfg(test)]
mod tests;
