//! TruthTable++ Lexicographic Sortedness Check (§7.2, PIOP 10), run inline:
//! every pair `(i, i + 1)` of `t_in` holds strings `s_i ⪯ s_{i+1}` (`⪰` for a
//! descending order), and the returned `same` marks exactly its pairs of
//! equal strings.
//!
//! Step 2 marks a pair `same` when its hash slots and its length agree:
//! inline-short columns store `""` and `"\0"` in one hash slot, so the hash
//! alone would let a prover call them equal and skip their comparison. The
//! NoZero check runs on `act·Δ + c·(1 − act)` with `act = t_in·(1 − same)`
//! and `Δ = Σ_j γ^j (h_j^next − h_j) + γ^S (l^next − l)`, so `same` marks
//! exactly the pairs whose hash slots and length agree. The strict check of
//! step 5 alone would reject an unmarked equal pair only if the characters
//! agreed with the hash, which nothing here binds.
//!
//! Deviation: the Rotation Check binding `h^next`, `l^next` and the caller's
//! extra columns (PIOP 12's `rk^π`) is this check's own and runs for every
//! `R`, including `R = 0`, where nothing else reads them. It is one multiset
//! check that also carries the rotated projections `c'_k` of step 5, so the
//! Lexicographic Sort Check is called on pairs already bound.
//!
//! `R` is a committed scalar the verifier caps at `2^m + 1` (`m` the
//! character domain's log size, which bounds every length) before tracking
//! any projection, and also refuses when the projections could exhaust the
//! tracker ids, which ark-piop counts in a `u16` and panics past. The guard
//! covers this check's ids only: a later check can still exhaust them after
//! an `R` that passes it, and the verifier then panics instead of rejecting,
//! until ark-piop's id allocation is fallible. Soundness
//! needs what the Character Projection Check needs of the character table,
//! and `index` bound by the caller.

use std::collections::HashMap;

use ark_ff::{One, Zero};
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::SnarkResult,
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};

use super::{
    PROJECTION_WIDTH, SortKey, Tie,
    character_projection::{self, Characters, Strings},
    check_failed,
};
use crate::irs::nodes::utils::{contig_sort::rotation, field_to_usize};

const GAMMA_LABEL: &[u8] = b"lex_sortedness_gamma";
const NOZERO_LABEL: &[u8] = b"lex_sortedness_nozero";

/// An upper bound, with margin, on the tracker ids the verifier spends per
/// projection from tracking `c_k` to the end of the check, range limbs of
/// a wide character domain included; the verifier reserves one more
/// position's worth for the part that does not depend on `R`.
pub(super) const IDS_PER_POSITION: usize = 128;

/// The sorted column at string level; its activator is `C_{µ,n}` for the
/// `n` of the tie it is checked under. `index[i]` is the `orig-ind` of row
/// `i`'s characters: the public identity, or a source column the caller
/// binds.
pub struct SortedStrings<P> {
    pub index: P,
    pub hash: Vec<P>,
    pub length: P,
}

/// The rotated columns agree with the columns shifted up by one row on the
/// rows `j < n − 1`; with fewer than two active rows they are the columns
/// themselves.
pub struct Sortedness<P> {
    pub same: Tie<P>,
    pub hash_next: Vec<P>,
    pub length_next: P,
    pub extras_next: Vec<P>,
}

/// The prover's committed columns. `R` is the number of projections.
pub(super) struct Witness<F> {
    pub(super) same: Vec<F>,
    pub(super) hash_next: Vec<Vec<F>>,
    pub(super) length_next: Vec<F>,
    pub(super) extras_next: Vec<Vec<F>>,
    pub(super) projections: Vec<Vec<F>>,
    pub(super) projections_next: Vec<Vec<F>>,
}

/// `column` shifted up by one row, the first row wrapping to the last.
pub(crate) fn rotate<F: Copy>(column: &[F]) -> Vec<F> {
    (0..column.len())
        .map(|j| column[(j + 1) % column.len()])
        .collect()
}

/// Proves the check on the pairs of `tie` and returns `same`, for chaining
/// into the next sort key, and the rotated columns, `extras` among them.
pub fn prove<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    strings: &SortedStrings<TrackedPoly<B>>,
    chars: &Characters<TrackedPoly<B>>,
    tie: Tie<TrackedPoly<B>>,
    extras: &[TrackedPoly<B>],
    asc: bool,
) -> SnarkResult<Sortedness<TrackedPoly<B>>> {
    let witness = witness(strings, chars, &tie, extras)?;
    prove_with_witness(prover, strings, chars, tie, extras, asc, witness)
}

/// The honest witness, from the strings rebuilt out of the character table
/// through `index`.
pub(super) fn witness<B: SnarkBackend>(
    strings: &SortedStrings<TrackedPoly<B>>,
    chars: &Characters<TrackedPoly<B>>,
    tie: &Tie<TrackedPoly<B>>,
    extras: &[TrackedPoly<B>],
) -> SnarkResult<Witness<B::F>> {
    let n = tie.active_rows();
    let tie_values = tie.poly().evaluations();
    let rows = tie_values.len();
    let hash: Vec<Vec<B::F>> = strings.hash.iter().map(|h| h.evaluations()).collect();
    let length = strings.length.evaluations();

    let mut owned: HashMap<B::F, Vec<(usize, i64)>> = HashMap::new();
    let char_active = chars.activator.evaluations();
    let orig_ind = chars.orig_ind.evaluations();
    let int_ind = chars.int_ind.evaluations();
    let bytes = chars.chars.evaluations();
    for j in (0..char_active.len()).filter(|&j| !char_active[j].is_zero()) {
        let position = field_to_usize(int_ind[j], "a character position")?;
        let byte = field_to_usize(bytes[j], "a character")? as i64;
        owned.entry(orig_ind[j]).or_default().push((position, byte));
    }
    let index = strings.index.evaluations();
    let sorted: Vec<Vec<i64>> = index[..n]
        .iter()
        .map(|i| {
            let mut characters = owned.get(i).cloned().unwrap_or_default();
            characters.sort_unstable();
            characters.into_iter().map(|(_, byte)| byte).collect()
        })
        .collect();

    let mut same = vec![B::F::zero(); rows];
    let mut separated = 0;
    for i in (0..n.saturating_sub(1)).filter(|&i| !tie_values[i].is_zero()) {
        let equal = length[i] == length[i + 1] && hash.iter().all(|h| h[i] == h[i + 1]);
        if equal {
            same[i] = tie_values[i];
        } else {
            let lcp = sorted[i]
                .iter()
                .zip(&sorted[i + 1])
                .take_while(|(a, b)| a == b)
                .count();
            separated = separated.max(lcp + 1);
        }
    }
    let projections: Vec<Vec<B::F>> = (0..separated)
        .map(|k| {
            (0..rows)
                .map(|i| {
                    let byte = sorted.get(i).and_then(|s| s.get(k)).copied();
                    B::F::from(byte.unwrap_or(-1))
                })
                .collect()
        })
        .collect();
    Ok(Witness {
        same,
        hash_next: hash.iter().map(|h| rotate(h)).collect(),
        length_next: rotate(&length),
        extras_next: extras.iter().map(|e| rotate(&e.evaluations())).collect(),
        projections_next: projections.iter().map(|c| rotate(c)).collect(),
        projections,
    })
}

/// [`prove`] with the committed columns given.
pub(super) fn prove_with_witness<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    strings: &SortedStrings<TrackedPoly<B>>,
    chars: &Characters<TrackedPoly<B>>,
    tie: Tie<TrackedPoly<B>>,
    extras: &[TrackedPoly<B>],
    asc: bool,
    witness: Witness<B::F>,
) -> SnarkResult<Sortedness<TrackedPoly<B>>> {
    let (log_size, n) = (tie.log_size(), tie.active_rows());
    if n <= 1 {
        return Ok(Sortedness {
            same: tie.zero(),
            hash_next: strings.hash.clone(),
            length_next: strings.length.clone(),
            extras_next: extras.to_vec(),
        });
    }
    let mut commit = |evals: Vec<B::F>| {
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, evals))
    };
    let same = commit(witness.same)?;
    let hash_next = witness
        .hash_next
        .into_iter()
        .map(&mut commit)
        .collect::<SnarkResult<Vec<_>>>()?;
    let length_next = commit(witness.length_next)?;
    let extras_next = witness
        .extras_next
        .into_iter()
        .map(&mut commit)
        .collect::<SnarkResult<Vec<_>>>()?;

    let one = B::F::one();
    let not_same = same.mul_scalar_poly(-one).add_scalar_poly(one);
    prover.add_mv_zerocheck_claim((&same * &not_same).id())?;
    let not_tie = tie.poly().mul_scalar_poly(-one).add_scalar_poly(one);
    prover.add_mv_zerocheck_claim((&same * &not_tie).id())?;
    let differences: Vec<TrackedPoly<B>> = hash_next
        .iter()
        .zip(&strings.hash)
        .chain([(&length_next, &strings.length)])
        .map(|(next, column)| next - column)
        .collect();
    for difference in &differences {
        prover.add_mv_zerocheck_claim((&same * difference).id())?;
    }
    let gamma = prover.get_and_append_challenge(GAMMA_LABEL)?;
    let c = prover.get_and_append_challenge(NOZERO_LABEL)?;
    let (first, rest) = differences.split_first().expect("a length column");
    let mut power = one;
    let delta = rest.iter().fold(first.clone(), |acc, difference| {
        power *= gamma;
        &acc + &difference.mul_scalar_poly(power)
    });
    let unequal = tie.poly() * &not_same;
    let not_unequal = unequal.mul_scalar_poly(-one).add_scalar_poly(one);
    prover
        .add_mv_nozerocheck_claim((&(&unequal * &delta) + &not_unequal.mul_scalar_poly(c)).id())?;

    let positions = witness.projections.len();
    prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
        0,
        vec![B::F::from(positions as u64)],
    ))?;
    let mut commit = |evals: Vec<B::F>| {
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, evals))
    };
    let projections = witness
        .projections
        .into_iter()
        .map(&mut commit)
        .collect::<SnarkResult<Vec<_>>>()?;
    let projections_next = witness
        .projections_next
        .into_iter()
        .map(&mut commit)
        .collect::<SnarkResult<Vec<_>>>()?;

    let pairs: Vec<_> = strings
        .hash
        .iter()
        .chain([&strings.length])
        .chain(extras)
        .chain(&projections)
        .cloned()
        .zip(
            hash_next
                .iter()
                .chain([&length_next])
                .chain(&extras_next)
                .chain(&projections_next)
                .cloned(),
        )
        .collect();
    rotation::prove(prover, &pairs, log_size, n)?;
    let activator = prover.get_or_build_contig_one_poly(log_size, n)?;
    character_projection::prove(
        prover,
        &Strings {
            index: strings.index.clone(),
            length: strings.length.clone(),
            activator,
        },
        chars,
        &projections,
    )?;
    let keys: Vec<_> = projections
        .into_iter()
        .zip(projections_next)
        .map(|(data, next)| SortKey {
            data,
            next,
            asc,
            width: PROJECTION_WIDTH,
        })
        .collect();
    super::prove(prover, &keys, Tie::new(unequal, log_size, n), true)?;
    Ok(Sortedness {
        same: Tie::new(same, log_size, n),
        hash_next,
        length_next,
        extras_next,
    })
}

pub fn verify<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    strings: &SortedStrings<TrackedOracle<B>>,
    chars: &Characters<TrackedOracle<B>>,
    tie: Tie<TrackedOracle<B>>,
    extras: &[TrackedOracle<B>],
    asc: bool,
) -> SnarkResult<Sortedness<TrackedOracle<B>>> {
    let (log_size, n) = (tie.log_size(), tie.active_rows());
    if n <= 1 {
        return Ok(Sortedness {
            same: tie.zero(),
            hash_next: strings.hash.clone(),
            length_next: strings.length.clone(),
            extras_next: extras.to_vec(),
        });
    }
    let same = verifier.track_next_mv_com()?;
    let hash_next = strings
        .hash
        .iter()
        .map(|_| verifier.track_next_mv_com())
        .collect::<SnarkResult<Vec<_>>>()?;
    let length_next = verifier.track_next_mv_com()?;
    let extras_next = extras
        .iter()
        .map(|_| verifier.track_next_mv_com())
        .collect::<SnarkResult<Vec<_>>>()?;

    let one = B::F::one();
    let not_same = same.mul_scalar_oracle(-one).add_scalar_oracle(one);
    verifier.add_mv_zerocheck_claim((&same * &not_same).id());
    let not_tie = tie.poly().mul_scalar_oracle(-one).add_scalar_oracle(one);
    verifier.add_mv_zerocheck_claim((&same * &not_tie).id());
    let differences: Vec<TrackedOracle<B>> = hash_next
        .iter()
        .zip(&strings.hash)
        .chain([(&length_next, &strings.length)])
        .map(|(next, column)| next - column)
        .collect();
    for difference in &differences {
        verifier.add_mv_zerocheck_claim((&same * difference).id());
    }
    let gamma = verifier.get_and_append_challenge(GAMMA_LABEL)?;
    let c = verifier.get_and_append_challenge(NOZERO_LABEL)?;
    let (first, rest) = differences.split_first().expect("a length column");
    let mut power = one;
    let delta = rest.iter().fold(first.clone(), |acc, difference| {
        power *= gamma;
        &acc + &difference.mul_scalar_oracle(power)
    });
    let unequal = tie.poly() * &not_same;
    let not_unequal = unequal.mul_scalar_oracle(-one).add_scalar_oracle(one);
    verifier
        .add_mv_nozerocheck_claim((&(&unequal * &delta) + &not_unequal.mul_scalar_oracle(c)).id());

    let committed = verifier.track_next_mv_com()?;
    let positions = match committed.as_constant() {
        Some(value) if committed.log_size() == 0 => field_to_usize(value, "the position count")?,
        _ => return Err(check_failed("the position count is not a committed scalar")),
    };
    if positions > (1 << chars.orig_ind.log_size()) + 1 {
        return Err(check_failed(
            "the position count exceeds the longest possible string",
        ));
    }
    let free_ids = usize::from(u16::MAX) - verifier.peek_next_id().to_int();
    if (positions + 1) * IDS_PER_POSITION > free_ids {
        return Err(check_failed(
            "the position count would exhaust the verifier's tracker ids",
        ));
    }
    let projections = (0..positions)
        .map(|_| verifier.track_next_mv_com())
        .collect::<SnarkResult<Vec<_>>>()?;
    let projections_next = (0..positions)
        .map(|_| verifier.track_next_mv_com())
        .collect::<SnarkResult<Vec<_>>>()?;

    let pairs: Vec<_> = strings
        .hash
        .iter()
        .chain([&strings.length])
        .chain(extras)
        .chain(&projections)
        .cloned()
        .zip(
            hash_next
                .iter()
                .chain([&length_next])
                .chain(&extras_next)
                .chain(&projections_next)
                .cloned(),
        )
        .collect();
    rotation::verify(verifier, &pairs, log_size, n)?;
    let activator = verifier.get_or_build_contig_one_poly(log_size, n)?;
    character_projection::verify(
        verifier,
        &Strings {
            index: strings.index.clone(),
            length: strings.length.clone(),
            activator,
        },
        chars,
        &projections,
    )?;
    let keys: Vec<_> = projections
        .into_iter()
        .zip(projections_next)
        .map(|(data, next)| SortKey {
            data,
            next,
            asc,
            width: PROJECTION_WIDTH,
        })
        .collect();
    super::verify(verifier, &keys, Tie::new(unequal, log_size, n), true)?;
    Ok(Sortedness {
        same: Tie::new(same, log_size, n),
        hash_next,
        length_next,
        extras_next,
    })
}

#[cfg(test)]
pub(super) mod tests;
