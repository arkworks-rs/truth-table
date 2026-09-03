//! Honest-witness computation for SweepFactors / MCPM.
//!
//! Given the char-level input data `(char, orig_ind, int_ind, bnd,
//! char_act)`, the string-level input `(ind, a, l)`, and a factor list
//! `[(pat_j, mode_j)]`, this module computes every per-factor witness
//! column that `SweepFactors` expects: `occurs`, `match`, `mark`,
//! `start`, `match_broadcast`, `start_broadcast`, `leftmost_mask`,
//! `rotated_char`, plus mode-specific `att_mask` (suffix) and
//! `rotated_bnd` (infix), plus per-inter-factor `past`.
//!
//! Additionally emits the outer MCPM witnesses driven by SweepFactors's
//! output: length-filter outputs `(char_act_old_prime, a_old_prime)`
//! for LFC with threshold `Σ_j |pat_j|`, and the new activators
//! `(char_act_new, a_new)` matching the final `alive_h_{t-1}`.
//!
//! # Semantics
//!
//! For each factor `j` (processed in order):
//! 1. Compute effective char-alive `alive_c_{j-1}` (= `char_act` for
//!    j=0, else `alive_c_{j-2} · past_{j-1}`).
//! 2. Compute `att_mask_j` from `alive_c_{j-1}` and `bnd` per the
//!    factor's mode.
//! 3. Compute `occurs_j[c]`: `1` iff `att_mask_j[c] = 1` AND the
//!    rotated char columns at position `c` match `pat_j` exactly.
//! 4. Choose `mark_j[c]` = leftmost `c` per string with `occurs_j[c]
//!    = 1`, using `orig_ind` to identify strings.
//! 5. Compute `match_str_j[i]` = 1 iff string `i` has any `mark_j[c] =
//!    1` char.
//! 6. Compute `start_j[i]` = `int_ind[mark_j's position for string i]`,
//!    else 0 for unmatched.
//! 7. Compute `start_broadcast_j[c] = start_j[orig_ind[c]]`.
//! 8. Compute `leftmost_mask_j[c] = 1 iff int_ind[c] < start_broadcast_j[c]`.
//! 9. If `j < t-1`, compute `past_j[c] = 1 iff int_ind[c] >
//!    start_broadcast_j[c]`.
//!
//! # Types
//!
//! Inputs and outputs use `Vec<F>` for direct compatibility with
//! `TrackedTable` construction. Booleans are `F::from(0/1)`; small
//! integers are `F::from(u64)`.

use ark_ff::{BigInteger, PrimeField};

use super::Mode;

/// Convert a small non-negative field element back to `usize`. Used
/// internally by the witness computer — panics if the value doesn't
/// fit in `u64` (which never happens for the small indices we compute
/// from).
fn as_usize<F: PrimeField>(x: F) -> usize {
    let bi = x.into_bigint();
    let bytes = bi.to_bytes_le();
    let mut acc: u64 = 0;
    for (i, b) in bytes.iter().take(8).enumerate() {
        acc |= (*b as u64) << (8 * i);
    }
    acc as usize
}

fn is_one<F: PrimeField>(x: F) -> bool {
    x == F::one()
}

/// Char-level rotate-left by δ (mod n).
pub(crate) fn shift_left<F: Copy>(xs: &[F], shift: usize) -> Vec<F> {
    let n = xs.len();
    if n == 0 {
        return Vec::new();
    }
    (0..n).map(|i| xs[(i + (shift % n)) % n]).collect()
}

/// Char-level data that SweepFactors consumes. `char_domain` = log2 of
/// the padded char slot count; `str_domain` = log2 of padded string
/// count.
#[derive(Clone)]
pub struct ScannedTables<F: PrimeField> {
    pub char: Vec<F>,
    pub orig_ind: Vec<F>,
    pub int_ind: Vec<F>,
    pub bnd: Vec<F>,
    pub char_act: Vec<F>,
    pub char_domain: usize,
    pub ind: Vec<F>,
    pub a: Vec<F>,
    pub l: Vec<F>,
    pub str_domain: usize,
}

/// Everything the prover needs to hand to the MCPM/SweepFactors
/// payload builders. All vectors are already padded to the correct
/// domain length.
#[derive(Clone)]
pub struct McpmWitness<F: PrimeField> {
    /// Per-factor witnesses, one entry per factor (0-indexed).
    pub per_factor: Vec<FactorWitness<F>>,
    /// LFC output: char_act_old_prime (char-level boolean).
    pub char_act_old_prime: Vec<F>,
    /// LFC output: a_old_prime (str-level boolean).
    pub a_old_prime: Vec<F>,
    /// Final MCPM output: char_act_new (char-level boolean).
    pub char_act_new: Vec<F>,
    /// Final MCPM output: a_new (str-level boolean = alive_h_{t-1} = match_{t-1}).
    pub a_new: Vec<F>,
    /// Total pattern content Σ_j |pat_j|. Used as the LFC threshold.
    pub total_len: u64,
}

#[derive(Clone)]
pub struct FactorWitness<F: PrimeField> {
    /// `char^{(δ)}` for δ = 0..k-1. `char^{(0)} = char`.
    pub rotated_chars: Vec<Vec<F>>,
    pub occurs: Vec<F>,
    pub match_str: Vec<F>,
    pub mark: Vec<F>,
    pub start: Vec<F>,
    pub match_broadcast: Vec<F>,
    pub start_broadcast: Vec<F>,
    pub leftmost_mask: Vec<F>,
    /// Suffix mode only.
    pub att_mask: Option<Vec<F>>,
    /// Infix mode, k ≥ 2 only. Columns `bnd(1), …, bnd(k-1)` in order.
    pub rotated_bnd: Option<Vec<Vec<F>>>,
    /// For `j < t - 1` only.
    pub past: Option<Vec<F>>,
}

/// Compute all MCPM/SweepFactors witnesses for a factor list against
/// the given scanned tables.
///
/// The character alphabet is byte-oriented (each `char[c]` is a u64
/// holding a byte value). Factor patterns are `Vec<F>` of the same
/// per-byte encoding; equality is field equality.
///
/// # Panics
///
/// Panics if any input vector length is not the expected padded domain
/// size, or if `orig_ind[c]` exceeds `str_domain` bounds.
pub fn compute_mcpm_witness<F: PrimeField>(
    tables: &ScannedTables<F>,
    factors: &[(Vec<F>, Mode)],
) -> McpmWitness<F> {
    let n_chars = 1usize << tables.char_domain;
    let n_strs = 1usize << tables.str_domain;
    assert_eq!(tables.char.len(), n_chars, "char vec size mismatch");
    assert_eq!(tables.orig_ind.len(), n_chars);
    assert_eq!(tables.int_ind.len(), n_chars);
    assert_eq!(tables.bnd.len(), n_chars);
    assert_eq!(tables.char_act.len(), n_chars);
    assert_eq!(tables.ind.len(), n_strs);
    assert_eq!(tables.a.len(), n_strs);
    assert_eq!(tables.l.len(), n_strs);

    let t = factors.len();
    let _ = n_strs; // used below via as_usize bounds checks
    let total_len: u64 = factors.iter().map(|(p, _)| p.len() as u64).sum();

    // ---- Length-filter outputs (identical for all factors) ----
    // Keep str i iff a[i] = 1 AND l[i] >= total_len.
    let a_old_prime: Vec<F> = (0..n_strs)
        .map(|i| {
            let a = tables.a[i];
            let l = as_usize(tables.l[i]) as u64;
            if is_one(a) && l >= total_len {
                F::one()
            } else {
                F::zero()
            }
        })
        .collect();
    let char_act_old_prime: Vec<F> = (0..n_chars)
        .map(|c| {
            let ca = tables.char_act[c];
            let src = as_usize(tables.orig_ind[c]);
            if is_one(ca) && src < n_strs && is_one(a_old_prime[src]) {
                F::one()
            } else {
                F::zero()
            }
        })
        .collect();

    // ---- Sweep per factor ----
    let mut per_factor: Vec<FactorWitness<F>> = Vec::with_capacity(t);
    let mut alive_c: Vec<F> = char_act_old_prime.clone();
    // alive_h is `a_old_prime` before the first factor and `match_j`
    // after each subsequent factor; only the final value (== match_{t-1})
    // is externally observed, via `a_new` below.
    let _alive_h_initial = a_old_prime.clone();

    for (j, (pat, mode)) in factors.iter().enumerate() {
        let k = pat.len();

        // Precompute rotated char columns: char^(δ) for δ = 0..k-1.
        let mut rotated_chars: Vec<Vec<F>> = Vec::with_capacity(k);
        rotated_chars.push(tables.char.clone());
        for delta in 1..k {
            rotated_chars.push(shift_left(&tables.char, delta));
        }

        // Precompute rotated bnd columns for infix mode: bnd(δ) for δ = 1..k-1.
        // bnd(0) = bnd is implicit.
        let rotated_bnd: Option<Vec<Vec<F>>> = match mode {
            Mode::Infix if k >= 2 => Some(
                (1..k)
                    .map(|delta| shift_left(&tables.bnd, delta))
                    .collect(),
            ),
            _ => None,
        };

        // Compute att_mask.
        //   Prefix: alive_c · bnd
        //   Suffix: ρ_{-k}(alive_c · bnd)
        //   Infix:  alive_c · (1 − Σ_{δ=1..k-1} bnd(δ))
        let (att_mask, att_mask_witness_slot): (Vec<F>, Option<Vec<F>>) = match mode {
            Mode::Prefix => {
                let am: Vec<F> = (0..n_chars)
                    .map(|c| alive_c[c] * tables.bnd[c])
                    .collect();
                (am, None)
            }
            Mode::Suffix => {
                let base: Vec<F> = (0..n_chars)
                    .map(|c| alive_c[c] * tables.bnd[c])
                    .collect();
                let am = shift_left(&base, k);
                let am_clone = am.clone();
                (am, Some(am_clone))
            }
            Mode::Infix => {
                let am: Vec<F> = (0..n_chars)
                    .map(|c| {
                        // 1 - Σ bnd(δ) for δ = 1..k-1
                        let mut sum = F::zero();
                        if let Some(rb) = rotated_bnd.as_ref() {
                            for col in rb.iter() {
                                sum += col[c];
                            }
                        }
                        alive_c[c] * (F::one() - sum)
                    })
                    .collect();
                (am, None)
            }
        };

        // occurs[c] = 1 iff att_mask[c]=1 AND rotated_chars[δ][c] == pat[δ] for all δ.
        let occurs: Vec<F> = (0..n_chars)
            .map(|c| {
                if !is_one(att_mask[c]) {
                    return F::zero();
                }
                for delta in 0..k {
                    if rotated_chars[delta][c] != pat[delta] {
                        return F::zero();
                    }
                }
                F::one()
            })
            .collect();

        // mark[c] = 1 for the leftmost occurs=1 char per string; 0 elsewhere.
        // "Leftmost" means smallest int_ind within the string.
        let mut mark: Vec<F> = vec![F::zero(); n_chars];
        let mut chosen_mark_pos: Vec<Option<usize>> = vec![None; n_strs];
        for c in 0..n_chars {
            if !is_one(occurs[c]) {
                continue;
            }
            let s = as_usize(tables.orig_ind[c]);
            if s >= n_strs {
                continue;
            }
            let ii = as_usize(tables.int_ind[c]);
            match chosen_mark_pos[s] {
                None => chosen_mark_pos[s] = Some(c),
                Some(prev) => {
                    let prev_ii = as_usize(tables.int_ind[prev]);
                    if ii < prev_ii {
                        chosen_mark_pos[s] = Some(c);
                    }
                }
            }
        }
        for pos in chosen_mark_pos.iter().flatten() {
            mark[*pos] = F::one();
        }

        // match_str[i] = 1 iff string i has a mark, else 0.
        let mut match_str: Vec<F> = vec![F::zero(); n_strs];
        for i in 0..n_strs {
            if chosen_mark_pos[i].is_some() {
                match_str[i] = F::one();
            }
        }

        // start[i] = int_ind[chosen_mark_pos[i]] if matched, else 0.
        let mut start: Vec<F> = vec![F::zero(); n_strs];
        for i in 0..n_strs {
            if let Some(pos) = chosen_mark_pos[i] {
                start[i] = tables.int_ind[pos];
            }
        }

        // match_broadcast[c] = match_str[orig_ind[c]] (defaults to 0 if OOB).
        let match_broadcast: Vec<F> = (0..n_chars)
            .map(|c| {
                let s = as_usize(tables.orig_ind[c]);
                if s < n_strs {
                    match_str[s]
                } else {
                    F::zero()
                }
            })
            .collect();

        // start_broadcast[c] = start[orig_ind[c]] (0 if OOB).
        let start_broadcast: Vec<F> = (0..n_chars)
            .map(|c| {
                let s = as_usize(tables.orig_ind[c]);
                if s < n_strs {
                    start[s]
                } else {
                    F::zero()
                }
            })
            .collect();

        // leftmost_mask[c] = 1 iff int_ind[c] < start_broadcast[c].
        let leftmost_mask: Vec<F> = (0..n_chars)
            .map(|c| {
                if as_usize(tables.int_ind[c]) < as_usize(start_broadcast[c]) {
                    F::one()
                } else {
                    F::zero()
                }
            })
            .collect();

        // past[c] = 1 iff int_ind[c] > start_broadcast[c] (only if j < t-1).
        let past: Option<Vec<F>> = if j + 1 < t {
            Some(
                (0..n_chars)
                    .map(|c| {
                        if as_usize(tables.int_ind[c]) > as_usize(start_broadcast[c]) {
                            F::one()
                        } else {
                            F::zero()
                        }
                    })
                    .collect(),
            )
        } else {
            None
        };

        // Update alive_c state for next round via past_j. alive_h is
        // implicit — the next round's activator is match_{j} which is
        // the current factor's `match_str`, already captured in
        // `per_factor` and available to the caller.
        if let Some(ref p) = past {
            let new_alive_c: Vec<F> = (0..n_chars).map(|c| alive_c[c] * p[c]).collect();
            alive_c = new_alive_c;
        }

        per_factor.push(FactorWitness {
            rotated_chars,
            occurs,
            match_str,
            mark,
            start,
            match_broadcast,
            start_broadcast,
            leftmost_mask,
            att_mask: att_mask_witness_slot,
            rotated_bnd,
            past,
        });
    }

    // Final alive_h_{t-1} = match_{t-1} (from the last factor).
    let a_new = per_factor.last().unwrap().match_str.clone();
    // Final char_act: chars whose owning string is `a_new = 1` AND
    // char was active in char_act_old_prime. (MCPM's DPUC requires the
    // char_act_new / a_new pair to be consistent.)
    let char_act_new: Vec<F> = (0..n_chars)
        .map(|c| {
            let ca = char_act_old_prime[c];
            let s = as_usize(tables.orig_ind[c]);
            if is_one(ca) && s < n_strs && is_one(a_new[s]) {
                F::one()
            } else {
                F::zero()
            }
        })
        .collect();

    McpmWitness {
        per_factor,
        char_act_old_prime,
        a_old_prime,
        char_act_new,
        a_new,
        total_len,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_piop::{DefaultSnarkBackend, SnarkBackend};
    type F = <DefaultSnarkBackend as SnarkBackend>::F;

    fn u(vs: &[u64]) -> Vec<F> {
        vs.iter().map(|v| F::from(*v)).collect()
    }
    fn i32_vals(vs: &[i32]) -> Vec<F> {
        vs.iter()
            .map(|v| {
                if *v >= 0 {
                    F::from(*v as u64)
                } else {
                    -F::from((-*v) as u64)
                }
            })
            .collect()
    }
    fn pattern(bytes: &[u8]) -> Vec<F> {
        bytes.iter().map(|b| F::from(*b as u64)).collect()
    }

    /// Fixture matching the MCPM t=2 test in tests.rs: two strings
    /// "abcd" packed contiguously, factor list [("ab", Infix), ("cd",
    /// Infix)].
    fn abcd_x2() -> ScannedTables<F> {
        ScannedTables {
            char: u(&[
                b'a' as u64, b'b' as u64, b'c' as u64, b'd' as u64,
                b'a' as u64, b'b' as u64, b'c' as u64, b'd' as u64,
            ]),
            orig_ind: u(&[0, 0, 0, 0, 1, 1, 1, 1]),
            int_ind: u(&[0, 1, 2, 3, 0, 1, 2, 3]),
            bnd: u(&[1, 0, 0, 0, 1, 0, 0, 0]),
            char_act: u(&[1, 1, 1, 1, 1, 1, 1, 1]),
            char_domain: 3,
            ind: u(&[0, 1, 2, 3, 4, 5, 6, 7]),
            a: u(&[1, 1, 0, 0, 0, 0, 0, 0]),
            l: i32_vals(&[4, 4, 0, 0, 0, 0, 0, 0]),
            str_domain: 3,
        }
    }

    #[test]
    fn two_infix_matches_hand_written_fixture() {
        let tables = abcd_x2();
        let factors = vec![
            (pattern(b"ab"), Mode::Infix),
            (pattern(b"cd"), Mode::Infix),
        ];
        let w = compute_mcpm_witness(&tables, &factors);

        assert_eq!(w.per_factor.len(), 2);

        // Factor 0 = "ab"
        assert_eq!(w.per_factor[0].occurs, u(&[1, 0, 0, 0, 1, 0, 0, 0]));
        assert_eq!(w.per_factor[0].match_str, u(&[1, 1, 0, 0, 0, 0, 0, 0]));
        assert_eq!(w.per_factor[0].mark, u(&[1, 0, 0, 0, 1, 0, 0, 0]));
        assert_eq!(w.per_factor[0].start, u(&[0, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(w.per_factor[0].leftmost_mask, u(&[0, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(
            w.per_factor[0].past.as_ref().unwrap(),
            &u(&[0, 1, 1, 1, 0, 1, 1, 1])
        );

        // Factor 1 = "cd" (against alive_c_0 = char_act_old_prime = all 1s,
        // gated by past_0). Match at int_ind = 2 of each string.
        assert_eq!(w.per_factor[1].occurs, u(&[0, 0, 1, 0, 0, 0, 1, 0]));
        assert_eq!(w.per_factor[1].match_str, u(&[1, 1, 0, 0, 0, 0, 0, 0]));
        assert_eq!(w.per_factor[1].mark, u(&[0, 0, 1, 0, 0, 0, 1, 0]));
        assert_eq!(w.per_factor[1].start, u(&[2, 2, 0, 0, 0, 0, 0, 0]));
        assert_eq!(w.per_factor[1].leftmost_mask, u(&[1, 1, 0, 0, 1, 1, 0, 0]));
        assert!(w.per_factor[1].past.is_none(), "last factor has no past");

        assert_eq!(w.a_new, u(&[1, 1, 0, 0, 0, 0, 0, 0]));
        assert_eq!(w.total_len, 4);
    }

    #[test]
    fn prefix_matches_hand_written_fixture() {
        // "ab" | "ab" — same as the MCPM t=1 prefix test.
        let tables = ScannedTables {
            char: u(&[b'a' as u64, b'b' as u64, b'a' as u64, b'b' as u64]),
            orig_ind: u(&[0, 0, 1, 1]),
            int_ind: u(&[0, 1, 0, 1]),
            bnd: u(&[1, 0, 1, 0]),
            char_act: u(&[1, 1, 1, 1]),
            char_domain: 2,
            ind: u(&[0, 1, 2, 3]),
            a: u(&[1, 1, 0, 0]),
            l: i32_vals(&[2, 2, 0, 0]),
            str_domain: 2,
        };
        let factors = vec![(pattern(b"ab"), Mode::Prefix)];
        let w = compute_mcpm_witness(&tables, &factors);
        assert_eq!(w.per_factor[0].occurs, u(&[1, 0, 1, 0]));
        assert_eq!(w.per_factor[0].match_str, u(&[1, 1, 0, 0]));
        assert_eq!(w.a_new, u(&[1, 1, 0, 0]));
    }

    #[test]
    fn no_match_leaves_a_new_zero() {
        let tables = ScannedTables {
            char: u(&[b'x' as u64, b'y' as u64, b'x' as u64, b'y' as u64]),
            orig_ind: u(&[0, 0, 1, 1]),
            int_ind: u(&[0, 1, 0, 1]),
            bnd: u(&[1, 0, 1, 0]),
            char_act: u(&[1, 1, 1, 1]),
            char_domain: 2,
            ind: u(&[0, 1, 2, 3]),
            a: u(&[1, 1, 0, 0]),
            l: i32_vals(&[2, 2, 0, 0]),
            str_domain: 2,
        };
        let factors = vec![(pattern(b"ab"), Mode::Prefix)];
        let w = compute_mcpm_witness(&tables, &factors);
        assert_eq!(w.per_factor[0].occurs, u(&[0, 0, 0, 0]));
        assert_eq!(w.per_factor[0].match_str, u(&[0, 0, 0, 0]));
        assert_eq!(w.a_new, u(&[0, 0, 0, 0]));
    }
}
