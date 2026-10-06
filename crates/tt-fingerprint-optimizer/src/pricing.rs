//! Price a workload under an assignment, each query choosing its bins as
//! the prover does.
//!
//! [`select`] prices every query three ways: with no pre-filter, with the
//! prover's choice of limbs ([`arithmetic::fingerprint::cost::limb_chain`],
//! rebuilt here on row bitsets) and with a perfect filter that keeps only
//! the matching rows.

use arithmetic::fingerprint::{Bin, Feature, LIMB_BITS, NUM_BINS};
use rayon::prelude::*;

use crate::corpus::{FeatureIndex, LengthPlanes, RowSet};
use crate::model::{CostModel, Shape};
use crate::workload::Query;

// --- Bitset kernels -------------------------------------------------------

/// Rows and characters of an intersection: the two numbers the cost model
/// needs, accumulated in one pass.
type Survivors = (usize, usize);

/// `|a ∧ b|` and its characters, over word slices of equal length.
fn and_count(a: &[u64], b: &[u64], len: &LengthPlanes) -> Survivors {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("popcnt") {
            // SAFETY: the CPU supports POPCNT (checked just above).
            return unsafe { and_count_popcnt(a, b, len) };
        }
    }
    and_count_generic(a, b, len)
}

#[inline(always)]
fn and_count_generic(a: &[u64], b: &[u64], len: &LengthPlanes) -> Survivors {
    let (mut rows, mut chars) = (0usize, 0usize);
    for (w, (x, y)) in a.iter().zip(b).enumerate() {
        let both = x & y;
        rows += both.count_ones() as usize;
        chars += len.chars_in_word(w, both);
    }
    (rows, chars)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "popcnt")]
unsafe fn and_count_popcnt(a: &[u64], b: &[u64], len: &LengthPlanes) -> Survivors {
    and_count_generic(a, b, len)
}

/// `dst ← dst ∧ src`, returning `|dst|` and its characters.
fn and_assign_count(dst: &mut [u64], src: &[u64], len: &LengthPlanes) -> Survivors {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("popcnt") {
            // SAFETY: the CPU supports POPCNT (checked just above).
            return unsafe { and_assign_count_popcnt(dst, src, len) };
        }
    }
    and_assign_count_generic(dst, src, len)
}

#[inline(always)]
fn and_assign_count_generic(dst: &mut [u64], src: &[u64], len: &LengthPlanes) -> Survivors {
    let (mut rows, mut chars) = (0usize, 0usize);
    for (w, (d, s)) in dst.iter_mut().zip(src).enumerate() {
        *d &= s;
        rows += d.count_ones() as usize;
        chars += len.chars_in_word(w, *d);
    }
    (rows, chars)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "popcnt")]
unsafe fn and_assign_count_popcnt(dst: &mut [u64], src: &[u64], len: &LengthPlanes) -> Survivors {
    and_assign_count_generic(dst, src, len)
}

// --- Problem --------------------------------------------------------------

/// The fixed inputs of a pricing run.
pub struct Problem<'a> {
    pub index: &'a FeatureIndex,
    pub queries: &'a [Query],
    pub model: CostModel,
    /// Active corpus rows and their total characters.
    pub rows: usize,
    pub chars: f64,
    /// Row lengths, for the exact characters of a survivor set.
    pub len: &'a LengthPlanes,
}

impl<'a> Problem<'a> {
    pub fn new(
        index: &'a FeatureIndex,
        queries: &'a [Query],
        model: CostModel,
        len: &'a LengthPlanes,
    ) -> Self {
        Self {
            index,
            queries,
            model,
            rows: index.num_rows,
            chars: len.total(),
            len,
        }
    }

    /// The model cost of query `q` with these survivors (rows and their
    /// characters) and touched limbs (0 touched limbs = no pre-filter).
    fn cost(&self, q: usize, survivors: Survivors, touched: usize) -> f64 {
        let query = &self.queries[q];
        let ((survivors, survivor_chars), touched) = if touched == 0 {
            ((self.rows, self.chars as usize), 0)
        } else {
            (survivors, touched)
        };
        self.model.cost(&Shape {
            rows: self.rows,
            chars: self.chars,
            survivors,
            survivor_chars: survivor_chars as f64,
            matches: query.matches,
            touched_limbs: touched,
            literal_len: query.literal_len(),
            factors: query.factors.len(),
        })
    }
}

/// A feature → bin assignment over a [`FeatureIndex`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    pub bin_of: Vec<Option<Bin>>,
}

impl Assignment {
    /// Assigned features and their bins, for a scheme.
    pub fn pairs(&self, index: &FeatureIndex) -> Vec<(Feature, usize)> {
        self.bin_of
            .iter()
            .enumerate()
            .filter_map(|(i, b)| b.map(|b| (index.features[i], b as usize)))
            .collect()
    }

    /// Bins holding at least one feature.
    pub fn used_bins(&self) -> usize {
        let mut used = vec![false; NUM_BINS];
        for &b in self.bin_of.iter().flatten() {
            used[b as usize] = true;
        }
        used.into_iter().filter(|&u| u).count()
    }
}

// --- Bin row sets ---------------------------------------------------------

/// Each bin's rows: those having any of its features.
struct State<'p, 'a> {
    p: &'p Problem<'a>,
    bin_of: &'p [Option<Bin>],
    bin_rows: Vec<RowSet>,
}

impl<'p, 'a> State<'p, 'a> {
    fn new(p: &'p Problem<'a>, assignment: &'p Assignment) -> Self {
        let mut bin_rows: Vec<RowSet> = (0..NUM_BINS).map(|_| RowSet::empty(p.rows)).collect();
        for (f, bin) in assignment.bin_of.iter().enumerate() {
            if let Some(b) = *bin {
                bin_rows[b as usize].or_with(&p.index.rows[f]);
            }
        }
        Self {
            p,
            bin_of: &assignment.bin_of,
            bin_rows,
        }
    }

    /// The sorted assigned bins of query `q`.
    fn query_bins(&self, q: usize) -> Vec<Bin> {
        let mut bins: Vec<Bin> = self.p.queries[q]
            .features
            .iter()
            .filter_map(|&f| self.bin_of[f])
            .collect();
        bins.sort_unstable();
        bins.dedup();
        bins
    }

    /// The prover's greedy chain for query `q`, as
    /// [`arithmetic::fingerprint::cost::limb_chain`] builds it: whole limbs,
    /// the most selective first. `chain[k]` is the bins tested, survivors
    /// and cost after `k` limbs; `chain[0]` is no pre-filter.
    fn chain(&self, q: usize) -> Vec<(usize, Survivors, f64)> {
        let bins = self.query_bins(q);
        let mut limbs: Vec<(usize, usize, RowSet)> = Vec::new();
        for &b in &bins {
            let j = b as usize / LIMB_BITS;
            let rows = &self.bin_rows[b as usize];
            match limbs.iter_mut().find(|(l, _, _)| *l == j) {
                Some((_, count, set)) => {
                    set.and_with(rows);
                    *count += 1;
                }
                None => limbs.push((j, 1, rows.clone())),
            }
        }
        limbs.sort_by_key(|&(j, _, _)| j);
        let mut scratch = RowSet::full(self.p.rows);
        let all = (self.p.rows, self.p.chars as usize);
        let mut chain = vec![(0, all, self.p.cost(q, all, 0))];
        let mut tested = 0;
        while !limbs.is_empty() {
            let next = limbs
                .iter()
                .enumerate()
                .map(|(i, (_, _, rows))| (and_count(&scratch.0, &rows.0, self.p.len).0, i))
                .min()
                .map(|(_, i)| i)
                .expect("non-empty");
            let (_, count, rows) = limbs.remove(next);
            let kept = and_assign_count(&mut scratch.0, &rows.0, self.p.len);
            tested += count;
            let touched = chain.len();
            chain.push((tested, kept, self.p.cost(q, kept, touched)));
        }
        chain
    }
}

/// One query with no pre-filter, with the prover's bins and with a perfect
/// filter.
#[derive(Debug, Clone)]
pub struct Selected {
    pub regime: usize,
    /// No pre-filter at all.
    pub none: f64,
    /// The prover's choice ([`select`]).
    pub greedy: f64,
    pub greedy_bins: usize,
    pub greedy_limbs: usize,
    pub greedy_survivors: usize,
    pub greedy_survivor_chars: usize,
    /// The cost after each prefix of the prover's limb chain: `chain[k]`
    /// after `k` limbs, `chain[0]` no pre-filter.
    pub chain: Vec<f64>,
    /// A perfect filter: one limb, and only the matching rows survive (at
    /// the corpus' mean length), or no pre-filter when that is cheaper, as
    /// the prover would choose. The ceiling of any feature improvement.
    pub perfect: f64,
    pub matches: usize,
}

/// Price every query choosing its own bins, as the prover does.
///
/// The prover holds the data, so it can afford the exact choice: starting
/// from all rows, it repeatedly adds the limb, among those holding the
/// pattern's bins, whose test leaves the fewest survivors, pricing the
/// query after every step, and keeps the cheapest step count — possibly
/// none. That is one bitset intersection per (step, candidate), a few
/// milliseconds for a pattern's handful of limbs. Any subset is sound (the
/// verifier checks the bins it is told, and every one is implied by the
/// public pattern), so the choice needs no agreement with the verifier.
pub fn select(problem: &Problem<'_>, assignment: &Assignment) -> Vec<Selected> {
    let state = State::new(problem, assignment);
    (0..problem.queries.len())
        .into_par_iter()
        .map(|q| {
            let r = problem.queries[q].regime;
            let chain = state.chain(q);
            let greedy_limbs = (0..chain.len())
                .min_by(|&a, &b| chain[a].2.total_cmp(&chain[b].2).then(a.cmp(&b)))
                .expect("the chain starts with no pre-filter");
            let (greedy_bins, (greedy_survivors, greedy_survivor_chars), greedy) =
                chain[greedy_limbs];
            let matches = problem.queries[q].matches;
            let match_chars =
                (matches as f64 * problem.chars / problem.rows.max(1) as f64) as usize;
            Selected {
                perfect: problem.cost(q, (matches, match_chars), 1).min(chain[0].2),
                matches,
                regime: r,
                none: chain[0].2,
                greedy,
                greedy_bins,
                greedy_limbs,
                greedy_survivors,
                greedy_survivor_chars,
                chain: chain.iter().map(|&(_, _, c)| c).collect(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::Corpus;
    use crate::model::NUM_TERMS;
    use crate::workload;
    use arithmetic::fingerprint::{FingerprintConfig, FingerprintScheme, is_subset};

    fn corpus() -> Corpus {
        let words = [
            "furiously",
            "quick",
            "deposits",
            "sleep",
            "regular",
            "ideas",
            "final",
            "packages",
            "bold",
            "accounts",
        ];
        Corpus::from_strings(
            (0..3000u64)
                .map(|i| {
                    let h = i.wrapping_mul(0x9e37_79b9_7f4a_7c15);
                    let pick = |s: u32| words[((h >> s) % 10) as usize];
                    format!("{} {} {}", pick(3), pick(17), pick(31)).into_bytes()
                })
                .collect(),
        )
    }

    fn model() -> CostModel {
        let mut coefficients = [0.0; NUM_TERMS];
        coefficients[0] = 10.0; // floor
        coefficients[1] = 0.2; // pre-filter
        coefficients[2] = 0.1; // touched limb
        coefficients[6] = 1e-3; // LIKE chars
        coefficients[10] = 1e-3; // second compaction rows
        CostModel { coefficients }
    }

    #[test]
    fn greedy_selection_never_loses_to_no_filter_and_matches_the_encoder() {
        let c = corpus();
        let index = FeatureIndex::build(&c);
        let queries = workload::generate(&c, &index, 6, 3);
        let lengths = LengthPlanes::new(&c);
        let problem = Problem::new(&index, &queries, model(), &lengths);
        let assignment = Assignment {
            bin_of: (0..index.len())
                .map(|f| Some((f * 37 % NUM_BINS) as Bin))
                .collect(),
        };
        let scheme = FingerprintScheme::from_config(FingerprintConfig::from_assignment(
            "t",
            assignment.pairs(&index),
            NUM_BINS,
        ))
        .unwrap();
        let fps = scheme.fingerprint_all(&c.strings);
        let state = State::new(&problem, &assignment);
        let selected = select(&problem, &assignment);
        assert_eq!(selected.len(), queries.len());
        for (q, (query, sel)) in queries.iter().zip(&selected).enumerate() {
            let chain = state.chain(q);
            let (all_bins, (all_survivors, _), all_cost) = *chain.last().unwrap();
            assert!(sel.greedy <= sel.none, "{}", query.pattern());
            // Testing every bin is one of the prefixes the greedy weighs.
            assert!(sel.greedy <= all_cost + 1e-9, "{}", query.pattern());
            assert_eq!(all_bins, state.query_bins(q).len());
            // Testing every bin leaves exactly the encoder's survivors.
            let phi = scheme.pattern_fingerprint(query.factors.iter().map(Vec::as_slice));
            if all_bins > 0 {
                let expected = fps.iter().filter(|fp| is_subset(&phi, fp)).count();
                assert_eq!(all_survivors, expected, "{}", query.pattern());
            }
            assert!(sel.greedy_survivors >= query.matches);
            if sel.greedy_bins == 0 {
                assert_eq!(sel.greedy, sel.none);
                assert_eq!(sel.greedy_survivors, problem.rows);
            }
        }
    }

    /// The offline chain is the prover's: same limbs in the same order,
    /// same survivors, same choice.
    #[test]
    fn offline_selection_is_the_provers() {
        let c = corpus();
        let index = FeatureIndex::build(&c);
        let queries = workload::generate(&c, &index, 6, 4);
        let lengths = LengthPlanes::new(&c);
        let problem = Problem::new(&index, &queries, model(), &lengths);
        let assignment = Assignment {
            bin_of: (0..index.len())
                .map(|f| Some((f * 37 % NUM_BINS) as Bin))
                .collect(),
        };
        let scheme = FingerprintScheme::from_config(FingerprintConfig::from_assignment(
            "t",
            assignment.pairs(&index),
            NUM_BINS,
        ))
        .unwrap();
        let fps = scheme.fingerprint_all(&c.strings);
        let selected = select(&problem, &assignment);
        for (query, sel) in queries.iter().zip(&selected) {
            let factors: Vec<&[u8]> = query.factors.iter().map(Vec::as_slice).collect();
            let prover = arithmetic::fingerprint::cost::select_bins(
                &scheme,
                &model(),
                &factors,
                &c.strings,
                &fps,
                query.matches,
            );
            assert_eq!(sel.greedy_bins, prover.bins.len(), "{}", query.pattern());
            assert_eq!(sel.greedy_limbs, prover.shape.touched_limbs);
            assert_eq!(sel.greedy_survivors, prover.shape.survivors);
            assert!((sel.greedy - model().cost(&prover.shape)).abs() < 1e-6);
        }
    }
}
