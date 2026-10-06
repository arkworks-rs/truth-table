//! Synthetic LIKE workloads with a controlled selectivity.
//!
//! Patterns are `%f1%…%fn%` with 1–3 literal factors cut, in order, from a
//! random corpus row (so they match at least that row), plus a share of
//! short patterns (up to 4 factors of 1–2 bytes, the only ones common enough
//! for the high-selectivity regimes) and a share whose factors are taken out
//! of order or from different rows (so some match nothing). Each candidate's
//! selectivity — matching rows / corpus rows — is computed exactly, and
//! candidates fill the [`REGIMES`] until each holds the requested number
//! of distinct patterns. Within a regime, sampling is
//! stratified over equal-width selectivity bands so a regime is not dominated
//! by its easiest end.

use std::collections::HashSet;

use rayon::prelude::*;

use crate::corpus::{Corpus, FeatureIndex, pattern_features};

/// Selectivity regimes `[lo, hi)`. Patterns matching half the rows or more
/// belong to none: the pre-filter cannot help them, so they are not
/// sampled.
pub const REGIMES: [(f64, f64); 3] = [(0.0, 0.01), (0.01, 0.25), (0.25, 0.5)];

/// The regime of a selectivity, `None` past the last one.
pub fn regime_of(selectivity: f64) -> Option<usize> {
    REGIMES.iter().position(|&(_, hi)| selectivity < hi)
}

/// Human-readable label of regime `r`, e.g. `"1–20%"`.
pub fn regime_label(r: usize) -> String {
    let (lo, hi) = REGIMES[r];
    if lo == 0.0 {
        format!("<{}%", hi * 100.0)
    } else {
        format!("{}–{}%", lo * 100.0, hi * 100.0)
    }
}

/// The literal factors of a `%`-only LIKE pattern (`%a%bc%` → `a`, `bc`).
pub fn parse_pattern(pattern: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    if pattern.contains(['_', '\\']) {
        anyhow::bail!("pattern {pattern:?}: only `%` wildcards are supported");
    }
    let factors: Vec<Vec<u8>> = pattern
        .split('%')
        .filter(|f| !f.is_empty())
        .map(|f| f.as_bytes().to_vec())
        .collect();
    if factors.is_empty() {
        anyhow::bail!("pattern {pattern:?} has no literal");
    }
    Ok(factors)
}

/// One workload query.
#[derive(Debug, Clone)]
pub struct Query {
    pub factors: Vec<Vec<u8>>,
    pub matches: usize,
    pub regime: usize,
    /// Dense [`FeatureIndex`] ids of the features every match has. Pattern
    /// features that occur in no row are left out: no assignment gives them
    /// a bin (a corpus-built assignment lists only corpus features).
    pub features: Vec<usize>,
}

impl Query {
    /// The SQL LIKE pattern.
    pub fn pattern(&self) -> String {
        let mut p = String::from("%");
        for f in &self.factors {
            p.push_str(&String::from_utf8_lossy(f));
            p.push('%');
        }
        p
    }

    /// Total literal length of the factors.
    pub fn literal_len(&self) -> usize {
        self.factors.iter().map(Vec::len).sum()
    }

    pub fn selectivity(&self, rows: usize) -> f64 {
        self.matches as f64 / rows.max(1) as f64
    }
}

/// SplitMix64: a small deterministic generator, one per candidate.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound.max(1) as u64) as usize
    }

    /// Index drawn with the given relative weights.
    fn weighted(&mut self, weights: &[u64]) -> usize {
        let total: u64 = weights.iter().sum();
        let mut x = self.next() % total;
        for (i, &w) in weights.iter().enumerate() {
            if x < w {
                return i;
            }
            x -= w;
        }
        weights.len() - 1
    }
}

/// Factor lengths 1..=7, favoring short ones (short literals are what
/// reach the high-selectivity regimes).
const LENGTH_WEIGHTS: [u64; 7] = [25, 20, 18, 14, 10, 7, 6];
/// Factor counts 1..=3.
const FACTOR_WEIGHTS: [u64; 3] = [45, 35, 20];
/// Short patterns: factor counts 1..=4, lengths 1..=2.
const SHORT_FACTOR_WEIGHTS: [u64; 4] = [30, 30, 25, 15];
const SHORT_LENGTH_WEIGHTS: [u64; 2] = [70, 30];

fn usable(byte: u8) -> bool {
    // `%` / `_` are LIKE wildcards and `\` an escape; keep plain bytes.
    (0x20..0x7f).contains(&byte) && !matches!(byte, b'%' | b'_' | b'\\')
}

/// One candidate pattern.
fn candidate(corpus: &Corpus, seed: u64) -> Option<Vec<Vec<u8>>> {
    let mut rng = Rng(seed);
    let short = rng.below(10) < 3;
    let (factor_weights, length_weights): (&[u64], &[u64]) = if short {
        (&SHORT_FACTOR_WEIGHTS, &SHORT_LENGTH_WEIGHTS)
    } else {
        (&FACTOR_WEIGHTS, &LENGTH_WEIGHTS)
    };
    let n = 1 + rng.weighted(factor_weights);
    let scramble = rng.below(10) == 0;
    let mut factors = Vec::with_capacity(n);
    let mut row = &corpus.strings[rng.below(corpus.len())];
    let mut at = 0;
    for _ in 0..n {
        if scramble {
            row = &corpus.strings[rng.below(corpus.len())];
            at = 0;
        }
        let len = 1 + rng.weighted(length_weights);
        if row.len() < at + len {
            break;
        }
        let start = at + rng.below(row.len() - at - len + 1);
        let factor = row[start..start + len].to_vec();
        if !factor.iter().all(|&b| usable(b)) {
            return None;
        }
        factors.push(factor);
        at = start + len;
    }
    if scramble {
        factors.reverse();
    }
    (!factors.is_empty()).then_some(factors)
}

/// Equal-width selectivity bands per regime; regime 0 separates the
/// zero-match patterns from the rest.
fn stratum(regime: usize, matches: usize, rows: usize, strata: usize) -> usize {
    let (lo, hi) = REGIMES[regime];
    let s = matches as f64 / rows as f64;
    if regime == 0 {
        if matches == 0 {
            return 0;
        }
        return 1 + (((s - lo) / (hi - lo) * (strata - 1) as f64) as usize).min(strata - 2);
    }
    (((s - lo) / (hi - lo) * strata as f64) as usize).min(strata - 1)
}

/// Generate `per_regime` distinct queries for each regime — fewer where the
/// corpus has too few distinct patterns of that selectivity (sampling stops
/// once many batches in a row add nothing).
pub fn generate(corpus: &Corpus, index: &FeatureIndex, per_regime: usize, seed: u64) -> Vec<Query> {
    const STRATA: usize = 4;
    const BATCH: u64 = 8192;
    const MAX_BATCHES: u64 = 400;
    const PATIENCE: u64 = 60;
    let rows = corpus.len();
    let quota = per_regime.div_ceil(STRATA);
    let mut filled = vec![[0usize; STRATA]; REGIMES.len()];
    // Every pattern evaluated so far, accepted or not.
    let mut evaluated: HashSet<Vec<Vec<u8>>> = HashSet::new();
    let mut out: Vec<Query> = Vec::new();
    let mut idle = 0;
    for batch in 0..MAX_BATCHES {
        if filled
            .iter()
            .all(|strata| strata.iter().sum::<usize>() >= per_regime)
            || idle >= PATIENCE
        {
            break;
        }
        let mut fresh: Vec<Vec<Vec<u8>>> = (0..BATCH)
            .into_par_iter()
            .filter_map(|i| {
                candidate(
                    corpus,
                    seed ^ (batch * BATCH + i).wrapping_mul(0x2545_f491_4f6c_dd1d),
                )
            })
            .collect();
        fresh.retain(|factors| evaluated.insert(factors.clone()));
        let candidates: Vec<(Vec<Vec<u8>>, usize)> = fresh
            .into_par_iter()
            .map(|factors| {
                let matches = index.matching_rows(corpus, &factors).count();
                (factors, matches)
            })
            .collect();
        // Bands a corpus struggles to fill (e.g. few patterns land in
        // 95–100%) hand their quota to the other bands of the regime once
        // sampling stalls.
        let band_quota = if idle < PATIENCE / 2 {
            quota
        } else {
            per_regime
        };
        let before = out.len();
        for (factors, matches) in candidates {
            let Some(regime) = regime_of(matches as f64 / rows as f64) else {
                continue;
            };
            let band = stratum(regime, matches, rows, STRATA);
            let total: usize = filled[regime].iter().sum();
            if filled[regime][band] >= band_quota || total >= per_regime {
                continue;
            }
            filled[regime][band] += 1;
            let features = pattern_features(&factors)
                .into_iter()
                .filter_map(|f| index.id(f))
                .collect();
            out.push(Query {
                factors,
                matches,
                regime,
                features,
            });
        }
        idle = if out.len() == before { idle + 1 } else { 0 };
    }
    out.sort_by_key(|a| (a.regime, a.matches));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_round_trip() {
        let factors = parse_pattern("%ab%c d%").unwrap();
        assert_eq!(factors, vec![b"ab".to_vec(), b"c d".to_vec()]);
        let q = Query {
            factors,
            matches: 0,
            regime: 0,
            features: Vec::new(),
        };
        assert_eq!(q.pattern(), "%ab%c d%");
        assert!(parse_pattern("%a_b%").is_err());
        assert!(parse_pattern("%%").is_err());
    }

    #[test]
    fn regimes_cover_selectivities_below_one_half() {
        assert_eq!(regime_of(0.0), Some(0));
        assert_eq!(regime_of(0.0099), Some(0));
        assert_eq!(regime_of(0.01), Some(1));
        assert_eq!(regime_of(0.2499), Some(1));
        assert_eq!(regime_of(0.25), Some(2));
        assert_eq!(regime_of(0.4999), Some(2));
        assert_eq!(regime_of(0.5), None);
        assert_eq!(regime_of(1.0), None);
    }

    #[test]
    fn generated_queries_have_their_stated_selectivity() {
        let words = ["alpha", "beta", "gamma", "delta", "epsilon"];
        let strings: Vec<Vec<u8>> = (0..2000)
            .map(|i| {
                let a = words[i % 5];
                let b = words[(i / 5) % 5];
                format!("{a} {b} {i}").into_bytes()
            })
            .collect();
        let corpus = Corpus::from_strings(strings);
        let index = FeatureIndex::build(&corpus);
        let queries = generate(&corpus, &index, 12, 7);
        assert!(!queries.is_empty());
        for q in &queries {
            let exact = corpus
                .strings
                .iter()
                .filter(|s| crate::corpus::like_matches(s, &q.factors))
                .count();
            assert_eq!(q.matches, exact, "{}", q.pattern());
            assert_eq!(Some(q.regime), regime_of(q.selectivity(corpus.len())));
        }
        let mut per_regime = [0usize; 6];
        for q in &queries {
            per_regime[q.regime] += 1;
        }
        assert!(per_regime.iter().all(|&n| n <= 12), "{per_regime:?}");
    }
}
