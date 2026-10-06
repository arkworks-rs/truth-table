//! The workload-free rule every string column is committed under: every
//! feature gets its own bin.
//!
//! The prover chooses per query which of a pattern's bins to test
//! ([`super::cost::select_bins`]), and a private bin per feature leaves it
//! every choice: no feature's rows are blurred by another's.
//!
//! The only choice left is which features get a bin when a column has more
//! than [`NUM_BINS`]. A feature in every row can never remove a row, so it
//! gets none; of the rest, the ones in the most rows are kept, because a
//! pattern is cut from the column's own text and so contains a feature
//! about as often as the rows do. Bins are numbered in that order, most
//! common first.
//!
//! Each bin is its own committed column, so a wide rule costs the data
//! owner commitment time, but not oracle size (the oracle keeps one Merkle
//! root per column) and not the prover: a query opens and reads only the
//! bins it tests.

use rayon::prelude::*;

use super::{Feature, FeatureKind, FingerprintConfig, NUM_BINS};
use super::{MIN_ROWS, row_features, slot, slots};

/// The single-feature rule of a column: one bin per feature some row has
/// and not every row has, the most common first, at most [`NUM_BINS`]; no
/// pre-filter below [`MIN_ROWS`] rows. `strings` are the column's active
/// rows.
pub fn single_feature_rule<S: AsRef<[u8]> + Sync>(
    name: impl Into<String>,
    strings: &[S],
) -> FingerprintConfig {
    single_feature_rule_at(name, strings, NUM_BINS)
}

/// [`single_feature_rule`] keeping only the `width` most common features;
/// width zero means no pre-filter.
pub fn single_feature_rule_at<S: AsRef<[u8]> + Sync>(
    name: impl Into<String>,
    strings: &[S],
    width: usize,
) -> FingerprintConfig {
    let name = name.into();
    if strings.len() < MIN_ROWS || width == 0 {
        return FingerprintConfig {
            name,
            bins: 0,
            ..FingerprintConfig::default()
        };
    }
    let features = ranked_features(strings);
    let chosen: Vec<Feature> = features.into_iter().take(width.min(NUM_BINS)).collect();
    let bins = chosen.len();
    FingerprintConfig::from_assignment(
        name,
        chosen.into_iter().enumerate().map(|(bin, f)| (f, bin)),
        bins,
    )
}

/// Every feature in some but not every row, the most common first (ties
/// by kind and id, so the rule is deterministic).
fn ranked_features<S: AsRef<[u8]> + Sync>(strings: &[S]) -> Vec<Feature> {
    let n = strings.len();
    let support = strings
        .par_chunks(4096)
        .map(|chunk| {
            let mut counts = vec![0u32; slots()];
            for row in chunk {
                for f in row_features(row.as_ref()) {
                    counts[slot(f)] += 1;
                }
            }
            counts
        })
        .reduce(
            || vec![0u32; slots()],
            |mut a, b| {
                a.iter_mut().zip(b).for_each(|(x, y)| *x += y);
                a
            },
        );
    let mut ranked: Vec<(u32, Feature)> = FeatureKind::ALL
        .iter()
        .flat_map(|&kind| (0..kind.id_space() as u32).map(move |id| Feature { kind, id }))
        .map(|f| (support[slot(f)], f))
        .filter(|&(s, _)| s > 0 && (s as usize) < n)
        .collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    ranked.into_iter().map(|(_, f)| f).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::{FingerprintScheme, is_subset};

    fn corpus(rows: u64) -> Vec<String> {
        let words = [
            "furiously",
            "quick",
            "deposits",
            "sleep",
            "regular",
            "ideas",
        ];
        (0..rows)
            .map(|i| {
                let h = i.wrapping_mul(0x9e37_79b9_7f4a_7c15);
                let pick = |s: u32| words[((h >> s) % 6) as usize];
                format!("{} {}. {}", pick(3), pick(17), pick(31))
            })
            .collect()
    }

    #[test]
    fn every_feature_gets_a_private_bin_except_the_universal_ones() {
        let c = corpus(MIN_ROWS as u64);
        let config = single_feature_rule("t", &c);
        let assignment = config.assignment().unwrap();
        let mut bins: Vec<usize> = assignment.iter().map(|&(_, b)| b).collect();
        bins.sort_unstable();
        bins.dedup();
        assert_eq!(bins.len(), assignment.len(), "no two features share a bin");
        assert_eq!(config.bins, assignment.len());
        // Every row has a space and a period, so neither gets a bin.
        let space = Feature::parse(FeatureKind::Char, " ").unwrap();
        let dot = Feature::parse(FeatureKind::Char, ".").unwrap();
        assert!(assignment.iter().all(|&(f, _)| f != space && f != dot));
        // The word-start bigram of a word some rows lack does get one.
        let q = Feature::parse(FeatureKind::Bigram, " q").unwrap();
        assert!(assignment.iter().any(|&(f, _)| f == q));
    }

    #[test]
    fn a_match_always_passes_and_small_columns_get_no_rule() {
        let c = corpus(MIN_ROWS as u64);
        let scheme = FingerprintScheme::from_config(single_feature_rule("t", &c)).unwrap();
        let phi = scheme.pattern_fingerprint([b"sleep".as_slice(), b"deposits".as_slice()]);
        for row in c.iter().filter(|r| {
            r.find("sleep")
                .is_some_and(|i| r[i + 5..].contains("deposits"))
        }) {
            assert!(is_subset(&phi, &scheme.fingerprint(row.as_bytes())));
        }
        let small = single_feature_rule("t", &corpus(100));
        assert!(small.assignment().unwrap().is_empty());
        assert_eq!(small.bins, 0);
    }
}
