//! Corpus loading, row bitsets and the per-corpus feature index.
//!
//! A [`Corpus`] holds the active strings of one table column. Its
//! [`FeatureIndex`] lists every fingerprint feature (character, bigram,
//! trigram, precedence pair — exactly the encoder's
//! [`for_each_feature`](arithmetic::fingerprint::for_each_feature)) that occurs
//! in some row, with the set of rows containing it as a bitset. Pre-filter
//! survivors of any assignment are then exact bitset intersections.

use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result, bail};
use arithmetic::fingerprint::{Feature, FeatureKind, for_each_feature};
use arrow::array::{Array, AsArray, BooleanArray};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use rayon::prelude::*;

/// One loaded string column: the active rows' bytes.
pub struct Corpus {
    pub strings: Vec<Vec<u8>>,
}

impl Corpus {
    /// Load `column` from a parquet file. When `activator_column` is present
    /// in the file, rows where it is `false` (hypercube padding) are skipped;
    /// pass `None` to keep every row. NULLs read as empty strings.
    pub fn from_parquet(path: &Path, column: &str, activator_column: Option<&str>) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("open parquet corpus {}", path.display()))?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
        let schema = builder.schema().clone();
        let mut projection = vec![
            schema
                .index_of(column)
                .with_context(|| format!("column '{column}' not found in {}", path.display()))?,
        ];
        let activator_column = activator_column.filter(|name| schema.index_of(name).is_ok());
        if let Some(name) = activator_column {
            projection.push(schema.index_of(name)?);
        }
        let mask = parquet::arrow::ProjectionMask::roots(
            builder.parquet_schema(),
            projection.iter().copied(),
        );
        let reader = builder.with_projection(mask).build()?;

        let mut strings: Vec<Vec<u8>> = Vec::new();
        for batch in reader {
            let batch = batch?;
            let data = batch.column(batch.schema().index_of(column)?).clone();
            let active: Option<BooleanArray> = match activator_column {
                Some(name) => Some(
                    batch
                        .column(batch.schema().index_of(name)?)
                        .as_boolean()
                        .clone(),
                ),
                None => None,
            };
            let is_active = |row: usize| {
                active
                    .as_ref()
                    .is_none_or(|a| a.is_valid(row) && a.value(row))
            };
            let values: Vec<Option<&str>> = match data.data_type() {
                arrow::datatypes::DataType::Utf8 => data.as_string::<i32>().iter().collect(),
                arrow::datatypes::DataType::LargeUtf8 => data.as_string::<i64>().iter().collect(),
                arrow::datatypes::DataType::Utf8View => data.as_string_view().iter().collect(),
                other => bail!("column '{column}' has unsupported type {other:?}"),
            };
            strings.extend(
                values
                    .into_iter()
                    .enumerate()
                    .filter(|&(row, _)| is_active(row))
                    .map(|(_, v)| v.unwrap_or_default().as_bytes().to_vec()),
            );
        }
        Ok(Self { strings })
    }

    /// The string columns of a parquet file, in file order — the columns a
    /// fingerprint can be built for. Lets callers work over a whole table
    /// without being told its schema.
    pub fn string_columns(path: &Path) -> Result<Vec<String>> {
        let file = File::open(path).with_context(|| format!("open parquet {}", path.display()))?;
        let schema = ParquetRecordBatchReaderBuilder::try_new(file)?
            .schema()
            .clone();
        Ok(schema
            .fields()
            .iter()
            .filter(|f| {
                matches!(
                    f.data_type(),
                    arrow::datatypes::DataType::Utf8
                        | arrow::datatypes::DataType::LargeUtf8
                        | arrow::datatypes::DataType::Utf8View
                )
            })
            .map(|f| f.name().clone())
            .collect())
    }

    pub fn from_strings(strings: Vec<Vec<u8>>) -> Self {
        Self { strings }
    }

    pub fn len(&self) -> usize {
        self.strings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }

    /// Mean string length in bytes.
    pub fn avg_len(&self) -> f64 {
        let total: usize = self.strings.iter().map(Vec::len).sum();
        total as f64 / self.len().max(1) as f64
    }
}

/// Row lengths held as bit-planes, so that the characters of a row set are
/// `Σⱼ 2ʲ · |set ∧ planeⱼ|`.
///
/// The cost model reads the LIKE's character count through a power-of-two
/// domain, and surviving rows are longer than the corpus average (a long row
/// is likelier to hold a pattern's features), so estimating their characters
/// as `survivors × mean length` lands on the wrong side of a power of two
/// often enough to matter. This makes the sum exact for the price of a
/// handful of word passes instead of a scan of every row.
pub struct LengthPlanes {
    planes: Vec<Vec<u64>>,
    total: f64,
}

impl LengthPlanes {
    pub fn new(corpus: &Corpus) -> Self {
        let words = corpus.len().div_ceil(64);
        let longest = corpus.strings.iter().map(Vec::len).max().unwrap_or(0);
        let bits = usize::BITS as usize - longest.leading_zeros() as usize;
        let mut planes = vec![vec![0u64; words]; bits];
        for (row, s) in corpus.strings.iter().enumerate() {
            for (j, plane) in planes.iter_mut().enumerate() {
                if s.len() >> j & 1 == 1 {
                    plane[row / 64] |= 1 << (row % 64);
                }
            }
        }
        Self {
            planes,
            total: corpus.strings.iter().map(Vec::len).sum::<usize>() as f64,
        }
    }

    /// Total characters of the whole corpus.
    pub fn total(&self) -> f64 {
        self.total
    }

    /// The characters of the rows set in `word` at word index `w`.
    #[inline(always)]
    pub fn chars_in_word(&self, w: usize, word: u64) -> usize {
        let mut chars = 0usize;
        for (j, plane) in self.planes.iter().enumerate() {
            chars += ((word & plane[w]).count_ones() as usize) << j;
        }
        chars
    }

    /// Total characters of the rows in `set`.
    pub fn chars_of(&self, set: &RowSet) -> usize {
        set.0
            .iter()
            .enumerate()
            .map(|(w, &word)| self.chars_in_word(w, word))
            .sum()
    }
}

/// Whether `s` matches the pattern `%f1%f2%…%` — every factor, in order,
/// without overlap (SQL `LIKE` semantics). The leftmost occurrence of each
/// factor leaves the most room for the rest, so a greedy scan is exact.
pub fn like_matches<F: AsRef<[u8]>>(s: &[u8], factors: &[F]) -> bool {
    let mut rest = s;
    for factor in factors {
        let f = factor.as_ref();
        if f.is_empty() {
            continue;
        }
        match rest.windows(f.len()).position(|w| w == f) {
            Some(at) => rest = &rest[at + f.len()..],
            None => return false,
        }
    }
    true
}

/// The features every string matching `%f1%f2%…%` has: the characters and
/// n-grams of each factor, and the precedence pairs of the factors read in
/// sequence — the pattern side of the encoder, deduplicated.
pub fn pattern_features<F: AsRef<[u8]>>(factors: &[F]) -> Vec<Feature> {
    let mut out = Vec::new();
    for factor in factors {
        for_each_feature(factor.as_ref(), |f| {
            if f.kind != FeatureKind::Precedence {
                out.push(f);
            }
        });
    }
    let joined: Vec<u8> = factors.iter().flat_map(|f| f.as_ref().to_vec()).collect();
    for_each_feature(&joined, |f| {
        if f.kind == FeatureKind::Precedence {
            out.push(f);
        }
    });
    out.sort_unstable();
    out.dedup();
    out
}

// --- Row bitsets ----------------------------------------------------------

/// A set of corpus rows, one bit per row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowSet(pub Vec<u64>);

impl RowSet {
    pub fn empty(rows: usize) -> Self {
        Self(vec![0; rows.div_ceil(64)])
    }

    /// Every row of a corpus with `rows` rows.
    pub fn full(rows: usize) -> Self {
        let mut set = Self(vec![u64::MAX; rows.div_ceil(64)]);
        if !rows.is_multiple_of(64)
            && let Some(last) = set.0.last_mut()
        {
            *last = (1u64 << (rows % 64)) - 1;
        }
        set
    }

    pub fn insert(&mut self, row: usize) {
        self.0[row / 64] |= 1 << (row % 64);
    }

    pub fn contains(&self, row: usize) -> bool {
        self.0[row / 64] >> (row % 64) & 1 == 1
    }

    pub fn count(&self) -> usize {
        self.0.iter().map(|w| w.count_ones() as usize).sum()
    }

    pub fn and_with(&mut self, other: &RowSet) {
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            *a &= b;
        }
    }

    pub fn or_with(&mut self, other: &RowSet) {
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            *a |= b;
        }
    }

    /// `|self ∧ other|` without materializing it.
    pub fn and_count(&self, other: &RowSet) -> usize {
        self.0
            .iter()
            .zip(&other.0)
            .map(|(a, b)| (a & b).count_ones() as usize)
            .sum()
    }

    /// The rows in the set, ascending.
    pub fn rows(&self) -> impl Iterator<Item = usize> + '_ {
        self.0.iter().enumerate().flat_map(|(w, &word)| {
            let mut rest = word;
            std::iter::from_fn(move || {
                (rest != 0).then(|| {
                    let bit = rest.trailing_zeros() as usize;
                    rest &= rest - 1;
                    w * 64 + bit
                })
            })
        })
    }
}

// --- Feature index --------------------------------------------------------

/// Every feature occurring in a corpus, with the rows containing it.
pub struct FeatureIndex {
    pub num_rows: usize,
    /// Features by dense index, sorted.
    pub features: Vec<Feature>,
    /// `rows[i]`: the rows containing `features[i]`.
    pub rows: Vec<RowSet>,
    index: HashMap<Feature, usize>,
}

impl FeatureIndex {
    pub fn build(corpus: &Corpus) -> Self {
        let num_rows = corpus.len();
        // Distinct features per row, in parallel.
        let per_row: Vec<Vec<Feature>> = corpus
            .strings
            .par_iter()
            .map(|s| {
                let mut features = Vec::new();
                for_each_feature(s, |f| features.push(f));
                features.sort_unstable();
                features.dedup();
                features
            })
            .collect();
        let mut features: Vec<Feature> = per_row.iter().flatten().copied().collect();
        features.par_sort_unstable();
        features.dedup();
        let index: HashMap<Feature, usize> =
            features.iter().enumerate().map(|(i, &f)| (f, i)).collect();
        // Row bitsets, one feature-id chunk per thread.
        let ids = &index;
        let mut postings: Vec<(usize, u32)> = per_row
            .par_iter()
            .enumerate()
            .flat_map_iter(|(row, fs)| fs.iter().map(move |f| (ids[f], row as u32)))
            .collect();
        postings.par_sort_unstable();
        let mut rows: Vec<RowSet> = (0..features.len())
            .map(|_| RowSet::empty(num_rows))
            .collect();
        rows.par_iter_mut().enumerate().for_each(|(i, set)| {
            let start = postings.partition_point(|&(f, _)| f < i);
            for &(_, row) in postings[start..].iter().take_while(|&&(f, _)| f == i) {
                set.insert(row as usize);
            }
        });
        postings.clear();
        Self {
            num_rows,
            features,
            rows,
            index,
        }
    }

    pub fn len(&self) -> usize {
        self.features.len()
    }

    pub fn is_empty(&self) -> bool {
        self.features.is_empty()
    }

    pub fn id(&self, feature: Feature) -> Option<usize> {
        self.index.get(&feature).copied()
    }

    /// Rows matching `%f1%f2%…%`: the rows having all of its features,
    /// confirmed by the exact match.
    pub fn matching_rows<F: AsRef<[u8]> + Sync>(&self, corpus: &Corpus, factors: &[F]) -> RowSet {
        let mut candidates = RowSet::full(self.num_rows);
        for feature in pattern_features(factors) {
            match self.id(feature) {
                Some(id) => candidates.and_with(&self.rows[id]),
                None => return RowSet::empty(self.num_rows),
            }
        }
        let rows: Vec<usize> = candidates.rows().collect();
        let mut out = RowSet::empty(self.num_rows);
        let hits: Vec<usize> = rows
            .par_iter()
            .copied()
            .filter(|&row| like_matches(&corpus.strings[row], factors))
            .collect();
        for row in hits {
            out.insert(row);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arithmetic::fingerprint::{FingerprintConfig, FingerprintScheme, NUM_BINS, is_subset};

    fn corpus() -> Corpus {
        Corpus::from_strings(
            [
                &b"the green light"[..],
                b"a greenhouse",
                b"nothing here",
                b"g r e e n but split",
                b"",
            ]
            .iter()
            .map(|s| s.to_vec())
            .collect(),
        )
    }

    /// The bit-plane sum must equal the naive one for every subset, since
    /// the cost model reads it through a power-of-two domain where being a
    /// little off can land on the wrong side of a step.
    #[test]
    fn length_planes_count_characters_exactly() {
        let c = corpus();
        let planes = LengthPlanes::new(&c);
        assert_eq!(
            planes.total(),
            c.strings.iter().map(Vec::len).sum::<usize>() as f64
        );
        for mask in 0u32..(1 << 5) {
            let mut set = RowSet::empty(c.len());
            let mut expected = 0usize;
            for row in 0..c.len() {
                if mask >> row & 1 == 1 {
                    set.insert(row);
                    expected += c.strings[row].len();
                }
            }
            assert_eq!(planes.chars_of(&set), expected, "rows {mask:#07b}");
        }
    }

    #[test]
    fn like_matches_keep_factor_order_without_overlap() {
        assert!(like_matches(b"the quick brown fox", &[b"quick", b"brown"]));
        assert!(!like_matches(b"the quick brown fox", &[b"brown", b"quick"]));
        assert!(!like_matches(b"abab", &[b"aba", b"bab"]));
        assert!(like_matches(b"ababab", &[b"aba", b"bab"]));
    }

    #[test]
    fn row_sets_count_and_iterate() {
        let mut s = RowSet::empty(130);
        for row in [0, 63, 64, 129] {
            s.insert(row);
        }
        assert_eq!(s.count(), 4);
        assert_eq!(s.rows().collect::<Vec<_>>(), vec![0, 63, 64, 129]);
        assert_eq!(RowSet::full(130).count(), 130);
        assert_eq!(s.and_count(&RowSet::full(130)), 4);
    }

    #[test]
    fn feature_rows_and_matches_are_exact() {
        let c = corpus();
        let index = FeatureIndex::build(&c);
        let e = index
            .id(Feature::parse(FeatureKind::Char, "e").unwrap())
            .unwrap();
        assert_eq!(index.rows[e].rows().collect::<Vec<_>>(), vec![0, 1, 2, 3]);
        let green = index.matching_rows(&c, &[b"green"]);
        assert_eq!(green.rows().collect::<Vec<_>>(), vec![0, 1]);
        let ordered = index.matching_rows(&c, &[b"g", b"t"]);
        assert_eq!(ordered.rows().collect::<Vec<_>>(), vec![0, 3]);
        assert_eq!(index.matching_rows(&c, &[b"zz"]).count(), 0);
    }

    #[test]
    fn pattern_features_are_the_encoders_pattern_bins() {
        // One bin per feature: the pattern fingerprint sets exactly the bins
        // of `pattern_features`, and every matching string has them.
        let c = corpus();
        let index = FeatureIndex::build(&c);
        let scheme = FingerprintScheme::from_config(FingerprintConfig::from_assignment(
            "one-per-bin",
            index.features.iter().take(NUM_BINS).copied().zip(0..),
            NUM_BINS,
        ))
        .unwrap();
        for factors in [vec![&b"green"[..]], vec![b"g", b"ht"], vec![b"e", b"e"]] {
            let phi = scheme.pattern_fingerprint(factors.iter().copied());
            let mut expected = arithmetic::fingerprint::EMPTY_MASK;
            for f in pattern_features(&factors) {
                if let Some(bin) = scheme.bin(f) {
                    expected[bin / 64] |= 1 << (bin % 64);
                }
            }
            assert_eq!(phi, expected, "{factors:?}");
            for row in index.matching_rows(&c, &factors).rows() {
                assert!(is_subset(&phi, &scheme.fingerprint(&c.strings[row])));
            }
        }
    }
}
