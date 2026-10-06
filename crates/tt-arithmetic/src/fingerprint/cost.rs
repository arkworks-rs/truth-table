//! The prover cost model of one `LIKE` query, and the bin selection the
//! prover makes with it.
//!
//! For `SELECT … FROM t WHERE c LIKE p` the planner builds, bottom-up:
//!
//! 1. the pre-filter `tt_prefilter(c, p, bins)` — only when the pattern has
//!    a bin to test: a row-domain witness and one zerocheck over the product
//!    of the tested bins' committed columns (a *limb* is one bin; see
//!    [`super::LIMB_BITS`]), priced per tested bin;
//! 2. a compaction of the survivors — only when they fit a strictly
//!    smaller hypercube than the input (`next_pow2⁺(s) < next_pow2⁺(n)`):
//!    a row-domain permutation and the char-domain DPUC over the compacted
//!    strings;
//! 3. the LIKE gadget on whatever domain reaches it: one keyed sumcheck per
//!    pattern character and one placement sweep per factor over the char
//!    domain;
//! 4. the result check, priced separately when the matches fit a strictly
//!    smaller hypercube than the LIKE's input rows.
//!
//! Stage 4 is named for a second compaction of the LIKE output, which
//! the planner no longer performs; the fit keeps only a small
//! per-character term for it, and the per-stage split of this model is
//! not to be read as a breakdown.
//!
//! The model prices each stage by the padded domain it works on, with
//! coefficients fitted offline to whole-prove measurements
//! (`tt-fp-opt fit`, fed by the `tt-fp-calibrate` binary) and compiled in
//! from `cost_model.toml`. It is linear in the coefficients, so a
//! non-negative least-squares fit over measured points recovers them.
//!
//! # Choosing the bins
//!
//! The prover holds the data, so it picks which of the pattern's bins the
//! pre-filter tests ([`select_bins`]), one limb — one bin — at a time:
//! starting from every row, it repeatedly adds the bin whose test leaves
//! the fewest survivors, prices the query after each step, and keeps the
//! cheapest step count — possibly none. Any subset is sound (the verifier
//! checks the bins it is told
//! against the public pattern, and testing a bin only drops rows that do
//! not match), so the choice needs no training and no agreement with the
//! verifier beyond the list of bins. The model is only a heuristic here: a
//! wrong coefficient costs time, never correctness.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use super::{Bin, FingerprintScheme, FpMask, LIMB_BITS, NUM_BINS, has_bin, limb};

/// The facts about one query run that the cost depends on.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Shape {
    /// Active rows entering the pre-filter / LIKE.
    pub rows: usize,
    /// Total characters of those rows.
    pub chars: f64,
    /// Rows passing the pre-filter (`rows` when there is none).
    pub survivors: usize,
    /// Total characters of the survivors.
    pub survivor_chars: f64,
    /// Rows matching the pattern.
    pub matches: usize,
    /// Fingerprint limbs the tested bins touch; 0 means no pre-filter.
    pub touched_limbs: usize,
    /// Total literal length of the pattern's factors.
    pub literal_len: usize,
    /// Number of literal factors (`%a%bc%` has 2).
    pub factors: usize,
}

/// The planner's compaction test: `next_power_of_two_strict`.
fn pow2_strict(x: usize) -> usize {
    if x <= 1 {
        x + 1
    } else if x.is_power_of_two() {
        x * 2
    } else {
        x.next_power_of_two()
    }
}

/// Padded domain size of `x` entries.
fn domain(x: f64) -> f64 {
    (x.max(1.0).ceil() as usize).next_power_of_two() as f64
}

/// Names of the model's terms, in coefficient order.
pub const TERMS: [&str; 15] = [
    "floor",
    "prefilter",
    "touched_limb",
    "compaction",
    "compaction_rows",
    "compaction_chars",
    "like_chars",
    "like_chars_per_extra_literal_char",
    "like_chars_per_extra_factor",
    "second_compaction",
    "second_compaction_rows",
    "second_compaction_output_chars",
    "like_rows",
    "like_rows_per_extra_literal_char",
    "like_rows_per_extra_factor",
];

/// Number of model terms.
pub const NUM_TERMS: usize = TERMS.len();

/// The regressors of a shape: seconds = `coefficients · terms(shape)`.
pub fn terms(shape: &Shape) -> [f64; NUM_TERMS] {
    let prefilter = shape.touched_limbs > 0;
    // The planner counts a scan's padding rows too, and tables are padded
    // to a power of two, so a filter straight over the scan is compared
    // against the padded row count.
    let table_rows = shape.rows.next_power_of_two();
    let compaction = prefilter && pow2_strict(shape.survivors) < pow2_strict(table_rows);
    // What the LIKE sees, and the row count the planner compares its
    // matches against.
    let (like_rows, like_chars, planner_rows) = if compaction {
        (shape.survivors, shape.survivor_chars, shape.survivors)
    } else {
        (shape.rows, shape.chars, table_rows)
    };
    let like_domain = domain(like_chars);
    let like_row_domain = domain(like_rows as f64);
    let second = pow2_strict(shape.matches) < pow2_strict(planner_rows);
    // The matches' characters, at the LIKE input's mean length.
    let match_chars = shape.matches as f64 * like_chars / like_rows.max(1) as f64;
    let on = |b: bool| if b { 1.0 } else { 0.0 };
    [
        1.0,
        on(prefilter),
        shape.touched_limbs as f64,
        on(compaction),
        on(compaction) * domain(shape.survivors as f64),
        on(compaction) * domain(shape.survivor_chars),
        like_domain,
        like_domain * (shape.literal_len as f64 - 1.0),
        like_domain * (shape.factors as f64 - 1.0),
        on(second),
        on(second) * domain(like_rows as f64),
        on(second) * domain(match_chars),
        like_row_domain,
        like_row_domain * (shape.literal_len as f64 - 1.0),
        like_row_domain * (shape.factors as f64 - 1.0),
    ]
}

/// Fitted coefficients, seconds per unit of each term in [`TERMS`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CostModel {
    pub coefficients: [f64; NUM_TERMS],
}

/// The prover's cost model, compiled into the binary: the limb model fitted
/// on `l_comment` whole-prove times.
pub const DEFAULT_COST_MODEL_TOML: &str = include_str!("../../cost_model.toml");

impl Default for CostModel {
    /// [`DEFAULT_COST_MODEL_TOML`], parsed once.
    fn default() -> Self {
        static MODEL: OnceLock<CostModel> = OnceLock::new();
        *MODEL.get_or_init(|| {
            Self::from_toml_str(DEFAULT_COST_MODEL_TOML).expect("compiled-in cost model is valid")
        })
    }
}

impl CostModel {
    /// Seconds to prove a query of this shape.
    pub fn cost(&self, shape: &Shape) -> f64 {
        self.coefficients
            .iter()
            .zip(terms(shape))
            .map(|(c, t)| c * t)
            .sum()
    }

    pub fn to_toml_string(&self) -> String {
        let table: toml::map::Map<String, toml::Value> = TERMS
            .iter()
            .zip(self.coefficients)
            .map(|(name, c)| (name.to_string(), toml::Value::Float(c)))
            .collect();
        toml::to_string_pretty(&table).expect("model serializes")
    }

    pub fn from_toml_str(s: &str) -> Result<Self, String> {
        let table: toml::map::Map<String, toml::Value> =
            toml::from_str(s).map_err(|e| e.to_string())?;
        let mut coefficients = [0.0; NUM_TERMS];
        for (i, name) in TERMS.iter().enumerate() {
            coefficients[i] = table
                .get(*name)
                .and_then(|v| v.as_float().or_else(|| v.as_integer().map(|i| i as f64)))
                .ok_or_else(|| format!("cost model is missing term {name}"))?;
        }
        Ok(Self { coefficients })
    }
}

// --- Bin selection --------------------------------------------------------

/// What [`select_bins`] chose for one query.
#[derive(Debug, Clone, PartialEq)]
pub struct Selection {
    /// The bins the pre-filter tests, ascending; empty for no pre-filter.
    pub bins: Vec<Bin>,
    /// The query's shape under that choice, as the model priced it.
    pub shape: Shape,
}

impl Selection {
    /// The pattern fingerprint the pre-filter uses: exactly [`Self::bins`].
    pub fn mask(&self) -> FpMask {
        mask_of(&self.bins)
    }
}

/// A fingerprint with exactly `bins` set.
pub fn mask_of(bins: &[Bin]) -> FpMask {
    let mut mask = super::EMPTY_MASK;
    for &b in bins {
        mask[usize::from(b) / 64] |= 1 << (usize::from(b) % 64);
    }
    mask
}

/// Choose the bins the pre-filter tests for `%f1%f2%…%` over a column
/// whose active rows are `strings`, fingerprinted under `scheme` as
/// `fingerprints`, when `matches` of them match.
///
/// The pre-filter pays per limb, not per bin: a touched limb is one lookup
/// whether it tests one of the pattern's bins or all of them. So the
/// choice is made in whole limbs. Each step adds the limb, among those
/// holding the pattern's bins, whose test (all the pattern's bins in it)
/// leaves the fewest survivors (ties to the lowest limb), then prices the
/// query with `model`. The cheapest step count wins, including zero (no
/// pre-filter). The whole chain is priced rather than stopping at the
/// first step that does not pay, since the cost falls in steps at powers
/// of two: a limb that saves nothing can precede one that crosses a step.
/// A row's fingerprint stands in for the row: a NULL is an empty string,
/// whose empty fingerprint fails every test, as the pre-filter's `false`
/// on NULL requires. Exact and cheap: one bitset intersection per
/// candidate limb per step, for a pattern's handful of limbs.
///
/// For benchmarks, [`FORCE_BINS_ENV`] replaces the priced choice with a
/// fixed prefix of the same chain.
pub fn select_bins<S: AsRef<[u8]>>(
    scheme: &FingerprintScheme,
    model: &CostModel,
    factors: &[&[u8]],
    strings: &[S],
    fingerprints: &[FpMask],
    matches: usize,
) -> Selection {
    let chain = limb_chain(scheme, model, factors, strings, fingerprints, matches);
    let best = (0..chain.steps.len())
        .min_by(|&a, &b| {
            chain.steps[a]
                .1
                .total_cmp(&chain.steps[b].1)
                .then(a.cmp(&b))
        })
        .expect("the chain starts with no pre-filter");
    let best = forced_bins().map_or(best, |k| k.min(chain.steps.len() - 1));
    let mut bins: Vec<Bin> = chain.limbs[..best]
        .iter()
        .flat_map(|&j| chain.bins_of_limb(j))
        .collect();
    bins.sort_unstable();
    Selection {
        bins,
        shape: chain.steps[best].0,
    }
}

/// Environment variable that makes [`select_bins`] test exactly the first
/// `k` bins of the greedy chain (all of them when the chain is shorter;
/// `0` means no pre-filter) instead of the cheapest prefix. For benchmarks
/// that sweep the number of bins tested; any prefix is sound, so it can
/// only change the proving time.
pub const FORCE_BINS_ENV: &str = "TT_PREFILTER_FORCE_BINS";

fn forced_bins() -> Option<usize> {
    std::env::var(FORCE_BINS_ENV).ok()?.parse().ok()
}

/// The prover's greedy chain for one query: the limbs in the order it adds
/// them, and the query's shape and cost after each prefix (`steps[k]`
/// after `k` limbs; `steps[0]` is no pre-filter).
#[derive(Debug, Clone)]
pub struct LimbChain {
    /// The pattern's bins, ascending.
    pub candidates: Vec<Bin>,
    /// Limbs in the order the greedy adds them.
    pub limbs: Vec<usize>,
    pub steps: Vec<(Shape, f64)>,
}

impl LimbChain {
    /// The pattern's bins in limb `j`.
    pub fn bins_of_limb(&self, j: usize) -> impl Iterator<Item = Bin> + '_ {
        self.candidates
            .iter()
            .copied()
            .filter(move |&b| usize::from(b) / LIMB_BITS == j)
    }
}

/// The whole greedy chain of [`select_bins`], every prefix priced.
pub fn limb_chain<S: AsRef<[u8]>>(
    scheme: &FingerprintScheme,
    model: &CostModel,
    factors: &[&[u8]],
    strings: &[S],
    fingerprints: &[FpMask],
    matches: usize,
) -> LimbChain {
    assert_eq!(strings.len(), fingerprints.len());
    let rows = strings.len();
    let lengths: Vec<u32> = strings.iter().map(|s| s.as_ref().len() as u32).collect();
    let chars: f64 = lengths.iter().map(|&l| f64::from(l)).sum();
    let literal_len = factors.iter().map(|f| f.len()).sum();
    let shape_of = |survivors: usize, survivor_chars: f64, touched: usize| Shape {
        rows,
        chars,
        survivors,
        survivor_chars,
        matches,
        touched_limbs: touched,
        literal_len,
        factors: factors.len(),
    };

    let phi = scheme.pattern_fingerprint(factors.iter().copied());
    let candidates: Vec<Bin> = (0..NUM_BINS)
        .filter(|&b| has_bin(&phi, b))
        .map(|b| b as Bin)
        .collect();
    let mut limb_ids: Vec<usize> = candidates
        .iter()
        .map(|&b| usize::from(b) / LIMB_BITS)
        .collect();
    limb_ids.dedup();
    let words = rows.div_ceil(64);
    // Rows passing each candidate limb's test: every pattern bit of the
    // limb set in the row's limb.
    let mut limb_rows: Vec<Vec<u64>> = vec![vec![0u64; words]; limb_ids.len()];
    for (row, fp) in fingerprints.iter().enumerate() {
        for (k, &j) in limb_ids.iter().enumerate() {
            let want = limb(&phi, j);
            if limb(fp, j) & want == want {
                limb_rows[k][row / 64] |= 1 << (row % 64);
            }
        }
    }

    let mut alive = vec![u64::MAX; words];
    if let Some(last) = alive.last_mut()
        && !rows.is_multiple_of(64)
    {
        *last = (1u64 << (rows % 64)) - 1;
    }
    let none = shape_of(rows, chars, 0);
    let mut steps = vec![(none, model.cost(&none))];
    let mut limbs: Vec<usize> = Vec::new();
    let mut remaining: Vec<usize> = (0..limb_ids.len()).collect();
    while !remaining.is_empty() {
        let (_, at) = remaining
            .iter()
            .enumerate()
            .map(|(at, &k)| {
                let kept: u32 = alive
                    .iter()
                    .zip(&limb_rows[k])
                    .map(|(a, b)| (a & b).count_ones())
                    .sum();
                (kept, at)
            })
            .min()
            .expect("non-empty");
        let k = remaining.remove(at);
        for (a, b) in alive.iter_mut().zip(&limb_rows[k]) {
            *a &= b;
        }
        let (mut survivors, mut survivor_chars) = (0usize, 0.0);
        for (w, word) in alive.iter().enumerate() {
            let mut bits = *word;
            while bits != 0 {
                let row = w * 64 + bits.trailing_zeros() as usize;
                bits &= bits - 1;
                survivors += 1;
                survivor_chars += f64::from(lengths[row]);
            }
        }
        limbs.push(limb_ids[k]);
        let shape = shape_of(survivors, survivor_chars, limbs.len());
        steps.push((shape, model.cost(&shape)));
    }
    LimbChain {
        candidates,
        limbs,
        steps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::{Feature, FeatureKind, FingerprintConfig, is_subset};

    fn shape(survivors: usize, matches: usize, touched: usize) -> Shape {
        Shape {
            rows: 300_000,
            chars: 8.0e6,
            survivors,
            survivor_chars: survivors as f64 * 26.5,
            matches,
            touched_limbs: touched,
            literal_len: 4,
            factors: 1,
        }
    }

    #[test]
    fn stages_follow_the_planner() {
        // No pre-filter: full-domain LIKE, stage 4 when matches shrink.
        let t = terms(&shape(300_000, 1_000, 0));
        assert_eq!(&t[..6], &[1.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
        assert_eq!(t[6], (1 << 23) as f64);
        assert_eq!(&t[9..11], &[1.0, (1 << 19) as f64]);
        assert_eq!(t[11], (1u64 << 15) as f64);
        // Pre-filter that compacts: LIKE on the survivors' chars; matches
        // within the survivors' hypercube → no stage 4.
        let t = terms(&shape(1_000, 900, 2));
        assert_eq!(&t[..5], &[1.0, 1.0, 2.0, 1.0, 1024.0]);
        assert_eq!(t[6], 32768.0);
        assert_eq!(t[9], 0.0);
        // The scan's padding counts: 270,000 survivors of 300,000 active
        // rows still compact (2^19 < 2^20 for the padded 2^19 table), and
        // 260,000 matches trip stage 4 (2^18 < 2^19).
        let t = terms(&shape(270_000, 260_000, 1));
        assert_eq!(t[3], 1.0);
        assert_eq!(t[9], 1.0);
        // A table with no padding and a pre-filter that drops nothing: no
        // compaction, and stage 4 only when matches shrink.
        let mut full = shape(1 << 18, 1 << 18, 1);
        full.rows = 1 << 18;
        let t = terms(&full);
        assert_eq!(t[3], 0.0);
        assert_eq!(t[9], 0.0);
    }

    #[test]
    fn compiled_in_model_parses_and_round_trips() {
        let model = CostModel::default();
        assert!(model.coefficients[0] > 0.0, "a floor");
        assert_eq!(
            CostModel::from_toml_str(&model.to_toml_string()).unwrap(),
            model
        );
        assert!(CostModel::from_toml_str("floor = 1.0").is_err());
    }

    /// Every alphanumeric character in its own bin, so a pattern's bins are
    /// exactly its distinct characters.
    fn char_scheme() -> FingerprintScheme {
        let assignment = (0..crate::fingerprint::NUM_ALNUM).map(|i| {
            let key = (crate::fingerprint::alnum_byte(i) as char).to_string();
            (Feature::parse(FeatureKind::Char, &key).unwrap(), i)
        });
        FingerprintScheme::from_config(FingerprintConfig::from_assignment(
            "chars", assignment, NUM_BINS,
        ))
        .unwrap()
    }

    fn corpus() -> Vec<Vec<u8>> {
        let words = [
            "furiously",
            "quick",
            "deposits",
            "sleep",
            "regular",
            "ideas",
            "zebra",
        ];
        (0..4000u64)
            .map(|i| {
                let h = i.wrapping_mul(0x9e37_79b9_7f4a_7c15);
                let pick = |s: u32| words[((h >> s) % 7) as usize];
                format!("{} {} {}", pick(3), pick(17), pick(31)).into_bytes()
            })
            .collect()
    }

    fn model(limb: f64, rows: f64) -> CostModel {
        let mut coefficients = [0.0; NUM_TERMS];
        coefficients[0] = 10.0;
        coefficients[2] = limb;
        coefficients[12] = rows;
        CostModel { coefficients }
    }

    #[test]
    fn greedy_adds_the_most_selective_limb_and_only_while_it_pays() {
        let scheme = char_scheme();
        let strings = corpus();
        let fps = scheme.fingerprint_all(&strings);
        let factors: [&[u8]; 1] = [b"zebra"];
        let matches = strings
            .iter()
            .filter(|s| s.windows(5).any(|w| w == b"zebra"))
            .count();
        // Rows are expensive and limbs are free: test until nothing helps.
        let cheap = select_bins(
            &scheme,
            &model(0.0, 1e-3),
            &factors,
            &strings,
            &fps,
            matches,
        );
        // `z` and `b` occur in "zebra" alone, so the limb holding either
        // leaves exactly the matches, and no further limb can pay. The
        // chosen limb is tested whole: every pattern bin in it.
        let limbs: Vec<usize> = cheap
            .bins
            .iter()
            .map(|&b| usize::from(b) / LIMB_BITS)
            .collect();
        assert!(limbs.windows(2).all(|w| w[0] == w[1]), "{:?}", cheap.bins);
        let only_in_zebra: Vec<Bin> = ["z", "b"]
            .iter()
            .map(|c| {
                scheme
                    .bin(Feature::parse(FeatureKind::Char, c).unwrap())
                    .unwrap() as Bin
            })
            .collect();
        assert!(cheap.bins.iter().any(|b| only_in_zebra.contains(b)));
        let phi = scheme.pattern_fingerprint(factors.iter().copied());
        let in_limb = (0..NUM_BINS)
            .filter(|&b| has_bin(&phi, b) && b / LIMB_BITS == limbs[0])
            .count();
        assert_eq!(cheap.bins.len(), in_limb);
        assert_eq!(cheap.shape.survivors, matches);
        assert_eq!(cheap.shape.touched_limbs, 1);
        // The survivors are exactly the rows holding every chosen bin.
        let mask = cheap.mask();
        let survivors = fps.iter().filter(|fp| is_subset(&mask, fp)).count();
        assert_eq!(cheap.shape.survivors, survivors);
        assert!(survivors >= matches);
        // Every chosen bin is one of the pattern's.
        assert!(is_subset(&mask, &phi));
        // Limbs are ruinous: no pre-filter at all.
        let dear = select_bins(
            &scheme,
            &model(1e9, 1e-3),
            &factors,
            &strings,
            &fps,
            matches,
        );
        assert!(dear.bins.is_empty());
        assert_eq!(dear.shape.touched_limbs, 0);
        assert_eq!(dear.shape.survivors, strings.len());
    }

    #[test]
    fn a_pattern_without_bins_selects_nothing() {
        let scheme = char_scheme();
        let strings = corpus();
        let fps = scheme.fingerprint_all(&strings);
        let factors: [&[u8]; 1] = [b" "];
        let chosen = select_bins(&scheme, &model(0.0, 1e-3), &factors, &strings, &fps, 4000);
        assert!(chosen.bins.is_empty());
    }
}
