//! String fingerprints (paper §6.1) with a runtime bin budget.
//!
//! A fingerprint is a bit vector of up to [`NUM_BINS`] bits: bit `b` is set
//! iff the string has a feature assigned to bin `b`. Pre-filtering reduces the pattern-match test
//! to the subset identity `fp(s) ∧ φ = φ`, where `φ` is the fingerprint of
//! the pattern's literal factors.
//!
//! One [`FingerprintScheme`] fixes a single feature → bin **assignment** over
//! all [`NUM_BINS`] bins. A query does not have to test all of the pattern's
//! bins: the prover picks the subset that makes the query cheapest
//! ([`cost::select_bins`]), and the verifier only checks that every bin it
//! is told is one of the pattern's. Dropping bins from `φ` only drops
//! constraints, so every subset is sound. The scheme's **width** (`bins`)
//! fixes the columns the data owner commits; every assigned bin lies below
//! it.
//!
//! Fingerprints are committed one boolean column per bin (a *limb* of
//! [`LIMB_BITS`] = 1 bin), so a query pays only for the bins it tests, and
//! the Pre-Filtering Check is a single product constraint over them. A
//! narrow scheme commits nothing wider: [`NUM_BINS`] is only a ceiling.
//!
//! # Features
//!
//! - a **character**: one ASCII byte;
//! - a **bigram** / **trigram**: 2 / 3 adjacent bytes read over a 64-symbol
//!   alphabet — the 62 ASCII alphanumerics, the space, and one symbol for
//!   every other byte. An n-gram with a space or "other" symbol in it says
//!   where a word starts or ends, which is what `% i%` or `%n %` need; the
//!   alphanumeric-only n-grams break at spaces and cannot;
//! - a **precedence** pair `ab`: an alphanumeric `a` whose first occurrence
//!   comes before the last occurrence of an alphanumeric `b` (`aa` means `a`
//!   occurs twice).
//!
//! A feature the assignment does not list sets no bin. Whatever the
//! assignment, the construction is conservative: a string containing the
//! pattern has every character and n-gram of each literal factor, and every
//! precedence pair of the factors read in order (a LIKE match keeps its
//! factors in order and apart), so it sets every bin `φ` sets.
//!
//! # File format
//!
//! A scheme is plain TOML, stored per column in the table's `.oracle`
//! ([`FingerprintRules`]):
//!
//! ```toml
//! name = "l_comment"
//! bins = 2048         # the width: bins 0..2048, one committed column each
//!
//! [chars]
//! e = 3
//! [bigrams]
//! th = 0
//! "n " = 7        # n ending a word
//! _i = 9          # i after punctuation (`_` stands for any other byte)
//! [trigrams]
//! the = 12
//! [precedence]
//! ae = 40
//! ```

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock, RwLock};

use serde::{Deserialize, Serialize};

pub mod cost;
pub mod merkle;
pub mod single;

/// The ceiling on how many bins a scheme may use. Not a per-scheme width:
/// [`FingerprintScheme::num_limbs`] gives the limbs a scheme actually
/// commits, and the Pre-Filtering Check folds limbs with a challenge rather
/// than packing them into one field element, so nothing here is bounded by
/// the scalar modulus.
pub const NUM_BINS: usize = 2048;
/// Bins per committed fingerprint column (a *limb*): one, so every bin is
/// its own boolean column and a query tests exactly the bins it chooses.
pub const LIMB_BITS: usize = 1;
/// Limb columns a scheme using every bin would commit.
pub const NUM_LIMBS: usize = NUM_BINS.div_ceil(LIMB_BITS);
/// 64-bit words in an [`FpMask`].
pub const MASK_WORDS: usize = NUM_BINS.div_ceil(64);

/// A bin index. Wider than a limb: [`NUM_BINS`] may exceed 256.
pub type Bin = u16;

/// An empty fingerprint.
pub const EMPTY_MASK: FpMask = [0u64; MASK_WORDS];

/// A fingerprint as a bit vector: bin `b` is bit `b % 64` of word `b / 64`.
pub type FpMask = [u64; MASK_WORDS];

/// Alphanumeric bytes: `0-9`, `a-z`, `A-Z`.
pub const NUM_ALNUM: usize = 62;

/// Sentinel for "not alphanumeric" in [`alnum_index`].
const NOT_ALNUM: u8 = u8::MAX;

/// Dense index of an alphanumeric byte (`0-9` → 0–9, `a-z` → 10–35, `A-Z` →
/// 36–61), or `None`.
pub fn alnum_index(byte: u8) -> Option<usize> {
    let i = ALNUM_INDEX[byte as usize];
    (i != NOT_ALNUM).then_some(i as usize)
}

/// Inverse of [`alnum_index`].
pub fn alnum_byte(index: usize) -> u8 {
    ALNUM_BYTES[index]
}

const ALNUM_BYTES: [u8; NUM_ALNUM] = {
    let mut out = [0u8; NUM_ALNUM];
    let mut i = 0;
    while i < 10 {
        out[i] = b'0' + i as u8;
        i += 1;
    }
    while i < 36 {
        out[i] = b'a' + (i - 10) as u8;
        i += 1;
    }
    while i < NUM_ALNUM {
        out[i] = b'A' + (i - 36) as u8;
        i += 1;
    }
    out
};

const ALNUM_INDEX: [u8; 256] = {
    let mut out = [NOT_ALNUM; 256];
    let mut i = 0;
    while i < NUM_ALNUM {
        out[ALNUM_BYTES[i] as usize] = i as u8;
        i += 1;
    }
    out
};

/// Symbols of the n-gram alphabet: the alphanumerics by [`alnum_index`],
/// then the space, then one symbol for every other byte.
pub const NUM_SYMBOLS: usize = NUM_ALNUM + 2;
const SPACE_SYMBOL: u8 = NUM_ALNUM as u8;
const OTHER_SYMBOL: u8 = NUM_ALNUM as u8 + 1;
/// The byte a scheme-file key writes for [`OTHER_SYMBOL`].
const OTHER_KEY: u8 = b'_';

const SYMBOL_INDEX: [u8; 256] = {
    let mut out = [OTHER_SYMBOL; 256];
    let mut i = 0;
    while i < NUM_ALNUM {
        out[ALNUM_BYTES[i] as usize] = i as u8;
        i += 1;
    }
    out[b' ' as usize] = SPACE_SYMBOL;
    out
};

/// The symbol a scheme-file key byte names: an alphanumeric, the space, or
/// [`OTHER_KEY`] for every other byte. A stray punctuation byte is refused
/// rather than read as "other", so one feature has one spelling.
fn parse_symbol(byte: u8) -> Option<u32> {
    match byte {
        b' ' => Some(u32::from(SPACE_SYMBOL)),
        OTHER_KEY => Some(u32::from(OTHER_SYMBOL)),
        _ => alnum_index(byte).map(|i| i as u32),
    }
}

/// Inverse of [`parse_symbol`].
fn symbol_key_byte(symbol: u32) -> u8 {
    match symbol as u8 {
        SPACE_SYMBOL => b' ',
        OTHER_SYMBOL => OTHER_KEY,
        i => alnum_byte(i as usize),
    }
}

// --- Features -------------------------------------------------------------

/// The four feature kinds a fingerprint bins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FeatureKind {
    Char,
    Bigram,
    Trigram,
    Precedence,
}

impl FeatureKind {
    pub const ALL: [FeatureKind; 4] = [
        FeatureKind::Char,
        FeatureKind::Bigram,
        FeatureKind::Trigram,
        FeatureKind::Precedence,
    ];

    /// Number of distinct features of this kind (the size of its id space).
    pub fn id_space(self) -> usize {
        match self {
            FeatureKind::Char => 128,
            FeatureKind::Bigram => NUM_SYMBOLS * NUM_SYMBOLS,
            FeatureKind::Trigram => NUM_SYMBOLS * NUM_SYMBOLS * NUM_SYMBOLS,
            FeatureKind::Precedence => NUM_ALNUM * NUM_ALNUM,
        }
    }

    fn label(self) -> &'static str {
        match self {
            FeatureKind::Char => "character",
            FeatureKind::Bigram => "bigram",
            FeatureKind::Trigram => "trigram",
            FeatureKind::Precedence => "precedence",
        }
    }
}

/// One feature, identified by its kind and a dense id: an ASCII byte for a
/// character, base-64 symbol indices for an n-gram (`a·64 + b` for the
/// bigram `ab`, `(a·64 + b)·64 + c` for a trigram), base-62 alphanumeric
/// indices for a precedence pair (`a·62 + b`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Feature {
    pub kind: FeatureKind,
    pub id: u32,
}

impl Feature {
    /// Parse a feature key of the given kind (`"e"`, `"th"`, `"n "`,
    /// `"_in"`, `"ae"`).
    pub fn parse(kind: FeatureKind, key: &str) -> Result<Self, String> {
        let bytes = key.as_bytes();
        let alnum = |i: usize| alnum_index(bytes[i]).map(|x| x as u32);
        let symbol = |i: usize| parse_symbol(bytes[i]);
        let id = match (kind, bytes.len()) {
            (FeatureKind::Char, 1) if bytes[0].is_ascii() => Some(u32::from(bytes[0])),
            (FeatureKind::Bigram, 2) => symbol(0).zip(symbol(1)).map(|(a, b)| a * 64 + b),
            (FeatureKind::Trigram, 3) => symbol(0)
                .zip(symbol(1))
                .zip(symbol(2))
                .map(|((a, b), c)| (a * 64 + b) * 64 + c),
            (FeatureKind::Precedence, 2) => alnum(0).zip(alnum(1)).map(|(a, b)| a * 62 + b),
            _ => None,
        };
        id.map(|id| Feature { kind, id })
            .ok_or_else(|| format!("{} feature {key:?} is malformed", kind.label()))
    }

    /// The feature's key as written in a scheme file.
    pub fn key(&self) -> String {
        let alnum = |i: u32| alnum_byte(i as usize) as char;
        let symbol = |i: u32| symbol_key_byte(i) as char;
        match self.kind {
            FeatureKind::Char => (self.id as u8 as char).to_string(),
            FeatureKind::Bigram => [symbol(self.id / 64), symbol(self.id % 64)]
                .iter()
                .collect(),
            FeatureKind::Trigram => [
                symbol(self.id / 4096),
                symbol(self.id / 64 % 64),
                symbol(self.id % 64),
            ]
            .iter()
            .collect(),
            FeatureKind::Precedence => [alnum(self.id / 62), alnum(self.id % 62)].iter().collect(),
        }
    }
}

/// Below this many rows a column gets no pre-filter: its padded domains are
/// too small for any bin count to repay the pre-filter's limbs.
pub const MIN_ROWS: usize = 1 << 14;

/// Dense index over every feature id: chars, then bigrams, trigrams and
/// precedence pairs.
fn slot(feature: Feature) -> usize {
    let mut base = 0;
    for kind in FeatureKind::ALL {
        if kind == feature.kind {
            return base + feature.id as usize;
        }
        base += kind.id_space();
    }
    unreachable!("every kind is in FeatureKind::ALL")
}

/// Size of the [`slot`] index.
fn slots() -> usize {
    FeatureKind::ALL.iter().map(|k| k.id_space()).sum()
}

/// A row's distinct features, sorted.
fn row_features(row: &[u8]) -> Vec<Feature> {
    let mut out = Vec::new();
    for_each_feature(row, |f| out.push(f));
    out.sort_unstable();
    out.dedup();
    out
}

/// Visit every distinct-or-not feature occurrence of `bytes` read in order:
/// characters, bigrams and trigrams at their positions, then each
/// precedence pair once. The encoder and offline tooling share this walk,
/// so they can never disagree on what a string's features are.
pub fn for_each_feature(bytes: &[u8], mut visit: impl FnMut(Feature)) {
    let mut first = [u32::MAX; NUM_ALNUM];
    let mut last = [0u32; NUM_ALNUM];
    let mut seen = 0u64;
    let (mut p1, mut p2) = (0u32, 0u32);
    for (pos, &byte) in bytes.iter().enumerate() {
        if byte.is_ascii() {
            visit(Feature {
                kind: FeatureKind::Char,
                id: u32::from(byte),
            });
        }
        let symbol = u32::from(SYMBOL_INDEX[byte as usize]);
        if pos >= 1 {
            let bigram = p1 * 64 + symbol;
            visit(Feature {
                kind: FeatureKind::Bigram,
                id: bigram,
            });
            if pos >= 2 {
                visit(Feature {
                    kind: FeatureKind::Trigram,
                    id: p2 * 4096 + bigram,
                });
            }
        }
        (p2, p1) = (p1, symbol);
        let i = ALNUM_INDEX[byte as usize] as usize;
        if i == NOT_ALNUM as usize {
            continue;
        }
        if seen >> i & 1 == 0 {
            seen |= 1 << i;
            first[i] = pos as u32;
        }
        last[i] = pos as u32;
    }
    let mut rest_a = seen;
    while rest_a != 0 {
        let a = rest_a.trailing_zeros() as usize;
        rest_a &= rest_a - 1;
        let mut rest_b = seen;
        while rest_b != 0 {
            let b = rest_b.trailing_zeros() as usize;
            rest_b &= rest_b - 1;
            if first[a] < last[b] {
                visit(Feature {
                    kind: FeatureKind::Precedence,
                    id: (a * 62 + b) as u32,
                });
            }
        }
    }
}

// --- Scheme description ---------------------------------------------------

/// A complete scheme as written in its TOML file.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FingerprintConfig {
    /// Free-form provenance label.
    pub name: String,
    /// The width: bins `0..bins` exist and the column commits
    /// `bins / 8` limbs. Zero means no pre-filter.
    #[serde(default)]
    pub bins: usize,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub chars: BTreeMap<String, usize>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bigrams: BTreeMap<String, usize>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub trigrams: BTreeMap<String, usize>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub precedence: BTreeMap<String, usize>,
}

/// Per-column fingerprint rules for one table.
///
/// The data owner optimizes every *string* column separately — other column
/// types are never fingerprinted — and ships the result inside the table's
/// `.oracle`, so prover and verifier read the same rule for the column a LIKE
/// filters instead of sharing a compile-time default.
///
/// # Trust
///
/// A rule is trusted table metadata, on the same footing as the schema. The
/// pre-filter avoids false negatives only when the committed `__fp` limbs were
/// built with the same rule the verifier uses for the pattern, and nothing in
/// the proof checks that they were. A data owner who declares one rule and
/// commits limbs from another can hide rows of their own table — but they
/// could equally commit different data, so this grants them no new power. What
/// it does buy is that an untrusted *prover* cannot influence the rule, since
/// the verifier takes it from the oracle and never from the proof.
///
/// A column with no entry is not pre-filtered at all, and neither is one
/// of width zero — what a rule gives a column too small for a pre-filter to
/// help. `commit` gives every string column an entry ([`column_rule`]).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FingerprintRules {
    /// Rule per string column name.
    #[serde(default)]
    pub columns: BTreeMap<String, FingerprintConfig>,
}

impl FingerprintRules {
    /// The rule for `column`, or `None` when it is not fingerprinted.
    pub fn get(&self, column: &str) -> Option<&FingerprintConfig> {
        self.columns.get(column)
    }

    /// Fold another table's rules in.
    ///
    /// Rules are keyed by column name, and two tables may use the same name.
    /// A disagreement is an error rather than last-one-wins, because
    /// fingerprinting a column under the wrong rule drops rows that do match.
    pub fn merge(&mut self, other: FingerprintRules) -> Result<(), String> {
        for (column, config) in other.columns {
            match self.columns.get(&column) {
                Some(existing) if *existing != config => {
                    return Err(format!(
                        "two tables give column '{column}' different fingerprint rules                          ('{}' and '{}'); rename one or commit them separately",
                        existing.name, config.name
                    ));
                }
                Some(_) => {}
                None => {
                    self.columns.insert(column, config);
                }
            }
        }
        Ok(())
    }

    pub fn to_toml_string(&self) -> String {
        toml::to_string_pretty(self).expect("fingerprint rules serialize to TOML")
    }

    pub fn from_toml_str(s: &str) -> Result<Self, String> {
        toml::from_str(s).map_err(|e| e.to_string())
    }
}

/// The rule `commit` gives a string column: one private bin per feature,
/// the most common first, at most `width` bins
/// ([`single::single_feature_rule_at`]). It needs no workload, only the
/// column's active rows `strings`; width zero means no pre-filter.
pub fn column_rule<S: AsRef<[u8]> + Sync>(
    column: &str,
    strings: &[S],
    width: usize,
) -> FingerprintConfig {
    single::single_feature_rule_at(column, strings, width)
}

/// The table's per-column rules, installed once before encoding, planning or
/// verifying. The data owner writes them; `commit` puts them in the `.oracle`;
/// prover and verifier both read them back from there, so they cannot
/// disagree about how a column was fingerprinted.
#[derive(Default)]
struct ActiveRules {
    rules: FingerprintRules,
    /// Compiled schemes, cached per column and dropped with their rules.
    compiled: BTreeMap<String, Option<FingerprintScheme>>,
}

static RULES: OnceLock<RwLock<ActiveRules>> = OnceLock::new();

fn rules_cell() -> &'static RwLock<ActiveRules> {
    RULES.get_or_init(|| RwLock::new(ActiveRules::default()))
}

/// Install `rules` for every later encode, plan and verify in this process.
///
/// Rules accumulate rather than replace, because one process may hold several
/// tables at once — a test harness proves many queries in parallel, and a join
/// spans tables. Replacing would let one table's rules silently drop another's,
/// and a column that falls back to the wrong rule loses rows that do match.
/// Conflicting definitions for one column name are refused for the same
/// reason. Use [`reset_rules`] to start over.
pub fn configure_rules(rules: FingerprintRules) -> Result<(), String> {
    let mut guard = rules_cell()
        .write()
        .map_err(|_| "fingerprint rules lock poisoned".to_string())?;
    let mut merged = guard.rules.clone();
    merged.merge(rules)?;
    if merged != guard.rules {
        *guard = ActiveRules {
            rules: merged,
            compiled: BTreeMap::new(),
        };
    }
    Ok(())
}

/// Forget every installed rule, so later columns take the default scheme.
pub fn reset_rules() {
    if let Ok(mut guard) = rules_cell().write() {
        *guard = ActiveRules::default();
    }
}

/// The rules currently installed.
pub fn configured_rules() -> FingerprintRules {
    rules_cell()
        .read()
        .map(|g| g.rules.clone())
        .unwrap_or_default()
}

/// The scheme that fingerprints `column`, or `None` when it is not
/// fingerprinted: `column` is `None`, no rules are installed, the rules do
/// not mention it, or its policy never uses a bin. The rules are
/// authoritative; `commit` writes one for every string column.
pub fn scheme_for_column(column: Option<&str>) -> Option<FingerprintScheme> {
    let column = column?;
    if let Ok(guard) = rules_cell().read()
        && let Some(hit) = guard.compiled.get(column)
    {
        return hit.clone();
    }
    let compiled = {
        let guard = rules_cell().read().ok()?;
        match guard.rules.get(column) {
            // An invalid rule is dropped rather than panicking mid-encode;
            // the column is then simply not pre-filtered.
            Some(config) => FingerprintScheme::from_config(config.clone()).ok(),
            None => None,
        }
    };
    if let Ok(mut guard) = rules_cell().write() {
        guard.compiled.insert(column.to_string(), compiled.clone());
    }
    compiled
}

impl FingerprintConfig {
    /// A config of width `bins` from an assignment.
    pub fn from_assignment(
        name: impl Into<String>,
        assignment: impl IntoIterator<Item = (Feature, usize)>,
        bins: usize,
    ) -> Self {
        let mut config = FingerprintConfig {
            name: name.into(),
            bins,
            ..Self::default()
        };
        for (feature, bin) in assignment {
            config.map_mut(feature.kind).insert(feature.key(), bin);
        }
        config
    }

    fn map(&self, kind: FeatureKind) -> &BTreeMap<String, usize> {
        match kind {
            FeatureKind::Char => &self.chars,
            FeatureKind::Bigram => &self.bigrams,
            FeatureKind::Trigram => &self.trigrams,
            FeatureKind::Precedence => &self.precedence,
        }
    }

    fn map_mut(&mut self, kind: FeatureKind) -> &mut BTreeMap<String, usize> {
        match kind {
            FeatureKind::Char => &mut self.chars,
            FeatureKind::Bigram => &mut self.bigrams,
            FeatureKind::Trigram => &mut self.trigrams,
            FeatureKind::Precedence => &mut self.precedence,
        }
    }

    /// Every assigned feature and its bin, each below the width.
    pub fn assignment(&self) -> Result<Vec<(Feature, usize)>, String> {
        let mut out = Vec::new();
        for kind in FeatureKind::ALL {
            for (key, &bin) in self.map(kind) {
                let feature = Feature::parse(kind, key)?;
                if bin >= self.bins {
                    return Err(format!(
                        "{} feature {key:?} → bin {bin} out of range (0..{})",
                        kind.label(),
                        self.bins
                    ));
                }
                out.push((feature, bin));
            }
        }
        Ok(out)
    }
}

// --- Compiled scheme ------------------------------------------------------

/// Table entry for "no bin" — [`set_bin`] writes nothing for it.
const NO_BIN: Bin = Bin::MAX;

#[derive(Debug)]
struct Compiled {
    config: FingerprintConfig,
    /// Bin per ASCII byte (non-ASCII bytes have none).
    char_bin: [Bin; 256],
    /// Bin per bigram id.
    bigram_bin: Vec<Bin>,
    /// Bin per trigram id.
    trigram_bin: Vec<Bin>,
    /// Bin per precedence id.
    precedence_bin: Vec<Bin>,
    /// For each alnum `a`: bit `b` set iff the pair `ab` has a bin.
    precedence_row: [u64; NUM_ALNUM],
    has_ngrams: bool,
    has_precedence: bool,
}

fn compile(config: FingerprintConfig) -> Result<Compiled, String> {
    if config.bins > NUM_BINS {
        return Err(format!(
            "width {} is more than {NUM_BINS} bins",
            config.bins
        ));
    }
    let mut char_bin = [NO_BIN; 256];
    let mut bigram_bin = vec![NO_BIN; FeatureKind::Bigram.id_space()];
    let mut trigram_bin = vec![NO_BIN; FeatureKind::Trigram.id_space()];
    let mut precedence_bin = vec![NO_BIN; FeatureKind::Precedence.id_space()];
    let mut precedence_row = [0u64; NUM_ALNUM];
    for (feature, bin) in config.assignment()? {
        let id = feature.id as usize;
        let bin = bin as Bin;
        match feature.kind {
            FeatureKind::Char => char_bin[id] = bin,
            FeatureKind::Bigram => bigram_bin[id] = bin,
            FeatureKind::Trigram => trigram_bin[id] = bin,
            FeatureKind::Precedence => {
                precedence_bin[id] = bin;
                precedence_row[id / 62] |= 1 << (id % 62);
            }
        }
    }
    let has_ngrams = bigram_bin
        .iter()
        .chain(&trigram_bin)
        .any(|&bin| bin != NO_BIN);
    let has_precedence = precedence_row.iter().any(|&row| row != 0);
    Ok(Compiled {
        config,
        char_bin,
        bigram_bin,
        trigram_bin,
        precedence_bin,
        precedence_row,
        has_ngrams,
        has_precedence,
    })
}

#[inline(always)]
fn set_bin(mask: &mut FpMask, bin: Bin) {
    if bin != NO_BIN {
        mask[(bin >> 6) as usize] |= 1 << (bin & 63);
    }
}

// --- The scheme handle ----------------------------------------------------

/// A fingerprint scheme: a compiled [`FingerprintConfig`] behind a cheap
/// clonable handle. Equality compares the configs.
#[derive(Debug, Clone)]
pub struct FingerprintScheme(Arc<Compiled>);

impl PartialEq for FingerprintScheme {
    fn eq(&self, other: &Self) -> bool {
        self.0.config == other.0.config
    }
}

impl FingerprintScheme {
    pub fn from_config(config: FingerprintConfig) -> Result<Self, String> {
        Ok(Self(Arc::new(compile(config)?)))
    }

    pub fn config(&self) -> &FingerprintConfig {
        &self.0.config
    }

    /// The bin of a feature, or `None` when it has none.
    pub fn bin(&self, feature: Feature) -> Option<usize> {
        let id = feature.id as usize;
        let bin = match feature.kind {
            FeatureKind::Char => self.0.char_bin.get(id).copied().unwrap_or(NO_BIN),
            FeatureKind::Bigram => self.0.bigram_bin[id],
            FeatureKind::Trigram => self.0.trigram_bin[id],
            FeatureKind::Precedence => self.0.precedence_bin[id],
        };
        (bin != NO_BIN).then_some(bin as usize)
    }

    /// The width: every bin of this scheme is below it.
    pub fn max_bins(&self) -> usize {
        self.0.config.bins
    }

    /// Limb columns a string column under this scheme commits: enough to
    /// hold every bin, and none at width zero. This, not [`NUM_LIMBS`], is
    /// the committed width.
    pub fn num_limbs(&self) -> usize {
        self.max_bins().div_ceil(LIMB_BITS)
    }

    /// Fingerprint of one string.
    pub fn fingerprint(&self, s: &[u8]) -> FpMask {
        let c = &*self.0;
        let mut mask = EMPTY_MASK;
        if !c.has_ngrams && !c.has_precedence {
            for &byte in s {
                set_bin(&mut mask, c.char_bin[byte as usize]);
            }
            return mask;
        }
        let mut first = [u32::MAX; NUM_ALNUM];
        let mut last = [0u32; NUM_ALNUM];
        let mut seen = 0u64;
        let (mut p1, mut p2) = (0usize, 0usize);
        for (pos, &byte) in s.iter().enumerate() {
            set_bin(&mut mask, c.char_bin[byte as usize]);
            if c.has_ngrams {
                let symbol = SYMBOL_INDEX[byte as usize] as usize;
                if pos >= 1 {
                    let bigram = p1 * 64 + symbol;
                    set_bin(&mut mask, c.bigram_bin[bigram]);
                    if pos >= 2 {
                        set_bin(&mut mask, c.trigram_bin[p2 * 4096 + bigram]);
                    }
                }
                (p2, p1) = (p1, symbol);
            }
            let i = ALNUM_INDEX[byte as usize] as usize;
            if i == NOT_ALNUM as usize {
                continue;
            }
            if seen >> i & 1 == 0 {
                seen |= 1 << i;
                first[i] = pos as u32;
            }
            last[i] = pos as u32;
        }
        if c.has_precedence {
            self.set_precedence(&mut mask, seen, &first, &last);
        }
        mask
    }

    #[inline]
    fn set_precedence(
        &self,
        mask: &mut FpMask,
        seen: u64,
        first: &[u32; NUM_ALNUM],
        last: &[u32; NUM_ALNUM],
    ) {
        let c = &*self.0;
        let mut rest_a = seen;
        while rest_a != 0 {
            let a = rest_a.trailing_zeros() as usize;
            rest_a &= rest_a - 1;
            let mut rest_b = c.precedence_row[a] & seen;
            while rest_b != 0 {
                let b = rest_b.trailing_zeros() as usize;
                rest_b &= rest_b - 1;
                if first[a] < last[b] {
                    set_bin(mask, c.precedence_bin[a * 62 + b]);
                }
            }
        }
    }

    /// Fingerprints of many strings, in order, computed in parallel.
    #[cfg(feature = "parallel")]
    pub fn fingerprint_all<S: AsRef<[u8]> + Sync>(&self, strings: &[S]) -> Vec<FpMask> {
        use rayon::prelude::*;
        strings
            .par_iter()
            .with_min_len(1 << 12)
            .map(|s| self.fingerprint(s.as_ref()))
            .collect()
    }

    /// Fingerprints of many strings, in order.
    #[cfg(not(feature = "parallel"))]
    pub fn fingerprint_all<S: AsRef<[u8]> + Sync>(&self, strings: &[S]) -> Vec<FpMask> {
        strings
            .iter()
            .map(|s| self.fingerprint(s.as_ref()))
            .collect()
    }

    /// Fingerprint `φ` of a pattern from its literal factors, in pattern
    /// order (paper §6.2). Characters
    /// and n-grams come from each factor alone — a wildcard can match
    /// anything, so n-grams never cross factors. Precedence pairs come from
    /// the factors read in sequence: a match keeps its factors in order, so
    /// every pair the sequence orders is ordered in the matching string too.
    pub fn pattern_fingerprint<'a>(&self, factors: impl IntoIterator<Item = &'a [u8]>) -> FpMask {
        let factors: Vec<&[u8]> = factors.into_iter().collect();
        let mut mask = EMPTY_MASK;
        for factor in &factors {
            let local = self.fingerprint_local(factor);
            for (m, l) in mask.iter_mut().zip(local) {
                *m |= l;
            }
        }
        if self.0.has_precedence {
            let mut first = [u32::MAX; NUM_ALNUM];
            let mut last = [0u32; NUM_ALNUM];
            let mut seen = 0u64;
            for (pos, i) in factors
                .iter()
                .flat_map(|f| f.iter())
                .enumerate()
                .filter_map(|(pos, &b)| alnum_index(b).map(|i| (pos, i)))
            {
                if seen >> i & 1 == 0 {
                    seen |= 1 << i;
                    first[i] = pos as u32;
                }
                last[i] = pos as u32;
            }
            self.set_precedence(&mut mask, seen, &first, &last);
        }
        mask
    }

    /// Characters and n-grams of one run of bytes (no precedence).
    fn fingerprint_local(&self, s: &[u8]) -> FpMask {
        let c = &*self.0;
        let mut mask = EMPTY_MASK;
        let (mut p1, mut p2) = (0usize, 0usize);
        for (pos, &byte) in s.iter().enumerate() {
            set_bin(&mut mask, c.char_bin[byte as usize]);
            if !c.has_ngrams {
                continue;
            }
            let symbol = SYMBOL_INDEX[byte as usize] as usize;
            if pos >= 1 {
                let bigram = p1 * 64 + symbol;
                set_bin(&mut mask, c.bigram_bin[bigram]);
                if pos >= 2 {
                    set_bin(&mut mask, c.trigram_bin[p2 * 4096 + bigram]);
                }
            }
            (p2, p1) = (p1, symbol);
        }
        mask
    }
}

/// The subset test `sub ∧ sup = sub` — `is_subset(φ, fp)` is the
/// pre-filter's keep condition.
#[inline]
pub fn is_subset(sub: &FpMask, sup: &FpMask) -> bool {
    sub.iter().zip(sup).all(|(s, f)| s & f == *s)
}

/// Limb `j` (bins `j·LIMB_BITS ..` the next [`LIMB_BITS`]) of a
/// fingerprint; with one bin per limb, bin `j` as 0 or 1.
#[inline]
pub fn limb(mask: &FpMask, j: usize) -> u8 {
    const { assert!(LIMB_BITS <= 8 && LIMB_BITS.is_power_of_two()) };
    let bit = j * LIMB_BITS;
    ((mask[bit / 64] >> (bit % 64)) & ((1u64 << LIMB_BITS) - 1)) as u8
}

/// The limbs a fingerprint touches (`limb ≠ 0`), ascending.
pub fn touched_limbs(mask: &FpMask) -> Vec<usize> {
    (0..NUM_LIMBS).filter(|&j| limb(mask, j) != 0).collect()
}

/// Whether bin `b` is set.
#[inline]
pub fn has_bin(mask: &FpMask, bin: usize) -> bool {
    mask[bin / 64] >> (bin % 64) & 1 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feature(kind: FeatureKind, key: &str) -> Feature {
        Feature::parse(kind, key).unwrap()
    }

    fn scheme(assignment: &[(FeatureKind, &str, usize)]) -> FingerprintScheme {
        FingerprintScheme::from_config(FingerprintConfig::from_assignment(
            "test",
            assignment
                .iter()
                .map(|&(k, key, bin)| (feature(k, key), bin)),
            NUM_BINS,
        ))
        .unwrap()
    }

    /// Every feature of every kind hashed into `bins`.
    fn dense(bins: usize) -> FingerprintScheme {
        let mut assignment = Vec::new();
        let mut next = 0;
        for kind in FeatureKind::ALL {
            for id in 0..kind.id_space() as u32 {
                assignment.push((Feature { kind, id }, next % bins));
                next += 7;
            }
        }
        FingerprintScheme::from_config(FingerprintConfig::from_assignment(
            "dense", assignment, bins,
        ))
        .unwrap()
    }

    fn passes(s: &FingerprintScheme, factors: &[&[u8]], string: &[u8]) -> bool {
        is_subset(
            &s.pattern_fingerprint(factors.iter().copied()),
            &s.fingerprint(string),
        )
    }

    /// The encoder's fingerprint equals the bins of the shared feature walk.
    fn reference(s: &FingerprintScheme, string: &[u8]) -> FpMask {
        let mut mask = EMPTY_MASK;
        for_each_feature(string, |f| {
            if let Some(bin) = s.bin(f) {
                mask[bin / 64] |= 1 << (bin % 64);
            }
        });
        mask
    }

    #[test]
    fn feature_keys_round_trip() {
        for (kind, key) in [
            (FeatureKind::Char, " "),
            (FeatureKind::Char, "Z"),
            (FeatureKind::Bigram, "t9"),
            (FeatureKind::Bigram, "t "),
            (FeatureKind::Bigram, "_i"),
            (FeatureKind::Trigram, "Abz"),
            (FeatureKind::Trigram, "s_ "),
            (FeatureKind::Precedence, "aa"),
        ] {
            assert_eq!(feature(kind, key).key(), key);
        }
        // Every non-alphanumeric byte but the space is one symbol, spelled `_`.
        assert!(Feature::parse(FeatureKind::Bigram, "t.").is_err());
        assert!(Feature::parse(FeatureKind::Precedence, "t ").is_err());
        assert!(Feature::parse(FeatureKind::Trigram, "ab").is_err());
        assert!(Feature::parse(FeatureKind::Char, "é").is_err());
        for kind in FeatureKind::ALL {
            for id in (0..kind.id_space() as u32).step_by(97) {
                let f = Feature { kind, id };
                assert_eq!(Feature::parse(kind, &f.key()).unwrap(), f);
            }
        }
    }

    #[test]
    fn fingerprint_sets_the_bins_of_each_feature_kind() {
        let s = scheme(&[
            (FeatureKind::Char, "q", 0),
            (FeatureKind::Bigram, "th", 9),
            (FeatureKind::Trigram, "the", 70),
            (FeatureKind::Precedence, "ay", 252),
        ]);
        let bins = |string: &[u8]| -> Vec<usize> {
            let mask = s.fingerprint(string);
            (0..NUM_BINS).filter(|&b| has_bin(&mask, b)).collect()
        };
        assert_eq!(bins(b"q"), vec![0]);
        assert_eq!(bins(b"the"), vec![9, 70]);
        assert_eq!(bins(b"t h e"), Vec::<usize>::new());
        assert_eq!(bins(b"a..y"), vec![252]);
        assert_eq!(bins(b"y..a"), Vec::<usize>::new());
    }

    #[test]
    fn n_grams_see_word_boundaries() {
        let s = scheme(&[
            (FeatureKind::Bigram, "n ", 1),
            (FeatureKind::Bigram, "_i", 2),
            (FeatureKind::Trigram, " in", 3),
            (FeatureKind::Trigram, "s_ ", 4),
        ]);
        let bins = |string: &[u8]| -> Vec<usize> {
            let mask = s.fingerprint(string);
            (0..NUM_BINS).filter(|&b| has_bin(&mask, b)).collect()
        };
        assert_eq!(bins(b"in the"), vec![1]);
        assert_eq!(bins(b"go in"), vec![3]);
        assert_eq!(bins(b"inside"), Vec::<usize>::new());
        // `_` is every byte that is neither alphanumeric nor a space.
        assert_eq!(bins(b"x.in"), vec![2]);
        assert_eq!(bins(b"x,in"), vec![2]);
        assert_eq!(bins(b"x in"), vec![3]);
        assert_eq!(bins(b"ideas. bold"), vec![4]);
        assert_eq!(bins(b"ideas, bold"), vec![4]);
        assert_eq!(bins(b"ideas bold"), Vec::<usize>::new());
        // A word ending in n: the pattern side sees the same n-grams.
        assert!(passes(&s, &[b"n "], b"in the"));
        assert!(!passes(&s, &[b"n "], b"inside"));
        assert!(passes(&s, &[b"s. "], b"ideas, bold"));
    }

    #[test]
    fn encoder_matches_the_feature_walk() {
        let s = dense(NUM_BINS);
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..2000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = (state % 20) as usize;
            let string: Vec<u8> = (0..len)
                .map(|i| b"abc1 -."[(state >> (i * 3) & 7) as usize % 7])
                .collect();
            assert_eq!(s.fingerprint(&string), reference(&s, &string), "{string:?}");
        }
    }

    #[test]
    fn precedence_discriminates_order_across_gaps() {
        let s = scheme(&[
            (FeatureKind::Char, "a", 1),
            (FeatureKind::Char, "c", 2),
            (FeatureKind::Precedence, "ac", 3),
            (FeatureKind::Precedence, "aa", 4),
        ]);
        assert!(passes(&s, &[b"a", b"c"], b"a..c"));
        assert!(!passes(&s, &[b"a", b"c"], b"c..a"));
        assert!(passes(&s, &[b"a", b"a"], b"a.a"));
        assert!(!passes(&s, &[b"a", b"a"], b"a"));
    }

    #[test]
    fn generated_matches_never_yield_false_negatives() {
        // Strings over a small alphabet (so characters repeat and orders
        // collide); patterns are ordered, non-overlapping substrings of the
        // string, so every one of them matches it — under every scheme.
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = |bound: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % bound as u64) as usize
        };
        let schemes = [dense(NUM_BINS), dense(20)];
        for _ in 0..4000 {
            let len = 1 + next(24);
            let string: Vec<u8> = (0..len).map(|_| b"abcab1 -"[next(8)]).collect();
            let mut factors: Vec<&[u8]> = Vec::new();
            let mut at = 0;
            while at < len && factors.len() < 3 {
                let start = at + next(len - at);
                let end = start + 1 + next((len - start).min(4));
                factors.push(&string[start..end]);
                at = end;
            }
            for s in &schemes {
                assert!(
                    passes(s, &factors, &string),
                    "false negative for {factors:?} in {:?} at {} bins",
                    String::from_utf8_lossy(&string),
                    s.max_bins()
                );
            }
        }
    }

    #[test]
    fn the_column_rule_has_the_width_asked() {
        let words = [
            "furiously",
            "quick",
            "deposits",
            "sleep",
            "regular",
            "ideas",
        ];
        let rows: Vec<String> = (0..MIN_ROWS as u64)
            .map(|i| {
                let h = i.wrapping_mul(0x9e37_79b9_7f4a_7c15);
                let pick = |s: u32| words[((h >> s) % 6) as usize];
                format!("{} {}. {}", pick(3), pick(17), pick(31))
            })
            .collect();
        for width in [0, 8, 16] {
            let rule = column_rule("c", &rows, width);
            assert_eq!(rule.bins, width, "width {width}");
            let bins: std::collections::BTreeSet<usize> =
                rule.assignment().unwrap().iter().map(|&(_, b)| b).collect();
            assert_eq!(bins.len(), width, "width {width}");
        }
    }

    #[test]
    fn invalid_schemes_are_rejected() {
        let ok =
            FingerprintConfig::from_assignment("ok", [(feature(FeatureKind::Bigram, "th"), 3)], 8);
        assert!(FingerprintScheme::from_config(ok.clone()).is_ok());
        let rejected = |edit: &dyn Fn(&mut FingerprintConfig)| {
            let mut config = ok.clone();
            edit(&mut config);
            FingerprintScheme::from_config(config).is_err()
        };
        assert!(rejected(&|c| {
            c.bigrams.insert("th".into(), 8);
        }));
        assert!(rejected(&|c| {
            c.bigrams.insert("t-".into(), 0);
        }));
        assert!(rejected(&|c| c.bins = NUM_BINS + 1));
    }

    #[test]
    fn toml_round_trip_preserves_the_rules() {
        let mut rules = FingerprintRules::default();
        for (column, s) in [("wide", dense(NUM_BINS)), ("narrow", dense(20))] {
            rules.columns.insert(column.into(), s.config().clone());
        }
        let restored = FingerprintRules::from_toml_str(&rules.to_toml_string()).unwrap();
        assert_eq!(rules, restored);
    }
}
