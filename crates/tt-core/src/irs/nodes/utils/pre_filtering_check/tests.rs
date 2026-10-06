//! Tests for `PreFilteringCheck` composite gadget node (paper PIOP 8),
//! under a local one-bin-per-character fixture so the gadget's arithmetic
//! is exercised independently of whatever scheme the system deploys.
//!
//! Setup mirrors the length-filtering fixture: 2 strings, 4 characters;
//! string 0 owns char 0, string 1 owns chars 1-3. `ind = [0, 1]`,
//! `orig-ind = [0, 1, 1, 1]`, lengths `l = [1, 3]`. The pattern is the
//! paper's `%dar%`: strings whose fingerprint misses one of `d`, `a`,
//! `r` must be dropped. They are bins 10, 13 and 27, one committed boolean
//! column each.

use std::sync::Arc;

use arithmetic::fingerprint::{
    self, Feature, FeatureKind, FingerprintConfig, FingerprintScheme, FpMask, NUM_BINS,
};
use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{
    CHAR_FILTERED_LABEL, CHAR_INPUT_LABEL, GadgetNode, STR_FILTERED_LABEL, STR_INDEX_LABEL,
    STR_INPUT_LABEL,
};
use crate::irs::nodes::Node;
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const STR_NV: usize = 1;
const CHAR_NV: usize = 2;

/// One bin per alphanumeric byte: digits 0–9, lowercase 10–35, uppercase
/// 36–61.
fn scheme() -> FingerprintScheme {
    let assignment = (0u8..=127).filter_map(|byte| {
        let bin = match byte {
            b'0'..=b'9' => (byte - b'0') as usize,
            b'a'..=b'z' => 10 + (byte - b'a') as usize,
            b'A'..=b'Z' => 36 + (byte - b'A') as usize,
            _ => return None,
        };
        let feature = Feature::parse(FeatureKind::Char, &(byte as char).to_string()).ok()?;
        Some((feature, bin))
    });
    FingerprintScheme::from_config(FingerprintConfig::from_assignment(
        "test-per-char",
        assignment,
        NUM_BINS,
    ))
    .expect("fixture scheme is valid")
}

/// `φ` of `%dar%` restricted to its bins below `bins`: a subset of the
/// pattern's bins, as the prover may choose.
fn phi(bins: usize) -> FpMask {
    let mut phi = scheme().pattern_fingerprint([b"dar".as_slice()]);
    for bin in bins..NUM_BINS {
        phi[bin / 64] &= !(1 << (bin % 64));
    }
    phi
}

fn f(vals: &[u64]) -> Vec<F> {
    vals.iter().map(|&v| F::from(v)).collect()
}

fn u64_field(name: &str) -> Arc<Field> {
    Arc::new(Field::new(name, DataType::UInt64, false))
}
fn bool_field(name: &str) -> Arc<Field> {
    Arc::new(Field::new(name, DataType::Boolean, false))
}

/// One boolean column per bin `phi` tests, over the two strings.
fn tested_bin_cols(prefix: &str, phi: &FpMask, vals: &[FpMask; 2]) -> TableCols {
    fingerprint::touched_limbs(phi)
        .into_iter()
        .map(|j| {
            let col = vals
                .iter()
                .map(|v| F::from(u64::from(fingerprint::limb(v, j))))
                .collect();
            (u64_field(&format!("{prefix}{j}")), col)
        })
        .collect()
}

type TableCols = Vec<(Arc<Field>, Vec<F>)>;

fn schema_of(cols: &TableCols) -> Schema {
    Schema::new(
        cols.iter()
            .map(|(field, _)| field.as_ref().clone())
            .collect::<Vec<_>>(),
    )
}

/// The witness a (possibly dishonest) prover supplies.
struct Witness {
    /// Committed fingerprints of the two strings.
    fp: [FpMask; 2],
    a: [u64; 2],
    a_prime: [u64; 2],
    /// `char-act'`; full mode only.
    char_act_prime: Vec<F>,
}

/// char-act = a broadcast over orig-ind = [0, 1, 1, 1].
fn char_of(v: [u64; 2]) -> Vec<F> {
    f(&[v[0], v[1], v[1], v[1]])
}

fn honest(strings: [&[u8]; 2], a: [u64; 2], keep: [u64; 2]) -> Witness {
    let s = scheme();
    let fp = [s.fingerprint(strings[0]), s.fingerprint(strings[1])];
    Witness {
        fp,
        a,
        a_prime: keep,
        char_act_prime: char_of(keep),
    }
}

fn run(w: Witness, bins: usize, full_mode: bool) -> Result<(), ark_piop::errors::SnarkError> {
    run_phi(w, phi(bins), full_mode)
}

fn run_phi(w: Witness, phi: FpMask, full_mode: bool) -> Result<(), ark_piop::errors::SnarkError> {
    let gadget = if full_mode {
        GadgetNode::<B>::new(phi)
    } else {
        GadgetNode::<B>::new_row_only(phi)
    };
    let gadget: Arc<Node<B>> = Arc::new(Node::Gadget(Arc::new(gadget)));
    let gadget_id = gadget.id();

    let fp_cols = tested_bin_cols("fp", &phi, &w.fp);
    let a_prime_f = bool_field("a_prime");

    let mut builder = GadgetHarness::<B>::builder(CHAR_NV)
        .with_gadget(gadget)
        .with_table(
            gadget_id,
            STR_INPUT_LABEL,
            TableSpec {
                schema: schema_of(&fp_cols),
                log_size: STR_NV,
                cols: fp_cols,
                activator: Some(f(&w.a)),
            },
        )
        .with_table(
            gadget_id,
            STR_FILTERED_LABEL,
            TableSpec {
                schema: Schema::new(vec![a_prime_f.as_ref().clone()]),
                log_size: STR_NV,
                cols: vec![(a_prime_f, f(&w.a_prime))],
                activator: None,
            },
        );
    if full_mode {
        let orig_ind_f = u64_field("orig_ind");
        let index_cols = vec![(u64_field("ind"), f(&[0, 1])), (u64_field("l"), f(&[1, 3]))];
        let char_act_prime_f = bool_field("char_act_prime");
        builder = builder
            .with_table(
                gadget_id,
                CHAR_INPUT_LABEL,
                TableSpec {
                    schema: Schema::new(vec![orig_ind_f.as_ref().clone()]),
                    log_size: CHAR_NV,
                    cols: vec![(orig_ind_f, f(&[0, 1, 1, 1]))],
                    activator: Some(char_of(w.a)),
                },
            )
            .with_table(
                gadget_id,
                STR_INDEX_LABEL,
                TableSpec {
                    schema: schema_of(&index_cols),
                    log_size: STR_NV,
                    cols: index_cols,
                    activator: None,
                },
            )
            .with_table(
                gadget_id,
                CHAR_FILTERED_LABEL,
                TableSpec {
                    schema: Schema::new(vec![char_act_prime_f.as_ref().clone()]),
                    log_size: CHAR_NV,
                    cols: vec![(char_act_prime_f, w.char_act_prime)],
                    activator: None,
                },
            );
    }
    run_gadget_pipeline(builder.build())
}

#[test]
fn every_tested_bin_is_its_own_column() {
    assert_eq!(fingerprint::touched_limbs(&phi(NUM_BINS)), vec![10, 13, 27]);
    assert_eq!(fingerprint::touched_limbs(&phi(16)), vec![10, 13]);
}

// ---- Positive cases ----

#[test]
fn superset_kept_and_true_negative_dropped() {
    // "darling" ⊇ {d,a,r} → kept; "lemon" misses d/a/r bins → dropped.
    for full_mode in [true, false] {
        run(
            honest([b"darling", b"lemon"], [1, 1], [1, 0]),
            NUM_BINS,
            full_mode,
        )
        .expect("honest pre-filtering should verify");
    }
}

#[test]
fn false_positive_of_the_scheme_survives_the_filter() {
    // "radish" contains d, a, r (so its per-char fingerprint passes)
    // without containing "dar" — the pre-filter keeps it; the exact
    // protocol downstream would remove it. The PIOP must accept the keep.
    run(honest([b"radish", b"dab"], [1, 1], [1, 0]), NUM_BINS, true)
        .expect("fingerprint false positives are legitimately kept");
}

#[test]
fn input_inactive_string_stays_inactive() {
    run(honest([b"darling", b"zzz"], [1, 0], [1, 0]), NUM_BINS, true)
        .expect("input-inactive string should stay inactive");
}

#[test]
fn a_subset_of_the_pattern_bins_keeps_what_it_allows() {
    // Testing only the bins below 16, `a` and `d`: "dab" passes, "lemon" fails.
    run(honest([b"dab", b"lemon"], [1, 1], [1, 0]), 16, false)
        .expect("honest pre-filtering on a subset should verify");
    let result = run(honest([b"dab", b"lemon"], [1, 1], [0, 0]), 16, false);
    assert!(result.is_err(), "dropping a string passing the subset φ");
}

#[test]
fn many_tested_bins_verify() {
    // The subset test is one product over the tested bins, of degree
    // |Q| + 1; 40 bins exercise a high-degree zerocheck.
    const WIDE: usize = 40;
    let bytes: Vec<u8> = (b'a'..=b'z')
        .chain(b'0'..=b'9')
        .chain(b'A'..=b'Z')
        .take(WIDE)
        .collect();
    let wide = FingerprintScheme::from_config(FingerprintConfig::from_assignment(
        "one-char-per-limb",
        bytes.iter().enumerate().map(|(i, &byte)| {
            let key = (byte as char).to_string();
            let feature = Feature::parse(FeatureKind::Char, &key).expect("alnum char");
            (feature, i * fingerprint::LIMB_BITS)
        }),
        WIDE * fingerprint::LIMB_BITS,
    ))
    .expect("wide fixture scheme is valid");

    let phi = wide.pattern_fingerprint([bytes.as_slice()]);
    assert_eq!(fingerprint::touched_limbs(&phi).len(), WIDE);

    // String 0 has every character; string 1 is missing the last one.
    let fp = [
        wide.fingerprint(&bytes),
        wide.fingerprint(&bytes[..WIDE - 1]),
    ];
    let witness = |keep: [u64; 2]| Witness {
        fp,
        a: [1, 1],
        a_prime: keep,
        char_act_prime: char_of(keep),
    };

    run_phi(witness([1, 0]), phi, false).expect("honest wide pre-filtering should verify");
    assert!(
        run_phi(witness([1, 1]), phi, false).is_err(),
        "keeping the string missing a needed bin must be rejected"
    );
}

// ---- Adversarial cases ----

#[test]
fn keeping_a_failing_string_rejected() {
    // "lemon" fails the subset test but the prover keeps it: a' = 1 where
    // a · ∏ fp_b = 0.
    for full_mode in [true, false] {
        let result = run(
            honest([b"darling", b"lemon"], [1, 1], [1, 1]),
            NUM_BINS,
            full_mode,
        );
        assert!(result.is_err(), "keeping a failing string must be rejected");
    }
}

#[test]
fn dropping_a_passing_string_rejected() {
    // "darling" passes but the prover drops it: a' = 0 where
    // a · ∏ fp_b = 1.
    for full_mode in [true, false] {
        let mut w = honest([b"darling", b"lemon"], [1, 1], [1, 0]);
        w.a_prime = [0, 0];
        w.char_act_prime = char_of([0, 0]);
        let result = run(w, NUM_BINS, full_mode);
        assert!(
            result.is_err(),
            "dropping a passing string must be rejected"
        );
    }
}

#[test]
fn a_non_boolean_filtered_activator_rejected() {
    // a' must equal the 0/1 product; a' = 2 on a passing row is rejected.
    let mut w = honest([b"darling", b"lemon"], [1, 1], [1, 0]);
    w.a_prime = [2, 0];
    let result = run(w, NUM_BINS, false);
    assert!(result.is_err(), "a non-boolean a' must be rejected");
}

#[test]
fn reviving_an_inactive_string_rejected() {
    // a[1] = 0 but a'[1] = 1, although "darts" sets every bin: the
    // product carries a, so a' = 1 where a · ∏ fp_b = 0.
    let mut w = honest([b"darling", b"darts"], [1, 0], [1, 1]);
    w.char_act_prime = char_of([1, 1]);
    let result = run(w, NUM_BINS, false);
    assert!(
        result.is_err(),
        "reviving an inactive string must be rejected"
    );
}

#[test]
fn mismatched_char_activator_rejected() {
    // Honest a' but char-act' doesn't match a'[orig-ind[c]]: the
    // Data-Preserving Update Check rejects.
    let mut w = honest([b"darling", b"lemon"], [1, 1], [1, 0]);
    w.char_act_prime = f(&[0, 1, 0, 0]);
    let result = run(w, NUM_BINS, true);
    assert!(result.is_err(), "mismatched char-act' must be rejected");
}
