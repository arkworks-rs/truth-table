//! Tests for `LengthFilteringCheck`.
//!
//! Fixture: 2 strings, 4 characters; string 0 owns char 0, string 1 owns
//! chars 1-3, so `ind = [0, 1]`, `src = [0, 1, 1, 1]` and the honest length
//! column is `[1, 3]`. The tests vary the threshold `k`, the input
//! activators `ah, ac` and the prover's filtered activators `a'h, a'c`.

use std::sync::Arc;

use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{
    CHAR_FILTERED_LABEL, CHAR_INPUT_LABEL, GadgetNode, STR_FILTERED_LABEL, STR_INPUT_LABEL,
};
use crate::irs::nodes::Node;
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const STR_NV: usize = 1;
const CHAR_NV: usize = 2;

fn build_gadget(k: u64) -> Arc<Node<B>> {
    Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new(k))))
}

fn fixed_src_evals() -> Vec<F> {
    vec![F::from(0u64), F::from(1u64), F::from(1u64), F::from(1u64)]
}
fn fixed_ind_evals() -> Vec<F> {
    vec![F::from(0u64), F::from(1u64)]
}

fn u64_field(name: &str) -> Arc<Field> {
    Arc::new(Field::new(name, DataType::UInt64, false))
}
fn i32_field(name: &str) -> Arc<Field> {
    // Sign-check-compatible integer type for `l`.
    Arc::new(Field::new(name, DataType::Int32, false))
}
fn bool_field(name: &str) -> Arc<Field> {
    // Non-system name so BoolCheck sees it as data.
    Arc::new(Field::new(name, DataType::Boolean, false))
}

/// `l_evals` are the string lengths (non-negative), `k` the threshold;
/// ah/ac are the input activators and a'h/a'c the prover's filtered ones.
#[allow(clippy::too_many_arguments)]
fn run(
    k: u64,
    l_evals: Vec<F>,
    ah_evals: Vec<F>,
    ac_evals: Vec<F>,
    a_h_prime_evals: Vec<F>,
    a_c_prime_evals: Vec<F>,
) -> Result<(), ark_piop::errors::SnarkError> {
    let gadget = build_gadget(k);
    let gadget_id = gadget.id();

    let src_f = u64_field("src");
    let ind_f = u64_field("ind");
    let l_f = i32_field("l");
    let a_h_prime_f = bool_field("a_h_prime");
    let a_c_prime_f = bool_field("a_c_prime");

    let char_input_schema = Schema::new(vec![src_f.as_ref().clone()]);
    let str_input_schema = Schema::new(vec![ind_f.as_ref().clone(), l_f.as_ref().clone()]);
    let char_filt_schema = Schema::new(vec![a_c_prime_f.as_ref().clone()]);
    let str_filt_schema = Schema::new(vec![a_h_prime_f.as_ref().clone()]);

    // The SRS must cover the sign gadget's range polynomial (2^16 for u16
    // chunks).
    let harness = GadgetHarness::<B>::builder(16)
        .with_gadget(gadget)
        .with_table(
            gadget_id,
            CHAR_INPUT_LABEL,
            TableSpec {
                schema: char_input_schema,
                log_size: CHAR_NV,
                cols: vec![(src_f, fixed_src_evals())],
                activator: Some(ac_evals),
            },
        )
        .with_table(
            gadget_id,
            STR_INPUT_LABEL,
            TableSpec {
                schema: str_input_schema,
                log_size: STR_NV,
                cols: vec![(ind_f, fixed_ind_evals()), (l_f, l_evals)],
                activator: Some(ah_evals),
            },
        )
        .with_table(
            gadget_id,
            CHAR_FILTERED_LABEL,
            TableSpec {
                schema: char_filt_schema,
                log_size: CHAR_NV,
                cols: vec![(a_c_prime_f, a_c_prime_evals)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            STR_FILTERED_LABEL,
            TableSpec {
                schema: str_filt_schema,
                log_size: STR_NV,
                cols: vec![(a_h_prime_f, a_h_prime_evals)],
                activator: None,
            },
        )
        .build();

    run_gadget_pipeline(harness)
}

#[test]
fn mixed_filter_keeps_only_long_strings() {
    // k=2: string 0 (length 1) is dropped, string 1 (length 3) is kept.
    let l = vec![F::from(1u64), F::from(3u64)];
    let ah = vec![F::from(1u64), F::from(1u64)];
    let ac = vec![F::from(1u64); 4];
    let a_h_p = vec![F::from(0u64), F::from(1u64)];
    // a'c[c] = a'h[src[c]] with src = [0, 1, 1, 1].
    let a_c_p = vec![F::from(0u64), F::from(1u64), F::from(1u64), F::from(1u64)];
    run(2, l, ah, ac, a_h_p, a_c_p).expect("mixed filter should verify");
}

#[test]
fn threshold_at_exact_length_kept() {
    // k=3: string 1 has l - k = 0, which the non-negative sign check
    // accepts.
    let l = vec![F::from(1u64), F::from(3u64)];
    let ah = vec![F::from(1u64), F::from(1u64)];
    let ac = vec![F::from(1u64); 4];
    let a_h_p = vec![F::from(0u64), F::from(1u64)];
    let a_c_p = vec![F::from(0u64), F::from(1u64), F::from(1u64), F::from(1u64)];
    run(3, l, ah, ac, a_h_p, a_c_p).expect("length == threshold should be kept");
}

#[test]
fn inactive_string_ignored() {
    // String 1 and its chars 1-3 are inactive on input. With k=0 string 0
    // passes and string 1 stays inactive.
    let l = vec![F::from(1u64), F::from(3u64)];
    let ah = vec![F::from(1u64), F::from(0u64)];
    let ac = vec![F::from(1u64), F::from(0u64), F::from(0u64), F::from(0u64)];
    let a_h_p = vec![F::from(1u64), F::from(0u64)];
    let a_c_p = vec![F::from(1u64), F::from(0u64), F::from(0u64), F::from(0u64)];
    run(0, l, ah, ac, a_h_p, a_c_p).expect("inactive string should stay inactive");
}

#[test]
fn keeping_a_short_string_rejected_by_nonneg_sign() {
    // String 0 has length 1 and k=2, so l - k = -1. Claiming a'h[0] = 1
    // puts a negative value on an active row of the non-negative check.
    let l = vec![F::from(1u64), F::from(3u64)];
    let ah = vec![F::from(1u64), F::from(1u64)];
    let ac = vec![F::from(1u64); 4];
    let a_h_p = vec![F::from(1u64), F::from(1u64)]; // wrongly keeps string 0
    let a_c_p = vec![F::from(1u64); 4];
    assert!(
        run(2, l, ah, ac, a_h_p, a_c_p).is_err(),
        "keeping a too-short string must be rejected"
    );
}

#[test]
fn dropping_a_long_string_rejected_by_neg_sign() {
    // String 1 has length 3 and k=2, so l - k = 1. Claiming a'h[1] = 0
    // makes ah·(1-a'h) = 1 on that row, a non-negative value on an active
    // row of the negative check.
    let l = vec![F::from(1u64), F::from(3u64)];
    let ah = vec![F::from(1u64), F::from(1u64)];
    let ac = vec![F::from(1u64); 4];
    let a_h_p = vec![F::from(0u64), F::from(0u64)]; // wrongly drops string 1
    let a_c_p = vec![F::from(0u64); 4];
    assert!(
        run(2, l, ah, ac, a_h_p, a_c_p).is_err(),
        "dropping a long-enough string must be rejected"
    );
}

#[test]
fn wrong_char_activator_rejected_by_ac() {
    // Honest a'h, but a'c does not match a'h[src[c]].
    let l = vec![F::from(1u64), F::from(3u64)];
    let ah = vec![F::from(1u64), F::from(1u64)];
    let ac = vec![F::from(1u64); 4];
    let a_h_p = vec![F::from(0u64), F::from(1u64)];
    // The honest a'c is [0, 1, 1, 1]; chars 0 and 1 are swapped.
    let a_c_p = vec![F::from(1u64), F::from(0u64), F::from(1u64), F::from(1u64)];
    assert!(
        run(2, l, ah, ac, a_h_p, a_c_p).is_err(),
        "mismatched a'c must be rejected by activator consistency"
    );
}

#[test]
fn non_boolean_a_h_prime_rejected() {
    // a'h[0] = 2 is not boolean.
    let l = vec![F::from(1u64), F::from(3u64)];
    let ah = vec![F::from(1u64), F::from(1u64)];
    let ac = vec![F::from(1u64); 4];
    let a_h_p = vec![F::from(2u64), F::from(1u64)]; // non-boolean
    let a_c_p = vec![F::from(1u64); 4];
    assert!(
        run(2, l, ah, ac, a_h_p, a_c_p).is_err(),
        "non-boolean a'h must be rejected by booleanity check"
    );
}

#[test]
fn keeping_inactive_string_rejected_by_containment() {
    // String 1 is inactive (ah[1] = 0). Claiming a'h[1] = 1 makes
    // a'h · (1 - ah) = 1 at row 1.
    let l = vec![F::from(1u64), F::from(3u64)];
    let ah = vec![F::from(1u64), F::from(0u64)];
    let ac = vec![F::from(1u64), F::from(0u64), F::from(0u64), F::from(0u64)];
    let a_h_p = vec![F::from(0u64), F::from(1u64)]; // wrongly keeps inactive string
    let a_c_p = vec![F::from(0u64), F::from(1u64), F::from(1u64), F::from(1u64)];
    assert!(
        run(2, l, ah, ac, a_h_p, a_c_p).is_err(),
        "keeping an input-inactive string must be rejected by containment"
    );
}
