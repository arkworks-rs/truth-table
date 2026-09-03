//! End-to-end test for `MultiCharacterPatternMatching` (paper §6.1 PIOP 6),
//! single-factor t = 1 case.
//!
//! Fixture (matched str/char domain log sizes to keep the sumcheck
//! equalization consistent for now):
//! - `n_str = 4` (log 2), `n_char = 4` (log 2).
//! - Two real strings, both `"ab"` of length 2; two inactive padding strings.
//! - Pattern factor: `"ab"` (k = 2), Mode::Prefix.
//! - Both real strings match; padding strings drop out via activators.

use std::sync::Arc;

use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{
    CHAR_INPUT_LABEL, GadgetNode, LENGTH_FILTERED_CHAR_LABEL, LENGTH_FILTERED_STR_LABEL, Mode,
    NEW_CHAR_LABEL, NEW_STR_LABEL, STR_INPUT_LABEL, factor_label,
};
use crate::irs::nodes::Node;
use crate::irs::nodes::utils::nodup;
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const STR_NV: usize = 2; // n_str = 4
const CHAR_NV: usize = 2; // n_char = 4

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
fn u64_field(name: &str) -> Arc<Field> {
    Arc::new(Field::new(name, DataType::UInt64, false))
}
fn i32_field(name: &str) -> Arc<Field> {
    Arc::new(Field::new(name, DataType::Int32, false))
}
fn bool_field(name: &str) -> Arc<Field> {
    Arc::new(Field::new(name, DataType::Boolean, false))
}

fn shift_left(xs: &[F], shift: usize) -> Vec<F> {
    let n = xs.len();
    (0..n).map(|i| xs[(i + (shift % n)) % n]).collect()
}

fn pattern_ab() -> Vec<F> {
    u(&[b'a' as u64, b'b' as u64])
}

#[test]
fn honest_prefix_single_factor_verifies() {
    // BezoutBased nodup_mark: the test harness bypasses
    // `initialize_gadget_plans`, so `SortBased` would panic on the
    // missing plan-time LEX_SORTED_LABEL hint.
    let gadget = Arc::new(Node::Gadget(Arc::new(
        GadgetNode::<B>::new_with_nodup_mode(
            vec![(pattern_ab(), Mode::Prefix)],
            nodup::Mode::BezoutBased,
        ),
    )));
    let gadget_id = gadget.id();

    // Char-level fixed columns.
    let char_col = u(&[b'a' as u64, b'b' as u64, b'a' as u64, b'b' as u64]);
    let orig_ind = u(&[0, 0, 1, 1]);
    let int_ind = u(&[0, 1, 0, 1]);
    let bnd = u(&[1, 0, 1, 0]);
    let char_act_old = u(&[1, 1, 1, 1]);
    // String-level fixed columns.
    let ind = u(&[0, 1, 2, 3]);
    let l = i32_vals(&[2, 2, 0, 0]);
    let a_old = u(&[1, 1, 0, 0]);

    // Length-filter outputs (k=2, both real strings kept).
    let char_act_old_prime = u(&[1, 1, 1, 1]);
    let a_old_prime = u(&[1, 1, 0, 0]);

    // Post-match activators.
    let char_act_new = u(&[1, 1, 1, 1]);
    let a_new = u(&[1, 1, 0, 0]);

    // Rotated char columns for FactorPlacement.
    let char_0 = char_col.clone();
    let char_1 = shift_left(&char_col, 1);

    // Factor Placement witnesses.
    let occurs = u(&[1, 0, 1, 0]);
    let match_str = u(&[1, 1, 0, 0]);
    let mark = u(&[1, 0, 1, 0]);
    let start = u(&[0, 0, 0, 0]);
    let match_broadcast = u(&[1, 1, 1, 1]);
    // Step 4(e) witnesses (leftmost check). Both strings mark at int_ind=0
    // (their leftmost occurrence), so start=0 → start_broadcast=0 → no
    // char position is "before start" → leftmost_mask=0 everywhere.
    let start_broadcast = u(&[0, 0, 0, 0]);
    let leftmost_mask = u(&[0, 0, 0, 0]);

    // Field refs.
    let char_f = u64_field("char");
    let orig_ind_f = u64_field("orig_ind");
    let int_ind_f = u64_field("int_ind");
    let bnd_f = u64_field("bnd");
    let ind_f = u64_field("ind");
    let l_f = i32_field("l");
    let flag = bool_field("data");
    let char0_f = u64_field("char_0");
    let char1_f = u64_field("char_1");
    let match_prime_f = u64_field("match_prime");
    let start_f = u64_field("start");
    let start_bcast_f = u64_field("start_broadcast");
    let mask_f = u64_field("leftmost_mask");

    let char_input_schema = Schema::new(vec![
        char_f.as_ref().clone(),
        orig_ind_f.as_ref().clone(),
        int_ind_f.as_ref().clone(),
        bnd_f.as_ref().clone(),
    ]);
    let str_input_schema = Schema::new(vec![ind_f.as_ref().clone(), l_f.as_ref().clone()]);
    let flag_schema = Schema::new(vec![flag.as_ref().clone()]);
    let rot_schema = Schema::new(vec![char0_f.as_ref().clone(), char1_f.as_ref().clone()]);

    let harness = GadgetHarness::<B>::builder(16)
        .with_gadget(gadget)
        .with_table(
            gadget_id,
            CHAR_INPUT_LABEL,
            TableSpec {
                schema: char_input_schema,
                log_size: CHAR_NV,
                cols: vec![
                    (char_f, char_col),
                    (orig_ind_f, orig_ind),
                    (int_ind_f, int_ind),
                    (bnd_f, bnd),
                ],
                activator: Some(char_act_old),
            },
        )
        .with_table(
            gadget_id,
            STR_INPUT_LABEL,
            TableSpec {
                schema: str_input_schema,
                log_size: STR_NV,
                cols: vec![(ind_f, ind), (l_f, l)],
                activator: Some(a_old),
            },
        )
        .with_table(
            gadget_id,
            LENGTH_FILTERED_CHAR_LABEL,
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), char_act_old_prime)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            LENGTH_FILTERED_STR_LABEL,
            TableSpec {
                schema: flag_schema.clone(),
                log_size: STR_NV,
                cols: vec![(flag.clone(), a_old_prime)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            NEW_CHAR_LABEL,
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), char_act_new)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            NEW_STR_LABEL,
            TableSpec {
                schema: flag_schema.clone(),
                log_size: STR_NV,
                cols: vec![(flag.clone(), a_new)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "rotated_char"),
            TableSpec {
                schema: rot_schema,
                log_size: CHAR_NV,
                cols: vec![(char0_f, char_0), (char1_f, char_1)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "occurs"),
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), occurs)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "match"),
            TableSpec {
                schema: flag_schema.clone(),
                log_size: STR_NV,
                cols: vec![(flag.clone(), match_str)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "mark"),
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), mark)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "start"),
            TableSpec {
                schema: Schema::new(vec![start_f.as_ref().clone()]),
                log_size: STR_NV,
                cols: vec![(start_f, start)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "match_broadcast"),
            TableSpec {
                schema: Schema::new(vec![match_prime_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(match_prime_f, match_broadcast)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "start_broadcast"),
            TableSpec {
                schema: Schema::new(vec![start_bcast_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(start_bcast_f, start_broadcast)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "leftmost_mask"),
            TableSpec {
                schema: Schema::new(vec![mask_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(mask_f, leftmost_mask)],
                activator: None,
            },
        )
        .build();

    run_gadget_pipeline(harness).expect("honest PIOP 6 (t=1, prefix) should verify");
}

// -----------------------------------------------------------------------------
// t = 2: two infix factors — pattern `%ab%cd%` against `"abcd"` | `"abcd"`.
// End-to-end MCPM: DPUC + LFC (threshold = 4) + SweepFactors + verdict.
// -----------------------------------------------------------------------------

#[test]
fn honest_two_infix_verifies() {
    const STR_NV: usize = 3; // 8 slots
    const CHAR_NV: usize = 3; // 8 slots

    let factors = vec![
        (pattern_ab(), Mode::Infix),
        (u(&[b'c' as u64, b'd' as u64]), Mode::Infix),
    ];
    let gadget = Arc::new(Node::Gadget(Arc::new(
        GadgetNode::<B>::new_with_nodup_mode(factors, nodup::Mode::BezoutBased),
    )));
    let gadget_id = gadget.id();

    // Char/string layout: two "abcd" strings packed contiguously.
    let char_col = u(&[
        b'a' as u64,
        b'b' as u64,
        b'c' as u64,
        b'd' as u64,
        b'a' as u64,
        b'b' as u64,
        b'c' as u64,
        b'd' as u64,
    ]);
    let orig_ind = u(&[0, 0, 0, 0, 1, 1, 1, 1]);
    let int_ind = u(&[0, 1, 2, 3, 0, 1, 2, 3]);
    let bnd = u(&[1, 0, 0, 0, 1, 0, 0, 0]);
    let char_act_old = u(&[1, 1, 1, 1, 1, 1, 1, 1]);
    let ind = u(&[0, 1, 2, 3, 4, 5, 6, 7]);
    // Both real strings length 4 (= threshold), rest inactive.
    let l = i32_vals(&[4, 4, 0, 0, 0, 0, 0, 0]);
    let a_old = u(&[1, 1, 0, 0, 0, 0, 0, 0]);

    // Length-filter output: both strings pass (l ≥ 4).
    let char_act_old_prime = u(&[1, 1, 1, 1, 1, 1, 1, 1]);
    let a_old_prime = u(&[1, 1, 0, 0, 0, 0, 0, 0]);

    // Post-match activators: both strings satisfy `%ab%cd%`.
    let char_act_new = u(&[1, 1, 1, 1, 1, 1, 1, 1]);
    let a_new = u(&[1, 1, 0, 0, 0, 0, 0, 0]);

    // Rotated char cols (shared shape across both factors, ℓ = 2 each).
    let char_0 = char_col.clone();
    let char_1 = shift_left(&char_col, 1);
    let bnd_1 = shift_left(&bnd, 1);

    // ---- Factor 0: "ab" ----
    let occurs_0 = u(&[1, 0, 0, 0, 1, 0, 0, 0]);
    let match_str_0 = u(&[1, 1, 0, 0, 0, 0, 0, 0]);
    let mark_0 = u(&[1, 0, 0, 0, 1, 0, 0, 0]);
    let start_0 = u(&[0, 0, 0, 0, 0, 0, 0, 0]);
    let match_broadcast_0 = u(&[1, 1, 1, 1, 1, 1, 1, 1]);
    let start_broadcast_0 = u(&[0, 0, 0, 0, 0, 0, 0, 0]);
    let leftmost_mask_0 = u(&[0, 0, 0, 0, 0, 0, 0, 0]);
    let past_0 = u(&[0, 1, 1, 1, 0, 1, 1, 1]);

    // ---- Factor 1: "cd" ----
    let occurs_1 = u(&[0, 0, 1, 0, 0, 0, 1, 0]);
    let match_str_1 = u(&[1, 1, 0, 0, 0, 0, 0, 0]);
    let mark_1 = u(&[0, 0, 1, 0, 0, 0, 1, 0]);
    let start_1 = u(&[2, 2, 0, 0, 0, 0, 0, 0]);
    let match_broadcast_1 = u(&[1, 1, 1, 1, 1, 1, 1, 1]);
    let start_broadcast_1 = u(&[2, 2, 2, 2, 2, 2, 2, 2]);
    let leftmost_mask_1 = u(&[1, 1, 0, 0, 1, 1, 0, 0]);

    // ---- Field refs and schemas ----
    let char_f = u64_field("char");
    let orig_ind_f = u64_field("orig_ind");
    let int_ind_f = u64_field("int_ind");
    let bnd_f = u64_field("bnd");
    let ind_f = u64_field("ind");
    let l_f = i32_field("l");
    let flag = bool_field("data");
    let char0_f = u64_field("char_0");
    let char1_f = u64_field("char_1");
    let bnd_1_f = u64_field("bnd_1");

    let char_input_schema = Schema::new(vec![
        char_f.as_ref().clone(),
        orig_ind_f.as_ref().clone(),
        int_ind_f.as_ref().clone(),
        bnd_f.as_ref().clone(),
    ]);
    let str_input_schema = Schema::new(vec![ind_f.as_ref().clone(), l_f.as_ref().clone()]);
    let flag_schema = Schema::new(vec![flag.as_ref().clone()]);
    let rot_char_schema = Schema::new(vec![char0_f.as_ref().clone(), char1_f.as_ref().clone()]);

    let start_f = u64_field("start");
    let match_prime_f = u64_field("match_prime");
    let start_bcast_f = u64_field("start_broadcast");
    let mask_f = u64_field("leftmost_mask");
    let past_f = u64_field("past");

    let harness = GadgetHarness::<B>::builder(16)
        .with_gadget(gadget)
        .with_table(
            gadget_id,
            CHAR_INPUT_LABEL,
            TableSpec {
                schema: char_input_schema,
                log_size: CHAR_NV,
                cols: vec![
                    (char_f, char_col),
                    (orig_ind_f, orig_ind),
                    (int_ind_f, int_ind),
                    (bnd_f, bnd),
                ],
                activator: Some(char_act_old),
            },
        )
        .with_table(
            gadget_id,
            STR_INPUT_LABEL,
            TableSpec {
                schema: str_input_schema,
                log_size: STR_NV,
                cols: vec![(ind_f, ind), (l_f, l)],
                activator: Some(a_old),
            },
        )
        .with_table(
            gadget_id,
            LENGTH_FILTERED_CHAR_LABEL,
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), char_act_old_prime)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            LENGTH_FILTERED_STR_LABEL,
            TableSpec {
                schema: flag_schema.clone(),
                log_size: STR_NV,
                cols: vec![(flag.clone(), a_old_prime)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            NEW_CHAR_LABEL,
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), char_act_new)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            NEW_STR_LABEL,
            TableSpec {
                schema: flag_schema.clone(),
                log_size: STR_NV,
                cols: vec![(flag.clone(), a_new)],
                activator: None,
            },
        )
        // --- Factor 0 ---
        .with_table(
            gadget_id,
            &factor_label(0, "rotated_char"),
            TableSpec {
                schema: rot_char_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![
                    (char0_f.clone(), char_0.clone()),
                    (char1_f.clone(), char_1.clone()),
                ],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "occurs"),
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), occurs_0)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "match"),
            TableSpec {
                schema: flag_schema.clone(),
                log_size: STR_NV,
                cols: vec![(flag.clone(), match_str_0)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "mark"),
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), mark_0)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "start"),
            TableSpec {
                schema: Schema::new(vec![start_f.as_ref().clone()]),
                log_size: STR_NV,
                cols: vec![(start_f.clone(), start_0)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "match_broadcast"),
            TableSpec {
                schema: Schema::new(vec![match_prime_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(match_prime_f.clone(), match_broadcast_0)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "start_broadcast"),
            TableSpec {
                schema: Schema::new(vec![start_bcast_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(start_bcast_f.clone(), start_broadcast_0)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "leftmost_mask"),
            TableSpec {
                schema: Schema::new(vec![mask_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(mask_f.clone(), leftmost_mask_0)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "rotated_bnd"),
            TableSpec {
                schema: Schema::new(vec![bnd_1_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(bnd_1_f.clone(), bnd_1.clone())],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(0, "past"),
            TableSpec {
                schema: Schema::new(vec![past_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(past_f.clone(), past_0)],
                activator: None,
            },
        )
        // --- Factor 1 ---
        .with_table(
            gadget_id,
            &factor_label(1, "rotated_char"),
            TableSpec {
                schema: rot_char_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![
                    (char0_f.clone(), char_0.clone()),
                    (char1_f.clone(), char_1.clone()),
                ],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(1, "occurs"),
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), occurs_1)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(1, "match"),
            TableSpec {
                schema: flag_schema.clone(),
                log_size: STR_NV,
                cols: vec![(flag.clone(), match_str_1)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(1, "mark"),
            TableSpec {
                schema: flag_schema.clone(),
                log_size: CHAR_NV,
                cols: vec![(flag.clone(), mark_1)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(1, "start"),
            TableSpec {
                schema: Schema::new(vec![start_f.as_ref().clone()]),
                log_size: STR_NV,
                cols: vec![(start_f.clone(), start_1)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(1, "match_broadcast"),
            TableSpec {
                schema: Schema::new(vec![match_prime_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(match_prime_f.clone(), match_broadcast_1)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(1, "start_broadcast"),
            TableSpec {
                schema: Schema::new(vec![start_bcast_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(start_bcast_f.clone(), start_broadcast_1)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(1, "leftmost_mask"),
            TableSpec {
                schema: Schema::new(vec![mask_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(mask_f.clone(), leftmost_mask_1)],
                activator: None,
            },
        )
        .with_table(
            gadget_id,
            &factor_label(1, "rotated_bnd"),
            TableSpec {
                schema: Schema::new(vec![bnd_1_f.as_ref().clone()]),
                log_size: CHAR_NV,
                cols: vec![(bnd_1_f.clone(), bnd_1.clone())],
                activator: None,
            },
        )
        .build();

    run_gadget_pipeline(harness).expect("honest PIOP 6 (t=2, two infix) should verify");
}
