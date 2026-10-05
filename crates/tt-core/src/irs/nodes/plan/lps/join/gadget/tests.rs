//! Tests for the PK-FK join gadget (the PKFKJoin lookup) against a dishonest
//! prover.
//!
//! The harness commits each payload table and proves the gadget directly, so
//! a join output whose PK-side columns were not looked up from the PK table
//! still produces a proof. The verifier must accept exactly the outputs whose
//! active rows carry the PK row that their FK key names.

use std::sync::Arc;

use ark_ff::{One, Zero};
use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion_expr::{JoinType, LogicalPlan, logical_plan::table_scan};

use super::{GadgetNode, JoinMode, LEFT_LABEL, OUTPUT_LABEL, RIGHT_LABEL};
use crate::irs::nodes::Node;
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

/// A table as `(column name, values)` per column plus which slots are active.
struct Table {
    cols: Vec<(&'static str, Vec<u64>)>,
    active: Vec<bool>,
}

impl Table {
    fn new(cols: &[(&'static str, &[u64])], active: &[bool]) -> Self {
        Self {
            cols: cols
                .iter()
                .map(|(name, values)| (*name, values.to_vec()))
                .collect(),
            active: active.to_vec(),
        }
    }
}

fn schema(cols: &[&str]) -> Schema {
    Schema::new(
        cols.iter()
            .map(|name| Field::new(*name, DataType::UInt64, false))
            .collect::<Vec<_>>(),
    )
}

fn spec(table: &Table) -> TableSpec<F> {
    let schema = schema(&table.cols.iter().map(|(name, _)| *name).collect::<Vec<_>>());
    TableSpec {
        log_size: table.active.len().trailing_zeros() as usize,
        cols: schema
            .fields()
            .iter()
            .zip(&table.cols)
            .map(|(field, (_, values))| {
                (field.clone(), values.iter().map(|&v| F::from(v)).collect())
            })
            .collect(),
        schema,
        activator: Some(
            table
                .active
                .iter()
                .map(|&on| if on { F::one() } else { F::zero() })
                .collect(),
        ),
    }
}

/// `f JOIN p ON f.f_key = p.p_key`, with `f` on the left when `fk_left`.
fn join_gadget(fk_left: bool) -> GadgetNode<B> {
    let f = table_scan(Some("f"), &schema(&["f_key", "f_val"]), None).unwrap();
    let p = table_scan(Some("p"), &schema(&["p_key", "p_val"]), None).unwrap();
    let (plan, mode) = if fk_left {
        let plan = f
            .join(
                p.build().unwrap(),
                JoinType::Inner,
                (vec!["f_key"], vec!["p_key"]),
                None,
            )
            .unwrap();
        (plan, JoinMode::MANY_TO_ONE)
    } else {
        let plan = p
            .join(
                f.build().unwrap(),
                JoinType::Inner,
                (vec!["p_key"], vec!["f_key"]),
                None,
            )
            .unwrap();
        (plan, JoinMode::ONE_TO_MANY)
    };
    let LogicalPlan::Join(join) = plan.build().unwrap() else {
        unreachable!("the builder produced a join");
    };
    GadgetNode::new(join, mode)
}

fn run_with(
    fk_left: bool,
    fk: Table,
    pk: Table,
    output: Table,
) -> Result<(), ark_piop::errors::SnarkError> {
    let gadget: Arc<Node<B>> = Arc::new(Node::Gadget(Arc::new(join_gadget(fk_left))));
    let id = gadget.id();
    let (fk_label, pk_label) = if fk_left {
        (LEFT_LABEL, RIGHT_LABEL)
    } else {
        (RIGHT_LABEL, LEFT_LABEL)
    };
    let harness = GadgetHarness::<B>::builder(8)
        .with_gadget(gadget)
        .with_table(id, fk_label, spec(&fk))
        .with_table(id, pk_label, spec(&pk))
        .with_table(id, OUTPUT_LABEL, spec(&output))
        .build();
    run_gadget_pipeline(harness)
}

fn run(output: Table) -> Result<(), ark_piop::errors::SnarkError> {
    run_with(true, fk(), pk(), output)
}

const FK_KEYS: &[u64] = &[1, 2, 1, 9];
const FK_VALS: &[u64] = &[5, 6, 7, 8];
const ACTIVE: &[bool] = &[true, true, true, false];

/// Three active FK rows naming keys 1, 2, 1; the inactive slot holds a key
/// the PK table does not have.
fn fk() -> Table {
    Table::new(&[("f_key", FK_KEYS), ("f_val", FK_VALS)], ACTIVE)
}

/// Keys 1, 2, 3 are active; key 7 sits in an inactive slot.
fn pk() -> Table {
    Table::new(
        &[("p_key", &[1, 2, 3, 7]), ("p_val", &[10, 20, 30, 70])],
        ACTIVE,
    )
}

/// The join output over the FK rows of [`fk`] with the given PK-side columns.
fn output(p_key: &[u64], p_val: &[u64]) -> Table {
    Table::new(
        &[
            ("f_key", FK_KEYS),
            ("f_val", FK_VALS),
            ("p_key", p_key),
            ("p_val", p_val),
        ],
        ACTIVE,
    )
}

#[test]
fn the_looked_up_pk_rows_verify() {
    run(output(&[1, 2, 1, 0], &[10, 20, 10, 0])).expect("the honest join output must verify");
}

#[test]
fn the_fk_side_may_be_the_right_input() {
    run_with(false, fk(), pk(), output(&[1, 2, 1, 0], &[10, 20, 10, 0]))
        .expect("the honest join output must verify with the FK side on the right");
}

#[test]
fn junk_in_an_inactive_fk_slot_is_ignored() {
    run(output(&[1, 2, 1, 123], &[10, 20, 10, 456])).expect("inactive rows are not looked up");
}

#[test]
fn a_changed_pk_value_is_rejected() {
    assert!(run(output(&[1, 2, 1, 0], &[10, 21, 10, 0])).is_err());
}

#[test]
fn another_pk_row_is_rejected() {
    // (2, 20) is a real PK row, but the FK row names key 1.
    assert!(run(output(&[2, 2, 1, 0], &[20, 20, 10, 0])).is_err());
}

#[test]
fn values_from_two_pk_rows_are_rejected() {
    // Key 1 with key 2's value: each column alone appears in the PK table.
    assert!(run(output(&[1, 2, 1, 0], &[20, 20, 10, 0])).is_err());
}

#[test]
fn an_inactive_pk_row_is_rejected() {
    // Key 7 exists only in the PK table's inactive slot.
    let fk = Table::new(&[("f_key", &[1, 2, 7, 9]), ("f_val", FK_VALS)], ACTIVE);
    let output = Table::new(
        &[
            ("f_key", &[1, 2, 7, 9]),
            ("f_val", FK_VALS),
            ("p_key", &[1, 2, 7, 0]),
            ("p_val", &[10, 20, 70, 0]),
        ],
        ACTIVE,
    );
    assert!(run_with(true, fk, pk(), output).is_err());
}
