//! Tests for the `ResultCheck` gadget against a dishonest prover.
//!
//! The harness proves the gadget directly, with no honest-prover check, so a
//! claimed result that differs from the proven output still produces a proof.
//! The verifier must accept exactly the claims whose active rows are the same
//! multiset as the output's, regardless of row order, padding and domain
//! size, and reject every other one.

use std::sync::Arc;

use ark_ff::{One, Zero};
use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{GadgetNode, INPUT_LABEL, OUTPUT_LABEL};
use crate::irs::nodes::Node;
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

/// A table as `(column name, values)` per column plus which slots are active.
/// Every column and the activator hold `2^nv` values.
struct Table<'a> {
    nv: usize,
    cols: &'a [(&'a str, &'a [u64])],
    active: &'a [bool],
}

fn spec(table: &Table) -> TableSpec<F> {
    let fields: Vec<_> = table
        .cols
        .iter()
        .map(|(name, _)| Arc::new(Field::new(*name, DataType::UInt64, false)))
        .collect();
    TableSpec {
        schema: Schema::new(
            fields
                .iter()
                .map(|f| f.as_ref().clone())
                .collect::<Vec<_>>(),
        ),
        log_size: table.nv,
        cols: fields
            .iter()
            .zip(table.cols)
            .map(|(field, (_, values))| {
                (field.clone(), values.iter().map(|&v| F::from(v)).collect())
            })
            .collect(),
        activator: Some(
            table
                .active
                .iter()
                .map(|&on| if on { F::one() } else { F::zero() })
                .collect(),
        ),
    }
}

fn run(output: Table, claimed: Table) -> Result<(), ark_piop::errors::SnarkError> {
    let gadget: Arc<Node<B>> = Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::new())));
    let gadget_id = gadget.id();
    let harness = GadgetHarness::<B>::builder(8)
        .with_gadget(gadget)
        .with_table(gadget_id, INPUT_LABEL, spec(&output))
        .with_table(gadget_id, OUTPUT_LABEL, spec(&claimed))
        .build();
    run_gadget_pipeline(harness)
}

/// Three active rows `(10, 1), (20, 2), (30, 3)` scattered over four slots,
/// with junk in the inactive slot.
fn output() -> Table<'static> {
    Table {
        nv: 2,
        cols: &[("a", &[10, 99, 20, 30]), ("b", &[1, 77, 2, 3])],
        active: &[true, false, true, true],
    }
}

#[test]
fn same_rows_in_another_order_verify() {
    let claimed = Table {
        nv: 2,
        cols: &[("a", &[30, 10, 20, 0]), ("b", &[3, 1, 2, 0])],
        active: &[true, true, true, false],
    };
    run(output(), claimed).expect("the same rows in another order must verify");
}

#[test]
fn a_smaller_claimed_domain_verifies() {
    let output = Table {
        nv: 3,
        cols: &[
            ("a", &[0, 10, 0, 0, 20, 0, 0, 0]),
            ("b", &[0, 1, 0, 0, 2, 0, 0, 0]),
        ],
        active: &[false, true, false, false, true, false, false, false],
    };
    let claimed = Table {
        nv: 1,
        cols: &[("a", &[20, 10]), ("b", &[2, 1])],
        active: &[true, true],
    };
    run(output, claimed).expect("equal rows on differently sized domains must verify");
}

#[test]
fn a_changed_value_is_rejected() {
    let claimed = Table {
        nv: 2,
        cols: &[("a", &[30, 10, 20, 0]), ("b", &[4, 1, 2, 0])],
        active: &[true, true, true, false],
    };
    assert!(run(output(), claimed).is_err());
}

#[test]
fn broken_row_pairing_is_rejected() {
    // Each column alone is a permutation of the output's, but `b` no longer
    // stays with its `a`.
    let claimed = Table {
        nv: 2,
        cols: &[("a", &[10, 20, 30, 0]), ("b", &[2, 1, 3, 0])],
        active: &[true, true, true, false],
    };
    assert!(run(output(), claimed).is_err());
}

#[test]
fn an_extra_row_is_rejected() {
    let claimed = Table {
        nv: 2,
        cols: &[("a", &[10, 20, 30, 30]), ("b", &[1, 2, 3, 3])],
        active: &[true, true, true, true],
    };
    assert!(run(output(), claimed).is_err());
}

#[test]
fn a_missing_row_is_rejected() {
    let claimed = Table {
        nv: 2,
        cols: &[("a", &[10, 20, 0, 0]), ("b", &[1, 2, 0, 0])],
        active: &[true, true, false, false],
    };
    assert!(run(output(), claimed).is_err());
}

#[test]
fn changed_multiplicities_are_rejected() {
    // Same distinct rows and the same row count, different multiplicities.
    let output = Table {
        nv: 2,
        cols: &[("a", &[10, 10, 20, 0]), ("b", &[1, 1, 2, 0])],
        active: &[true, true, true, false],
    };
    let claimed = Table {
        nv: 2,
        cols: &[("a", &[10, 20, 20, 0]), ("b", &[1, 2, 2, 0])],
        active: &[true, true, true, false],
    };
    assert!(run(output, claimed).is_err());
}

#[test]
fn junk_in_an_inactive_claimed_slot_is_ignored() {
    let claimed = Table {
        nv: 2,
        cols: &[("a", &[30, 10, 20, 55]), ("b", &[3, 1, 2, 66])],
        active: &[true, true, true, false],
    };
    run(output(), claimed).expect("values in inactive slots must not matter");
}

#[test]
fn a_renamed_column_is_rejected() {
    let claimed = Table {
        nv: 2,
        cols: &[("a", &[30, 10, 20, 0]), ("c", &[3, 1, 2, 0])],
        active: &[true, true, true, false],
    };
    assert!(run(output(), claimed).is_err());
}
