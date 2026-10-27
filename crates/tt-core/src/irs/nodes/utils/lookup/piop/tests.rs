//! The Lookup PIOP with two included columns that share values, through a
//! gadget that calls it inline.

use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_FIELD, col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_piop::{DefaultSnarkBackend, SnarkBackend, errors::SnarkError, piop::PIOP};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{
    HintedLookupPIOP, HintedLookupProverInput, HintedLookupVerifierInput, LookupPIOP,
    LookupProverInput, LookupVerifierInput,
};
use crate::irs::nodes::utils::contig_sort::tests::assert_rejected;
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};
use crate::test_utils::inline_gadget::InlineGadget;

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const NV: usize = 2;
const FIRST: &str = "first";
const SECOND: &str = "second";
const SUPER: &str = "super";
const MULTIPLICITY: &str = "multiplicity";

/// 5 is in both included columns and once in the super column; the second
/// column's inactive 7 is in neither.
const FIRST_VALUES: [u64; 4] = [3, 5, 5, 8];
const SECOND_VALUES: [u64; 4] = [5, 8, 3, 7];
const SECOND_ACTIVE: [u64; 4] = [1, 1, 1, 0];
const SUPER_VALUES: [u64; 4] = [3, 5, 8, 9];
const MULTIPLICITIES: [u64; 4] = [2, 3, 2, 0];

fn spec(name: &str, values: [u64; 4], activator: Option<[u64; 4]>) -> TableSpec<F> {
    let field = Arc::new(Field::new(name, DataType::UInt64, false));
    let mut schema = vec![field.as_ref().clone()];
    if activator.is_some() {
        schema.push(ACTIVATOR_FIELD.as_ref().clone());
    }
    TableSpec {
        schema: Schema::new(schema),
        log_size: NV,
        cols: vec![(field, values.map(F::from).to_vec())],
        activator: activator.map(|a| a.map(F::from).to_vec()),
    }
}

fn col(table: &TrackedTable<B>) -> TrackedCol<B> {
    let data = table
        .tracked_col_by_ind(table.data_tracked_polys_indices()[0])
        .data_tracked_poly();
    TrackedCol::new(data, table.activator_tracked_poly(), None)
}

fn col_oracle(table: &TrackedTableOracle<B>) -> TrackedColOracle<B> {
    let data = table
        .tracked_col_oracle_by_ind(table.data_tracked_oracles_indices()[0])
        .data_tracked_oracle();
    TrackedColOracle::new(data, table.activator_tracked_poly(), None)
}

/// Proves that both columns are included in the super column, with the
/// multiplicity the PIOP computes or with `forged` committed in its place.
fn run(forged: Option<[u64; 4]>) -> Result<(), SnarkError> {
    let hinted = forged.is_some();
    let gadget = InlineGadget::<B>::node(
        Box::new(move |prover, payload| {
            let included_cols = vec![col(&payload[FIRST]), col(&payload[SECOND])];
            let super_col = col(&payload[SUPER]);
            if hinted {
                let input = HintedLookupProverInput {
                    included_cols,
                    super_col,
                    super_col_multiplicity: col(&payload[MULTIPLICITY]).data_tracked_poly(),
                };
                return HintedLookupPIOP::<B>::prove(prover, input);
            }
            let input = LookupProverInput {
                included_cols,
                super_col,
            };
            let output = LookupPIOP::<B>::prove(prover, input)?;
            assert_eq!(
                output.super_col_m.evaluations(),
                MULTIPLICITIES.map(F::from).to_vec()
            );
            Ok(())
        }),
        Box::new(move |verifier, payload| {
            let included_tracked_col_oracles =
                vec![col_oracle(&payload[FIRST]), col_oracle(&payload[SECOND])];
            let super_tracked_col_oracle = col_oracle(&payload[SUPER]);
            if hinted {
                let input = HintedLookupVerifierInput {
                    included_tracked_col_oracles,
                    super_tracked_col_oracle,
                    super_col_multiplicity: col_oracle(&payload[MULTIPLICITY])
                        .data_tracked_oracle(),
                };
                return HintedLookupPIOP::<B>::verify(verifier, input);
            }
            let input = LookupVerifierInput {
                included_tracked_col_oracles,
                super_tracked_col_oracle,
            };
            LookupPIOP::<B>::verify(verifier, input).map(|_| ())
        }),
    );
    let id = gadget.id();
    let mut builder = GadgetHarness::<B>::builder(16)
        .with_gadget(gadget)
        .with_table(id, FIRST, spec("first", FIRST_VALUES, None))
        .with_table(
            id,
            SECOND,
            spec("second", SECOND_VALUES, Some(SECOND_ACTIVE)),
        )
        .with_table(id, SUPER, spec("super", SUPER_VALUES, None));
    if let Some(multiplicity) = forged {
        builder = builder.with_table(id, MULTIPLICITY, spec("m", multiplicity, None));
    }
    run_gadget_pipeline(builder.build())
}

#[test]
fn multiplicity_counts_every_included_column() {
    run(None).expect("the multiplicity summed over both columns verifies");
}

#[test]
fn multiplicity_of_one_included_column_rejected() {
    // The counts in the first column alone, then in the second alone.
    for forged in [[1, 2, 1, 0], [1, 1, 1, 0]] {
        assert_rejected(run(Some(forged)));
    }
}
