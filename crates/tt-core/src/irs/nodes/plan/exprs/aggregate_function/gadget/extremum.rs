//! Shared table wiring for sound MAX/MIN checks.
//!
//! The extremum gadgets use two lookups in addition to their pointwise bound:
//! every active input row's broadcast claim must be the reported claim for its group,
//! and every reported claim must occur in an active input row of the same group.

use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_FIELD, col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::Field;
use indexmap::IndexMap;

const GROUP_FIELD_NAME: &str = "__extremum_group__";
const VALUE_FIELD_NAME: &str = "__extremum_value__";

/// The three pair tables consumed by the two extremum lookups.
pub(super) struct ExtremumTables<T> {
    /// Input-active `(group, per-row broadcast claim)` pairs.
    pub broadcast_input: T,
    /// Output-active `(group, reported claim)` pairs.
    pub output_claims: T,
    /// Input-active `(group, raw input value)` pairs.
    pub raw_input: T,
}

fn only_data_col<B: SnarkBackend>(table: &TrackedTable<B>, context: &str) -> TrackedCol<B> {
    let indices = table.data_tracked_polys_indices();
    assert_eq!(
        indices.len(),
        1,
        "{context} must contain exactly one data column"
    );
    table.tracked_col_by_ind(indices[0])
}

fn only_data_oracle<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    context: &str,
) -> TrackedColOracle<B> {
    let indices = table.data_tracked_oracles_indices();
    assert_eq!(
        indices.len(),
        1,
        "{context} must contain exactly one data column"
    );
    table.tracked_col_oracle_by_ind(indices[0])
}

fn pair_table<B: SnarkBackend>(
    groups: &TrackedTable<B>,
    values: &TrackedTable<B>,
    activator_source: &TrackedTable<B>,
) -> TrackedTable<B> {
    assert_eq!(
        groups.log_size(),
        values.log_size(),
        "extremum group and value columns must share a Boolean-hypercube domain"
    );
    assert_eq!(
        groups.log_size(),
        activator_source.log_size(),
        "extremum pair data and activator must share a Boolean-hypercube domain"
    );

    let group = only_data_col(groups, "extremum group table");
    let value = only_data_col(values, "extremum value table");
    let group_source_field = group
        .field_ref()
        .expect("extremum group column must carry field metadata");
    let value_source_field = value
        .field_ref()
        .expect("extremum value column must carry field metadata");

    let group_field = Arc::new(Field::new(
        GROUP_FIELD_NAME,
        group_source_field.data_type().clone(),
        group_source_field.is_nullable(),
    ));
    let value_field = Arc::new(Field::new(
        VALUE_FIELD_NAME,
        value_source_field.data_type().clone(),
        value_source_field.is_nullable(),
    ));
    let mut polys = IndexMap::new();
    polys.insert(group_field, group.data_tracked_poly());
    polys.insert(value_field, value.data_tracked_poly());
    if let Some(activator) = activator_source.activator_tracked_poly() {
        polys.insert(ACTIVATOR_FIELD.clone(), activator);
    }

    TrackedTable::new(None, polys, groups.log_size())
}

fn pair_oracle_table<B: SnarkBackend>(
    groups: &TrackedTableOracle<B>,
    values: &TrackedTableOracle<B>,
    activator_source: &TrackedTableOracle<B>,
) -> TrackedTableOracle<B> {
    assert_eq!(
        groups.log_size(),
        values.log_size(),
        "extremum group and value columns must share a Boolean-hypercube domain"
    );
    assert_eq!(
        groups.log_size(),
        activator_source.log_size(),
        "extremum pair data and activator must share a Boolean-hypercube domain"
    );

    let group = only_data_oracle(groups, "extremum group oracle table");
    let value = only_data_oracle(values, "extremum value oracle table");
    let group_source_field = group
        .field_ref()
        .expect("extremum group oracle must carry field metadata");
    let value_source_field = value
        .field_ref()
        .expect("extremum value oracle must carry field metadata");

    let group_field = Arc::new(Field::new(
        GROUP_FIELD_NAME,
        group_source_field.data_type().clone(),
        group_source_field.is_nullable(),
    ));
    let value_field = Arc::new(Field::new(
        VALUE_FIELD_NAME,
        value_source_field.data_type().clone(),
        value_source_field.is_nullable(),
    ));
    let mut oracles = IndexMap::new();
    oracles.insert(group_field, group.data_tracked_oracle());
    oracles.insert(value_field, value.data_tracked_oracle());
    if let Some(activator) = activator_source.activator_tracked_poly() {
        oracles.insert(ACTIVATOR_FIELD.clone(), activator);
    }

    TrackedTableOracle::new(None, oracles, groups.log_size())
}

/// Construct the prover tables for broadcast uniformity and active attainment.
pub(super) fn prover_tables<B: SnarkBackend>(
    input_groups: &TrackedTable<B>,
    output_groups: &TrackedTable<B>,
    raw_input: &TrackedTable<B>,
    output_values: &TrackedTable<B>,
) -> ExtremumTables<TrackedTable<B>> {
    assert_eq!(
        input_groups.activator_tracked_poly(),
        raw_input.activator_tracked_poly(),
        "extremum input groups and raw values must share an activator"
    );
    assert_eq!(
        output_groups.activator_tracked_poly(),
        output_values.activator_tracked_poly(),
        "extremum output groups and claims must share an activator"
    );

    ExtremumTables {
        broadcast_input: pair_table(input_groups, output_values, input_groups),
        output_claims: pair_table(output_groups, output_values, output_groups),
        raw_input: pair_table(input_groups, raw_input, input_groups),
    }
}

/// Construct the verifier tables for broadcast uniformity and active attainment.
pub(super) fn verifier_tables<B: SnarkBackend>(
    input_groups: &TrackedTableOracle<B>,
    output_groups: &TrackedTableOracle<B>,
    raw_input: &TrackedTableOracle<B>,
    output_values: &TrackedTableOracle<B>,
) -> ExtremumTables<TrackedTableOracle<B>> {
    assert_eq!(
        input_groups.activator_tracked_poly(),
        raw_input.activator_tracked_poly(),
        "extremum input group and raw-value oracles must share an activator"
    );
    assert_eq!(
        output_groups.activator_tracked_poly(),
        output_values.activator_tracked_poly(),
        "extremum output group and claim oracles must share an activator"
    );

    ExtremumTables {
        broadcast_input: pair_oracle_table(input_groups, output_values, input_groups),
        output_claims: pair_oracle_table(output_groups, output_values, output_groups),
        raw_input: pair_oracle_table(input_groups, raw_input, input_groups),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::One;
    use ark_piop::{
        DefaultSnarkBackend, SnarkBackend,
        arithmetic::mat_poly::mle::MLE,
        prover::{ArgProver, structs::polynomial::TrackedPoly},
        test_utils::prelude_with_vars,
    };
    use datafusion::arrow::datatypes::DataType;

    type B = DefaultSnarkBackend;
    type F = <B as SnarkBackend>::F;

    fn tracked_poly(prover: &mut ArgProver<B>, values: &[u64]) -> TrackedPoly<B> {
        assert!(values.len().is_power_of_two());
        let log_size = values.len().ilog2() as usize;
        let values = values.iter().copied().map(F::from).collect();
        prover.track_mat_mv_poly(MLE::from_evaluations_vec(log_size, values))
    }

    fn table(
        prover: &mut ArgProver<B>,
        field_name: &str,
        values: &[u64],
        activator: TrackedPoly<B>,
    ) -> TrackedTable<B> {
        assert!(values.len().is_power_of_two());
        let log_size = values.len().ilog2() as usize;
        let value_poly = tracked_poly(prover, values);

        let mut polys = IndexMap::new();
        polys.insert(
            Arc::new(Field::new(field_name, DataType::UInt64, false)),
            value_poly,
        );
        polys.insert(ACTIVATOR_FIELD.clone(), activator);
        TrackedTable::new(None, polys, log_size)
    }

    fn active_rows(table: &TrackedTable<B>) -> Vec<Vec<F>> {
        let columns = table
            .data_tracked_polys_indices()
            .into_iter()
            .map(|index| {
                table
                    .tracked_col_by_ind(index)
                    .data_tracked_poly()
                    .evaluations()
            })
            .collect::<Vec<_>>();
        let active = table
            .activator_tracked_poly()
            .expect("test pair table must carry an activator")
            .evaluations();

        (0..table.size())
            .filter(|&row| active[row] == F::one())
            .map(|row| columns.iter().map(|column| column[row]).collect())
            .collect()
    }

    fn active_subset(included: &TrackedTable<B>, superset: &TrackedTable<B>) -> bool {
        let included = active_rows(included);
        let superset = active_rows(superset);
        included.iter().all(|row| superset.contains(row))
    }

    #[test]
    fn attainment_lookup_accepts_an_honest_max_from_another_slot() {
        let (mut prover, _) = prelude_with_vars::<B>(2).unwrap();
        let input_active = [1, 1, 0, 0];
        let output_active = [1, 0, 0, 0];
        let input_activator = tracked_poly(&mut prover, &input_active);
        let output_activator = tracked_poly(&mut prover, &output_active);
        let input_groups = table(&mut prover, "group", &[7, 7, 0, 0], input_activator.clone());
        let output_groups = table(
            &mut prover,
            "group",
            &[7, 7, 0, 0],
            output_activator.clone(),
        );
        let raw_input = table(&mut prover, "value", &[1, 2, 0, 0], input_activator);
        // The output representative is slot 0, but the maximum is attained at slot 1.
        let output = table(&mut prover, "max", &[2, 2, 0, 0], output_activator);

        let tables = prover_tables(&input_groups, &output_groups, &raw_input, &output);
        assert!(active_subset(
            &tables.broadcast_input,
            &tables.output_claims
        ));
        assert!(active_subset(&tables.output_claims, &tables.raw_input));
    }

    #[test]
    fn broadcast_lookup_rejects_a_nonuniform_group_claim() {
        let (mut prover, _) = prelude_with_vars::<B>(2).unwrap();
        let input_active = [1, 1, 0, 0];
        let output_active = [1, 0, 0, 0];
        let input_activator = tracked_poly(&mut prover, &input_active);
        let output_activator = tracked_poly(&mut prover, &output_active);
        let input_groups = table(&mut prover, "group", &[7, 7, 0, 0], input_activator.clone());
        let output_groups = table(
            &mut prover,
            "group",
            &[7, 7, 0, 0],
            output_activator.clone(),
        );
        let raw_input = table(&mut prover, "value", &[1, 2, 0, 0], input_activator);
        // Slot 1 claims three for the same group whose active output row claims two.
        let output = table(&mut prover, "max", &[2, 3, 0, 0], output_activator);

        let tables = prover_tables(&input_groups, &output_groups, &raw_input, &output);
        assert!(!active_subset(
            &tables.broadcast_input,
            &tables.output_claims
        ));
        assert!(active_subset(&tables.output_claims, &tables.raw_input));
    }

    #[test]
    fn attainment_lookup_rejects_an_unattained_bound() {
        let (mut prover, _) = prelude_with_vars::<B>(2).unwrap();
        let input_active = [1, 1, 0, 0];
        let output_active = [1, 0, 0, 0];
        let input_activator = tracked_poly(&mut prover, &input_active);
        let output_activator = tracked_poly(&mut prover, &output_active);
        let input_groups = table(&mut prover, "group", &[7, 7, 0, 0], input_activator.clone());
        let output_groups = table(
            &mut prover,
            "group",
            &[7, 7, 0, 0],
            output_activator.clone(),
        );
        let raw_input = table(&mut prover, "value", &[1, 2, 0, 0], input_activator);
        // Three upper-bounds both active values but is not attained by either one.
        let output = table(&mut prover, "max", &[3, 3, 0, 0], output_activator);

        let tables = prover_tables(&input_groups, &output_groups, &raw_input, &output);
        assert!(active_subset(
            &tables.broadcast_input,
            &tables.output_claims
        ));
        assert!(!active_subset(&tables.output_claims, &tables.raw_input));
    }

    #[test]
    fn attainment_lookup_rejects_an_inactive_padding_witness() {
        let (mut prover, _) = prelude_with_vars::<B>(2).unwrap();
        let input_active = [1, 1, 0, 0];
        let output_active = [0, 0, 1, 0];
        let input_activator = tracked_poly(&mut prover, &input_active);
        let output_activator = tracked_poly(&mut prover, &output_active);
        let input_groups = table(&mut prover, "group", &[7, 7, 7, 0], input_activator.clone());
        let output_groups = table(
            &mut prover,
            "group",
            &[7, 7, 7, 0],
            output_activator.clone(),
        );
        let raw_input = table(&mut prover, "value", &[1, 2, 0, 0], input_activator);
        // Zero is a lower bound but appears only in inactive padding.
        let output = table(&mut prover, "min", &[0, 0, 0, 0], output_activator);

        let tables = prover_tables(&input_groups, &output_groups, &raw_input, &output);
        assert!(active_subset(
            &tables.broadcast_input,
            &tables.output_claims
        ));
        assert!(!active_subset(&tables.output_claims, &tables.raw_input));
    }
}
