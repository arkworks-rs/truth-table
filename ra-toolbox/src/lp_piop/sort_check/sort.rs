use arithmetic::{ACTIVATOR_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::{Prover, structs::polynomial::TrackedPoly},
    verifier::{Verifier, structs::oracle::TrackedOracle},
};
use col_toolbox::contig_lex_sort_check::{
    ContigLexSortCheckPIOP, ContigLexSortCheckProverInput, ContigLexSortCheckVerifierInput,
};
use datafusion::arrow::datatypes::FieldRef;
use indexmap::IndexMap;

use crate::lp_piop::sort_check::{SortPIOPProverInput, SortPIOPVerifierInput};

// Prove that the sorted exprs are sorted lexicographically
pub(super) fn lex_sort_prove<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    prover: &mut Prover<F, MvPCS, UvPCS>,
    input: &SortPIOPProverInput<F, MvPCS, UvPCS>,
) -> SnarkResult<()> {
    let mut tracked_columns: IndexMap<FieldRef, TrackedPoly<F, MvPCS, UvPCS>> = IndexMap::new();
    let mut shift_columns: IndexMap<FieldRef, TrackedPoly<F, MvPCS, UvPCS>> = IndexMap::new();
    let mut table_log_size: Option<usize> = None;

    for sort_tracked_col in &input.sroted_sort_exprs {
        let expr_col = sort_tracked_col.expr.clone();
        let shifted_col = sort_tracked_col.shifted_expr.clone();

        if let Some(existing) = table_log_size {
            assert_eq!(
                existing,
                expr_col.log_size(),
                "all sort expression columns must share the same log size",
            );
        } else {
            table_log_size = Some(expr_col.log_size());
        }

        assert_eq!(
            expr_col.log_size(),
            shifted_col.log_size(),
            "shifted sort expression must match original log size",
        );

        match (
            expr_col.activator_tracked_poly(),
            shifted_col.activator_tracked_poly(),
        ) {
            (Some(a), Some(b)) => a.assert_same_tracker(&b),
            (None, None) => {},
            _ => panic!("inconsistent activators between sort expression and its shift"),
        }

        let expr_field = expr_col
            .field_ref()
            .unwrap_or_else(|| panic!("sort expression column missing field metadata"));
        let shifted_field = shifted_col
            .field_ref()
            .unwrap_or_else(|| panic!("shifted sort expression column missing field metadata"));

        tracked_columns.insert(expr_field.clone(), expr_col.data_tracked_poly());
        shift_columns.insert(shifted_field.clone(), shifted_col.data_tracked_poly());
    }

    if let Some((field, poly)) = input
        .lex_sorted_table
        .tracked_polys()
        .into_iter()
        .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
    {
        tracked_columns.insert(field.clone(), poly.clone());
        shift_columns.insert(field, poly);
    }

    let table_log_size = table_log_size.expect("sort expressions must produce at least one column");

    let tracked_table = TrackedTable::new(None, tracked_columns, table_log_size);
    let shift_tracked_table = TrackedTable::new(None, shift_columns, table_log_size);

    let ascending: Vec<bool> = input.sroted_sort_exprs.iter().map(|col| col.asc).collect();
    let strict = vec![false; ascending.len()];

    let tie_indicator_tracked_polys: Vec<TrackedPoly<F, MvPCS, UvPCS>> = input
        .tie_indicator_cols
        .iter()
        .map(|col| col.data_tracked_poly())
        .collect();

    let contig_lex_sort_check_prover_input = ContigLexSortCheckProverInput {
        tracked_table,
        tie_indicator_tracked_polys,
        shift_tracked_table,
        ascending,
        strict,
    };

    ContigLexSortCheckPIOP::<F, MvPCS, UvPCS>::prove(prover, contig_lex_sort_check_prover_input)
}

pub(super) fn lex_sort_verify<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    verifier: &mut Verifier<F, MvPCS, UvPCS>,
    input: &SortPIOPVerifierInput<F, MvPCS, UvPCS>,
) -> SnarkResult<()> {
    let mut tracked_columns: IndexMap<
        datafusion::arrow::datatypes::FieldRef,
        TrackedOracle<F, MvPCS, UvPCS>,
    > = IndexMap::new();
    let mut shift_columns: IndexMap<
        datafusion::arrow::datatypes::FieldRef,
        TrackedOracle<F, MvPCS, UvPCS>,
    > = IndexMap::new();
    let mut table_log_size: Option<usize> = None;

    for tracked_col in &input.sroted_sort_exprs {
        let expr_col = tracked_col.expr.clone();
        let shifted_col = tracked_col.shifted_expr.clone();

        if let Some(existing) = table_log_size {
            assert_eq!(
                existing,
                expr_col.log_size(),
                "all sort expression column oracles must share the same log size",
            );
        } else {
            table_log_size = Some(expr_col.log_size());
        }

        assert_eq!(
            expr_col.log_size(),
            shifted_col.log_size(),
            "shifted sort expression oracle must match original log size",
        );

        match (
            expr_col.activator_tracked_oracle(),
            shifted_col.activator_tracked_oracle(),
        ) {
            (Some(a), Some(b)) => a.assert_same_tracker(&b),
            (None, None) => {},
            _ => panic!("inconsistent activators between sort expression oracle and its shift"),
        }

        let expr_field = expr_col
            .field_ref()
            .unwrap_or_else(|| panic!("sort expression oracle missing field metadata"));
        let shifted_field = shifted_col
            .field_ref()
            .unwrap_or_else(|| panic!("shifted sort expression oracle missing field metadata"));

        tracked_columns.insert(expr_field.clone(), expr_col.data_tracked_oracle());
        shift_columns.insert(shifted_field.clone(), shifted_col.data_tracked_oracle());
    }

    if let Some((field, poly)) = input
        .lex_sorted_table
        .tracked_oracles()
        .into_iter()
        .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
    {
        tracked_columns.insert(field.clone(), poly.clone());
        shift_columns.insert(field, poly);
    }

    let table_log_size =
        table_log_size.expect("sort expressions must produce at least one column oracle");

    let tracked_table_oracle = TrackedTableOracle::new(None, tracked_columns, table_log_size);
    let shift_table_oracle = TrackedTableOracle::new(None, shift_columns, table_log_size);

    let tie_indicator_tracked_oracles: Vec<TrackedOracle<F, MvPCS, UvPCS>> = input
        .tie_indicator_cols
        .iter()
        .map(|col| col.data_tracked_oracle())
        .collect();

    let ascending: Vec<bool> = input.sroted_sort_exprs.iter().map(|col| col.asc).collect();
    let strict = vec![false; ascending.len()];

    let contig_lex_sort_check_verifier_input = ContigLexSortCheckVerifierInput {
        tracked_table_oracle,
        tie_indicator_tracked_oracles,
        shift_tracked_table_oracle: shift_table_oracle,
        ascending,
        strict,
    };

    ContigLexSortCheckPIOP::<F, MvPCS, UvPCS>::verify(
        verifier,
        contig_lex_sort_check_verifier_input,
    )
}
