use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::Prover,
    verifier::Verifier,
};
use col_toolbox::perm_check::{PermPIOP, PermPIOPProverInput, PermPIOPVerifierInput};

use crate::lp_piop::sort_check::{SortPIOPProverInput, SortPIOPVerifierInput};

/// Prove that the table coupled with the original sort expressions is a
/// permutation of the lexicographically sorted table coupled with the sorted
/// expressions
pub(super) fn perm_prove<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    prover: &mut Prover<F, MvPCS, UvPCS>,
    input: &SortPIOPProverInput<F, MvPCS, UvPCS>,
) -> SnarkResult<()> {
    // First, compute enough challenges to fold all data columns of the table
    let row_fold_challenges: Vec<F> = (0..input.tracked_table.num_data_tracked_cols())
        .map(|_| {
            prover
                .get_and_append_challenge(b"sort-row-fold")
                .expect("failed to draw folding challenge")
        })
        .collect();
    // next, fold all data columns of the table
    let table_folded_col = input
        .tracked_table
        .fold_all_data_columns(&row_fold_challenges);

    // Also, fold all data columns of the lexicographically sorted table, with the
    // same challenges
    let lex_sorted_table_folded_col = input
        .lex_sorted_tracked_table
        .fold_all_data_columns(&row_fold_challenges);

    // Now, start folding the sort expressions
    // We first produce enough challenges to fold all sort expression columns
    let sort_exprs_fold_challenges: Vec<F> =
        (0..input.sort_exprs_tracked_table.num_data_tracked_cols())
            .map(|_| {
                prover
                    .get_and_append_challenge(b"sort-key-fold")
                    .expect("failed to draw key folding challenge")
            })
            .collect();
    let sort_exprs_folded_col = input
        .sort_exprs_tracked_table
        .fold_all_data_columns(&sort_exprs_fold_challenges);

    // We do the same procedure for the sorted sort expressions

    let lex_sorted_sort_exprs_folded_col = input
        .lex_sorted_sort_exprs_tracked_table
        .fold_all_data_columns(&sort_exprs_fold_challenges);

    // Now, combine all the table folded column and sort expression folded poly
    let input_lc_tracked_poly =
        &table_folded_col.data_tracked_poly() + &sort_exprs_folded_col.data_tracked_poly();

    // Then, combine all the sorted table folded column and sorted sort expression
    // folded poly
    let lex_sorted_lc_tracked_poly = &lex_sorted_table_folded_col.data_tracked_poly()
        + &lex_sorted_sort_exprs_folded_col.data_tracked_poly();

    // Then attach the input activator to the input lc tracked poly. Note that the
    // input table and sort expressions should all have the same activator. This
    // should be checked in the honest prover check.
    let input_activator = input.tracked_table.activator_tracked_poly();
    let lex_sorted_activator = input.lex_sorted_tracked_table.activator_tracked_poly();
    
    let input_lc_tracked_col =
        TrackedCol::new(input_lc_tracked_poly, input_activator.clone(), None);
    let lex_sorted_lc_tracked_col =
        TrackedCol::new(lex_sorted_lc_tracked_poly, lex_sorted_activator, None);

    let perm_input = PermPIOPProverInput {
        left_col: input_lc_tracked_col,
        right_col: lex_sorted_lc_tracked_col,
    };

    PermPIOP::<F, MvPCS, UvPCS>::prove(prover, perm_input)
}

/// Prove that the table coupled with the original sort expressions is a
/// permutation of the lexicographically sorted table coupled with the sorted
/// expressions
pub(super) fn perm_verify<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    verifier: &mut Verifier<F, MvPCS, UvPCS>,
    input: &SortPIOPVerifierInput<F, MvPCS, UvPCS>,
) -> SnarkResult<()> {
    // First, compute enough challenges to fold all data columns of the table
    let row_fold_challenges: Vec<F> =
        (0..input.tracked_table_oracle.num_data_tracked_col_oracles())
            .map(|_| {
                verifier
                    .get_and_append_challenge(b"sort-row-fold")
                    .expect("failed to draw folding challenge")
            })
            .collect();
    // next, fold all data columns of the table
    let table_folded_col = input
        .tracked_table_oracle
        .fold_all_data_oracles(&row_fold_challenges);

    // Also, fold all data columns of the lexicographically sorted table, with the
    // same challenges
    let lex_sorted_table_folded_col = input
        .lex_sorted_tracked_table_oracle
        .fold_all_data_oracles(&row_fold_challenges);

    // Now, start folding the sort expressions
    // We first produce enough challenges to fold all sort expression columns
    let sort_exprs_fold_challenges: Vec<F> = (0..input
        .sort_exprs_tracked_table_oracle
        .num_data_tracked_col_oracles())
        .map(|_| {
            verifier
                .get_and_append_challenge(b"sort-key-fold")
                .expect("failed to draw key folding challenge")
        })
        .collect();
    let sort_exprs_folded_col = input
        .sort_exprs_tracked_table_oracle
        .fold_all_data_oracles(&sort_exprs_fold_challenges);

    // We do the same procedure for the sorted sort expressions

    let lex_sorted_sort_exprs_folded_col = input
        .lex_sorted_sort_exprs_tracked_table_oracle
        .fold_all_data_oracles(&sort_exprs_fold_challenges);

    // Now, combine all the table folded column and sort expression folded poly
    let input_lc_tracked_poly =
        &table_folded_col.data_tracked_oracle() + &sort_exprs_folded_col.data_tracked_oracle();

    // Then, combine all the sorted table folded column and sorted sort expression
    // folded poly
    let lex_sorted_lc_tracked_poly = &lex_sorted_table_folded_col.data_tracked_oracle()
        + &lex_sorted_sort_exprs_folded_col.data_tracked_oracle();

    // Then attach the input activator to the input lc tracked poly. Note that the
    // input table and sort expressions should all have the same activator. This
    // should be checked in the honest prover check.
    let input_activator = input.tracked_table_oracle.activator_tracked_poly();
    let sorted_activator = input
        .lex_sorted_tracked_table_oracle
        .activator_tracked_poly();

    let input_lc_tracked_col =
        TrackedColOracle::new(input_lc_tracked_poly, input_activator.clone(), None);
    let sorted_lc_tracked_col =
        TrackedColOracle::new(lex_sorted_lc_tracked_poly, sorted_activator, None);

    let perm_input = PermPIOPVerifierInput {
        left_tracked_col_oracle: input_lc_tracked_col,
        right_tracked_col_oracle: sorted_lc_tracked_col,
    };

    PermPIOP::<F, MvPCS, UvPCS>::verify(verifier, perm_input)
}
