use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::Prover,
    verifier::Verifier,
};
use col_toolbox::contig_lex_sort_check::{
    ContigLexSortCheckPIOP, ContigLexSortCheckProverInput, ContigLexSortCheckVerifierInput,
};

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
    let contig_lex_sort_check_prover_input = ContigLexSortCheckProverInput {
        tracked_table: input.lex_sorted_sort_exprs_tracked_table.clone(),
        tie_indicator_tracked_table: input.tie_indicators_tracked_table.clone(),
        shift_tracked_table: input.shifted_lex_sorted_sort_exprs_tracked_table.clone(),
        ascending: input.ascending_vec.clone(),
        strict: vec![false; input.ascending_vec.len()],
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
    let contig_lex_sort_check_verifier_input = ContigLexSortCheckVerifierInput {
        tracked_table_oracle: input.lex_sorted_sort_exprs_tracked_table_oracle.clone(),
        tie_indicator_tracked_table_oracle: input.tie_indicators_tracked_table_oracle.clone(),
        shift_tracked_table_oracle: input
            .shifted_lex_sorted_sort_exprs_tracked_table_oracle
            .clone(),
        ascending: input.ascending_vec.clone(),
        strict: vec![false; input.ascending_vec.len()],
    };

    ContigLexSortCheckPIOP::<F, MvPCS, UvPCS>::verify(
        verifier,
        contig_lex_sort_check_verifier_input,
    )
}
