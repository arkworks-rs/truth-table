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
    // let contig_lex_sort_check_prover_input = ContigLexSortCheckProverInput {
    //     tracked_table,
    //     tie_indicator_tracked_polys,
    //     shift_tracked_table,
    //     ascending,
    //     strict,
    // };

    // ContigLexSortCheckPIOP::<F, MvPCS, UvPCS>::prove(prover,
    // contig_lex_sort_check_prover_input)
    Ok(())
}

pub(super) fn lex_sort_verify<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    verifier: &mut Verifier<F, MvPCS, UvPCS>,
    input: &SortPIOPVerifierInput<F, MvPCS, UvPCS>,
) -> SnarkResult<()> {
    // let contig_lex_sort_check_verifier_input =
    // ContigLexSortCheckVerifierInput {     tracked_table_oracle,
    //     tie_indicator_tracked_oracles,
    //     shift_tracked_table_oracle: shift_table_oracle,
    //     ascending,
    //     strict,
    // };

    // ContigLexSortCheckPIOP::<F, MvPCS, UvPCS>::verify(
    //     verifier,
    //     contig_lex_sort_check_verifier_input,
    // )
    Ok(())
}
