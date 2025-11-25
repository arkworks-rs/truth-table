#[cfg(test)]
mod test;

use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::ArgProver,
    verifier::ArgVerifier,
};
use derivative::Derivative;
use std::marker::PhantomData;

use crate::{
    contig_lex_sort_check::{
        ContigLexSortCheckPIOP, ContigLexSortCheckProverInput, ContigLexSortCheckVerifierInput,
    },
    perm_check::{PermPIOP, PermPIOPProverInput, PermPIOPVerifierInput},
};
// Convinces the verifier that
pub struct SortBasedMultiNoDup<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

#[derive(Derivative)]
#[derivative(Debug(bound = ""), Clone(bound = ""))]
pub struct SortBasedMultiNoDupProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
> {
    pub tracked_table: TrackedTable<F, MvPCS, UvPCS>,
    pub contig_lex_sorted_tracked_table: TrackedTable<F, MvPCS, UvPCS>,
    pub tie_indicator_tracked_table: Option<TrackedTable<F, MvPCS, UvPCS>>,
    pub shift_tracked_table: TrackedTable<F, MvPCS, UvPCS>,
}

impl<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
> DeepClone<F, MvPCS, UvPCS> for SortBasedMultiNoDupProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: ArgProver<F, MvPCS, UvPCS>) -> Self {
        Self {
            tracked_table: self.tracked_table.deep_clone(prover.clone()),
            contig_lex_sorted_tracked_table: self
                .contig_lex_sorted_tracked_table
                .deep_clone(prover.clone()),
            shift_tracked_table: self.shift_tracked_table.deep_clone(prover.clone()),
            tie_indicator_tracked_table: self
                .tie_indicator_tracked_table
                .as_ref()
                .map(|table| table.deep_clone(prover.clone())),
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""), Clone(bound = ""))]
pub struct SortBasedMultiNoDupVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
> {
    pub tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub contig_lex_sorted_tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub tie_indicator_tracked_table_oracle: Option<TrackedTableOracle<F, MvPCS, UvPCS>>,
    pub shift_tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
}
impl<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
> PIOP<F, MvPCS, UvPCS> for SortBasedMultiNoDup<F, MvPCS, UvPCS>
{
    type ProverInput = SortBasedMultiNoDupProverInput<F, MvPCS, UvPCS>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = SortBasedMultiNoDupVerifierInput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(_input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        // TODO
        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let challenges = (0..input.tracked_table.num_data_tracked_cols())
            .map(|_| prover.get_and_append_challenge(b"fold").unwrap())
            .collect::<Vec<_>>();
        let tracked_table_folded_col = input.tracked_table.fold_all_data_columns(&challenges);
        let contig_lex_sorted_tracked_table_folded_col = input
            .contig_lex_sorted_tracked_table
            .fold_all_data_columns(&challenges);
        let perm_piop_prover_input = PermPIOPProverInput {
            left_col: tracked_table_folded_col,
            right_col: contig_lex_sorted_tracked_table_folded_col,
        };
        PermPIOP::<F, MvPCS, UvPCS>::prove(prover, perm_piop_prover_input)?;

        let mut strict_vec = vec![false; challenges.len() - 1];
        strict_vec.push(true);
        let contig_lex_sort_check_prover_input = ContigLexSortCheckProverInput {
            tracked_table: input.contig_lex_sorted_tracked_table,
            tie_indicator_tracked_table: input.tie_indicator_tracked_table,
            shift_tracked_table: input.shift_tracked_table,
            ascending: vec![true; challenges.len()],
            strict: strict_vec,
        };
        ContigLexSortCheckPIOP::<F, MvPCS, UvPCS>::prove(
            prover,
            contig_lex_sort_check_prover_input,
        )?;
        Ok(())
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let challenges = (0..input.tracked_table_oracle.num_data_tracked_col_oracles())
            .map(|_| verifier.get_and_append_challenge(b"fold").unwrap())
            .collect::<Vec<_>>();
        let tracked_table_folded_col_oracle = input
            .tracked_table_oracle
            .fold_all_data_oracles(&challenges);
        let contig_lex_sorted_tracked_table_folded_col_oracle = input
            .contig_lex_sorted_tracked_table_oracle
            .fold_all_data_oracles(&challenges);
        let perm_piop_verifier_input = PermPIOPVerifierInput {
            left_tracked_col_oracle: tracked_table_folded_col_oracle,
            right_tracked_col_oracle: contig_lex_sorted_tracked_table_folded_col_oracle,
        };
        PermPIOP::<F, MvPCS, UvPCS>::verify(verifier, perm_piop_verifier_input)?;

        let mut strict_vec = vec![false; challenges.len() - 1];
        strict_vec.push(true);
        let contig_lex_sort_check_verifier_input = ContigLexSortCheckVerifierInput {
            tracked_table_oracle: input.contig_lex_sorted_tracked_table_oracle,
            tie_indicator_tracked_table_oracle: input.tie_indicator_tracked_table_oracle,
            shift_tracked_table_oracle: input.shift_tracked_table_oracle,
            ascending: vec![true; challenges.len()],
            strict: strict_vec,
        };
        ContigLexSortCheckPIOP::<F, MvPCS, UvPCS>::verify(
            verifier,
            contig_lex_sort_check_verifier_input,
        )?;
        Ok(())
    }
}
