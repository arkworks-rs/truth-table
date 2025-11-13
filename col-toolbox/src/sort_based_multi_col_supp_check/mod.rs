#[cfg(test)]
mod test;

use crate::{
    inclusion_check::{
        HintedInclusionCheckPIOP, HintedInclusionCheckProverInput,
        HintedInclusionCheckVerifierInput,
    },
    no_zeros_check::{NoZerosCheck, NoZerosCheckProverInput, NoZerosCheckVerifierInput},
    sort_based_multi_col_nodup::{
        SortBasedMultiNoDup, SortBasedMultiNoDupProverInput, SortBasedMultiNoDupVerifierInput,
    },
};
use arithmetic::{
    col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{Prover, structs::polynomial::TrackedPoly},
    verifier::{Verifier, structs::oracle::TrackedOracle},
};
use derivative::Derivative;
use std::marker::PhantomData;

pub struct MultiColSuppCheckPIOP<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct MultiColSuppCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub orig_tracked_table: TrackedTable<F, MvPCS, UvPCS>,
    pub supp_tracked_table: TrackedTable<F, MvPCS, UvPCS>,
    pub contig_lex_sorted_supp_tracked_table: TrackedTable<F, MvPCS, UvPCS>,
    pub shifted_contig_lex_sorted_supp_tracked_table: TrackedTable<F, MvPCS, UvPCS>,
    pub tie_indicator_tracked_table: Option<TrackedTable<F, MvPCS, UvPCS>>,
    pub multiplicity: TrackedPoly<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for MultiColSuppCheckProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, new_prover: Prover<F, MvPCS, UvPCS>) -> Self {
        MultiColSuppCheckProverInput {
            orig_tracked_table: self.orig_tracked_table.deep_clone(new_prover.clone()),
            supp_tracked_table: self.supp_tracked_table.deep_clone(new_prover.clone()),
            contig_lex_sorted_supp_tracked_table: self
                .contig_lex_sorted_supp_tracked_table
                .deep_clone(new_prover.clone()),
            shifted_contig_lex_sorted_supp_tracked_table: self
                .shifted_contig_lex_sorted_supp_tracked_table
                .deep_clone(new_prover.clone()),
            tie_indicator_tracked_table: self
                .tie_indicator_tracked_table
                .as_ref()
                .map(|table| table.deep_clone(new_prover.clone())),

            multiplicity: self.multiplicity.deep_clone(new_prover),
        }
    }
}

pub struct MultiColSuppCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub orig_tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub supp_tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub contig_lex_sorted_supp_tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub shifted_contig_lex_sorted_supp_tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub tie_indicator_tracked_table_oracle: Option<TrackedTableOracle<F, MvPCS, UvPCS>>,
    pub multiplicity: TrackedOracle<F, MvPCS, UvPCS>,
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct MultiColSuppCheckProverOutput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub orig_folded_tracked_col: TrackedCol<F, MvPCS, UvPCS>,
    pub supp_folded_tracked_col: TrackedCol<F, MvPCS, UvPCS>,
}
#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct MultiColSuppCheckVerifierOutput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub orig_folded_tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    pub supp_folded_tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for MultiColSuppCheckPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = MultiColSuppCheckProverInput<F, MvPCS, UvPCS>;
    type VerifierInput = MultiColSuppCheckVerifierInput<F, MvPCS, UvPCS>;
    type ProverOutput = MultiColSuppCheckProverOutput<F, MvPCS, UvPCS>;
    type VerifierOutput = MultiColSuppCheckVerifierOutput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(_input: Self::ProverInput) -> SnarkResult<()> {
        // TODO

        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        prover_input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let table_folding_challs = (0..prover_input.orig_tracked_table.num_data_tracked_cols())
            .map(|_| prover.get_and_append_challenge(b"a").unwrap())
            .collect::<Vec<F>>();

        let orig_table_folded_col = prover_input
            .orig_tracked_table
            .fold_all_data_columns(&table_folding_challs);

        let supp_table_folded_col = prover_input
            .supp_tracked_table
            .fold_all_data_columns(&table_folding_challs);

        let multicol_inclusion_check_prover_input = HintedInclusionCheckProverInput {
            included_cols: vec![orig_table_folded_col.clone()],
            super_col: supp_table_folded_col.clone(),
            super_col_multiplicities: vec![prover_input.multiplicity.clone()],
        };

        HintedInclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(
            prover,
            multicol_inclusion_check_prover_input,
        )?;

        let supp_no_dups_checker = TrackedCol::new(
            prover_input.multiplicity.clone(),
            prover_input.supp_tracked_table.activator_tracked_poly(),
            None,
        );
        let no_zeros_check_prover_input = NoZerosCheckProverInput {
            col: supp_no_dups_checker,
        };
        NoZerosCheck::<F, MvPCS, UvPCS>::prove(prover, no_zeros_check_prover_input)?;

        let multi_col_no_dup_prover_input = SortBasedMultiNoDupProverInput {
            tracked_table: prover_input.supp_tracked_table.clone(),
            contig_lex_sorted_tracked_table: prover_input
                .contig_lex_sorted_supp_tracked_table
                .clone(),
            tie_indicator_tracked_table: prover_input.tie_indicator_tracked_table.clone(),
            shift_tracked_table: prover_input
                .shifted_contig_lex_sorted_supp_tracked_table
                .clone(),
        };

        SortBasedMultiNoDup::<F, MvPCS, UvPCS>::prove(prover, multi_col_no_dup_prover_input)?;
        // let multi_col_no_dup_prover_input = BezoutBasedMultiNoDupProverInput {
        //     tracked_table: prover_input.supp_tracked_table.clone(),
        //     contig_lex_sorted_tracked_table: prover_input
        //         .contig_lex_sorted_supp_tracked_table
        //         .clone(),
        //     tie_indicator_tracked_table:
        // prover_input.tie_indicator_tracked_table.clone(),
        //     shift_tracked_table: prover_input
        //         .shifted_contig_lex_sorted_supp_tracked_table
        //         .clone(),
        // };

        // BezoutBasedMultiNoDup::<F, MvPCS, UvPCS>::prove(prover,
        // multi_col_no_dup_prover_input)?;
        let multi_col_supp_check_prover_output = MultiColSuppCheckProverOutput {
            orig_folded_tracked_col: orig_table_folded_col,
            supp_folded_tracked_col: supp_table_folded_col,
        };
        Ok(multi_col_supp_check_prover_output)
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        verifier_input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let table_folding_challs = (0..verifier_input
            .orig_tracked_table_oracle
            .num_data_tracked_col_oracles())
            .map(|_| verifier.get_and_append_challenge(b"a").unwrap())
            .collect::<Vec<F>>();

        let orig_table_folded_col = verifier_input
            .orig_tracked_table_oracle
            .fold_all_data_oracles(&table_folding_challs);

        let supp_table_folded_col = verifier_input
            .supp_tracked_table_oracle
            .fold_all_data_oracles(&table_folding_challs);

        let multicol_inclusion_check_verifier_input = HintedInclusionCheckVerifierInput {
            included_tracked_col_oracles: vec![orig_table_folded_col.clone()],
            super_tracked_col_oracle: supp_table_folded_col.clone(),
            super_col_multiplicities: vec![verifier_input.multiplicity.clone()],
        };

        HintedInclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(
            verifier,
            multicol_inclusion_check_verifier_input,
        )?;

        let supp_no_dups_checker = TrackedColOracle::new(
            verifier_input.multiplicity.clone(),
            verifier_input
                .supp_tracked_table_oracle
                .activator_tracked_poly(),
            None,
        );
        let no_zeros_check_verifier_input = NoZerosCheckVerifierInput {
            tracked_col_oracle: supp_no_dups_checker,
        };
        NoZerosCheck::<F, MvPCS, UvPCS>::verify(verifier, no_zeros_check_verifier_input)?;

        let multi_col_no_dup_verifier_input = SortBasedMultiNoDupVerifierInput {
            tracked_table_oracle: verifier_input.supp_tracked_table_oracle.clone(),
            contig_lex_sorted_tracked_table_oracle: verifier_input
                .contig_lex_sorted_supp_tracked_table_oracle
                .clone(),
            tie_indicator_tracked_table_oracle: verifier_input
                .tie_indicator_tracked_table_oracle
                .clone(),
            shift_tracked_table_oracle: verifier_input
                .shifted_contig_lex_sorted_supp_tracked_table_oracle
                .clone(),
        };

        SortBasedMultiNoDup::<F, MvPCS, UvPCS>::verify(
            verifier,
            multi_col_no_dup_verifier_input.clone(),
        )?;

        // let multi_col_no_dup_verifier_input = BezoutBasedMultiNoDupVerifierInput {
        //     tracked_table_oracle: verifier_input.supp_tracked_table_oracle.clone(),
        //     contig_lex_sorted_tracked_table_oracle: verifier_input
        //         .contig_lex_sorted_supp_tracked_table_oracle
        //         .clone(),
        //     tie_indicator_tracked_table_oracle: verifier_input
        //         .tie_indicator_tracked_table_oracle
        //         .clone(),
        //     shift_tracked_table_oracle: verifier_input
        //         .shifted_contig_lex_sorted_supp_tracked_table_oracle
        //         .clone(),
        // };

        // BezoutBasedMultiNoDup::<F, MvPCS, UvPCS>::verify(
        //     verifier,
        //     multi_col_no_dup_verifier_input,
        // )?;

        let multi_col_supp_check_verifier_output = MultiColSuppCheckVerifierOutput {
            orig_folded_tracked_col_oracle: orig_table_folded_col,
            supp_folded_tracked_col_oracle: supp_table_folded_col,
        };
        Ok(multi_col_supp_check_verifier_output)
    }
}
