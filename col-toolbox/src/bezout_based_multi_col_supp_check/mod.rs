#[cfg(test)]
mod test;

use crate::{
    bezout_based_multi_col_nodup::{
        BezoutBasedMultiNoDup, BezoutBasedMultiNoDupProverInput, BezoutBasedMultiNoDupVerifierInput,
    },
    inclusion_check::{InclusionCheckPIOP, InclusionCheckProverInput, InclusionCheckVerifierInput},
    no_zeros_check::{NoZerosCheck, NoZerosCheckProverInput, NoZerosCheckVerifierInput},
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
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};
use derivative::Derivative;
use std::marker::PhantomData;

pub struct BezoutMultiColSuppCheckPIOP<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct BezoutMultiColSuppCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
> {
    pub orig_tracked_table: TrackedTable<F, MvPCS, UvPCS>,
    pub supp_tracked_table: TrackedTable<F, MvPCS, UvPCS>,
}

impl<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
> DeepClone<F, MvPCS, UvPCS> for BezoutMultiColSuppCheckProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, new_prover: ArgProver<F, MvPCS, UvPCS>) -> Self {
        BezoutMultiColSuppCheckProverInput {
            orig_tracked_table: self.orig_tracked_table.deep_clone(new_prover.clone()),
            supp_tracked_table: self.supp_tracked_table.deep_clone(new_prover.clone()),
        }
    }
}

pub struct BezoutMultiColSuppCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
> {
    pub orig_tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub supp_tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct BezoutMultiColSuppCheckProverOutput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
> {
    pub orig_folded_tracked_col: TrackedCol<F, MvPCS, UvPCS>,
    pub supp_folded_tracked_col: TrackedCol<F, MvPCS, UvPCS>,
    pub multiplicity: TrackedPoly<F, MvPCS, UvPCS>,
}
#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct BezoutMultiColSuppCheckVerifierOutput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
> {
    pub orig_folded_tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    pub supp_folded_tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    pub multiplicity: TrackedOracle<F, MvPCS, UvPCS>,
}

impl<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
> PIOP<F, MvPCS, UvPCS> for BezoutMultiColSuppCheckPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = BezoutMultiColSuppCheckProverInput<F, MvPCS, UvPCS>;
    type VerifierInput = BezoutMultiColSuppCheckVerifierInput<F, MvPCS, UvPCS>;
    type ProverOutput = BezoutMultiColSuppCheckProverOutput<F, MvPCS, UvPCS>;
    type VerifierOutput = BezoutMultiColSuppCheckVerifierOutput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(_input: Self::ProverInput) -> SnarkResult<()> {
        // TODO

        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<F, MvPCS, UvPCS>,
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

        let multicol_inclusion_check_prover_input = InclusionCheckProverInput {
            included_cols: vec![orig_table_folded_col.clone()],
            super_col: supp_table_folded_col.clone(),
        };

        let inclusion_piop_prover_output = InclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(
            prover,
            multicol_inclusion_check_prover_input,
        )?;

        let supp_no_dups_checker = TrackedCol::new(
            inclusion_piop_prover_output.super_col_ms[0].clone(),
            prover_input.supp_tracked_table.activator_tracked_poly(),
            None,
        );
        let no_zeros_check_prover_input = NoZerosCheckProverInput {
            col: supp_no_dups_checker,
        };
        NoZerosCheck::<F, MvPCS, UvPCS>::prove(prover, no_zeros_check_prover_input)?;

        let multi_col_no_dup_prover_input = BezoutBasedMultiNoDupProverInput {
            tracked_table: prover_input.supp_tracked_table.clone(),
        };

        BezoutBasedMultiNoDup::<F, MvPCS, UvPCS>::prove(prover, multi_col_no_dup_prover_input)?;
        let multi_col_supp_check_prover_output = BezoutMultiColSuppCheckProverOutput {
            orig_folded_tracked_col: orig_table_folded_col,
            supp_folded_tracked_col: supp_table_folded_col,
            multiplicity: inclusion_piop_prover_output.super_col_ms[0].clone(),
        };
        Ok(multi_col_supp_check_prover_output)
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<F, MvPCS, UvPCS>,
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

        let multicol_inclusion_check_verifier_input = InclusionCheckVerifierInput {
            included_tracked_col_oracles: vec![orig_table_folded_col.clone()],
            super_tracked_col_oracle: supp_table_folded_col.clone(),
        };

        let inclusion_check_piop_verifier_output = InclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(
            verifier,
            multicol_inclusion_check_verifier_input,
        )?;

        let supp_no_dups_checker = TrackedColOracle::new(
            inclusion_check_piop_verifier_output.super_col_m_comms[0].clone(),
            verifier_input
                .supp_tracked_table_oracle
                .activator_tracked_poly(),
            None,
        );
        let no_zeros_check_verifier_input = NoZerosCheckVerifierInput {
            tracked_col_oracle: supp_no_dups_checker,
        };
        NoZerosCheck::<F, MvPCS, UvPCS>::verify(verifier, no_zeros_check_verifier_input)?;

        let multi_col_no_dup_verifier_input = BezoutBasedMultiNoDupVerifierInput {
            tracked_table_oracle: verifier_input.supp_tracked_table_oracle.clone(),
        };

        BezoutBasedMultiNoDup::<F, MvPCS, UvPCS>::verify(
            verifier,
            multi_col_no_dup_verifier_input,
        )?;

        let multi_col_supp_check_verifier_output = BezoutMultiColSuppCheckVerifierOutput {
            orig_folded_tracked_col_oracle: orig_table_folded_col,
            supp_folded_tracked_col_oracle: supp_table_folded_col,
            multiplicity: inclusion_check_piop_verifier_output.super_col_m_comms[0].clone(),
        };
        Ok(multi_col_supp_check_verifier_output)
    }
}
