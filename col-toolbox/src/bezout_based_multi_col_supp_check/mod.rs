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
    SnarkBackend,
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};
use derivative::Derivative;
use std::marker::PhantomData;

pub struct BezoutMultiColSuppCheckPIOP<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct BezoutMultiColSuppCheckProverInput<B: SnarkBackend> {
    pub orig_tracked_table: TrackedTable<B>,
    pub supp_tracked_table: TrackedTable<B>,
}

impl<B: SnarkBackend> DeepClone<B> for BezoutMultiColSuppCheckProverInput<B> {
    fn deep_clone(&self, new_prover: ArgProver<B>) -> Self {
        BezoutMultiColSuppCheckProverInput {
            orig_tracked_table: self.orig_tracked_table.deep_clone(new_prover.clone()),
            supp_tracked_table: self.supp_tracked_table.deep_clone(new_prover.clone()),
        }
    }
}

pub struct BezoutMultiColSuppCheckVerifierInput<B: SnarkBackend> {
    pub orig_tracked_table_oracle: TrackedTableOracle<B>,
    pub supp_tracked_table_oracle: TrackedTableOracle<B>,
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct BezoutMultiColSuppCheckProverOutput<B: SnarkBackend> {
    pub orig_folded_tracked_col: TrackedCol<B>,
    pub supp_folded_tracked_col: TrackedCol<B>,
    pub multiplicity: TrackedPoly<B>,
}
#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct BezoutMultiColSuppCheckVerifierOutput<B: SnarkBackend> {
    pub orig_folded_tracked_col_oracle: TrackedColOracle<B>,
    pub supp_folded_tracked_col_oracle: TrackedColOracle<B>,
    pub multiplicity: TrackedOracle<B>,
}

impl<B: SnarkBackend> PIOP<B> for BezoutMultiColSuppCheckPIOP<B> {
    type ProverInput = BezoutMultiColSuppCheckProverInput<B>;
    type VerifierInput = BezoutMultiColSuppCheckVerifierInput<B>;
    type ProverOutput = BezoutMultiColSuppCheckProverOutput<B>;
    type VerifierOutput = BezoutMultiColSuppCheckVerifierOutput<B>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(_input: Self::ProverInput) -> SnarkResult<()> {
        // TODO

        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<B>,
        prover_input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let table_folding_challs = (0..prover_input.orig_tracked_table.num_data_tracked_cols())
            .map(|_| prover.get_and_append_challenge(b"a").unwrap())
            .collect::<Vec<B::F>>();

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

        let inclusion_piop_prover_output =
            InclusionCheckPIOP::<B>::prove(prover, multicol_inclusion_check_prover_input)?;

        let supp_no_dups_checker = TrackedCol::new(
            inclusion_piop_prover_output.super_col_ms[0].clone(),
            prover_input.supp_tracked_table.activator_tracked_poly(),
            None,
        );
        let no_zeros_check_prover_input = NoZerosCheckProverInput {
            col: supp_no_dups_checker,
        };
        NoZerosCheck::<B>::prove(prover, no_zeros_check_prover_input)?;

        let multi_col_no_dup_prover_input = BezoutBasedMultiNoDupProverInput {
            tracked_table: prover_input.supp_tracked_table.clone(),
        };

        BezoutBasedMultiNoDup::<B>::prove(prover, multi_col_no_dup_prover_input)?;
        let multi_col_supp_check_prover_output = BezoutMultiColSuppCheckProverOutput {
            orig_folded_tracked_col: orig_table_folded_col,
            supp_folded_tracked_col: supp_table_folded_col,
            multiplicity: inclusion_piop_prover_output.super_col_ms[0].clone(),
        };
        Ok(multi_col_supp_check_prover_output)
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        verifier_input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let table_folding_challs = (0..verifier_input
            .orig_tracked_table_oracle
            .num_data_tracked_col_oracles())
            .map(|_| verifier.get_and_append_challenge(b"a").unwrap())
            .collect::<Vec<B::F>>();

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

        let inclusion_check_piop_verifier_output =
            InclusionCheckPIOP::<B>::verify(verifier, multicol_inclusion_check_verifier_input)?;

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
        NoZerosCheck::<B>::verify(verifier, no_zeros_check_verifier_input)?;

        let multi_col_no_dup_verifier_input = BezoutBasedMultiNoDupVerifierInput {
            tracked_table_oracle: verifier_input.supp_tracked_table_oracle.clone(),
        };

        BezoutBasedMultiNoDup::<B>::verify(verifier, multi_col_no_dup_verifier_input)?;

        let multi_col_supp_check_verifier_output = BezoutMultiColSuppCheckVerifierOutput {
            orig_folded_tracked_col_oracle: orig_table_folded_col,
            supp_folded_tracked_col_oracle: supp_table_folded_col,
            multiplicity: inclusion_check_piop_verifier_output.super_col_m_comms[0].clone(),
        };
        Ok(multi_col_supp_check_verifier_output)
    }
}
