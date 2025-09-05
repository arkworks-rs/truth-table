////////////// Imports //////////////

use arithmetic::col::{ArithCol, ColCom};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{Prover, structs::polynomial::TrackedPoly},
    timed,
    verifier::{Verifier, structs::oracle::TrackedOracle},
};
use ark_std::{end_timer, start_timer};
use col_toolbox::supp_check::{SuppCheckPIOP, SuppCheckProverInput, SuppCheckVerifierInput};
use std::marker::PhantomData;

use crate::group_by::utils::{fold_coms, fold_polys};

pub struct GroupingCheckPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    PhantomData<F>,
    PhantomData<MvPCS>,
    PhantomData<UvPCS>,
);

pub struct GroupingCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub input_grouping_columns: Vec<ArithCol<F, MvPCS, UvPCS>>,
    pub output_grouping_columns: Vec<ArithCol<F, MvPCS, UvPCS>>,
}

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for GroupingCheckProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        let input_grouping_columns = self
            .input_grouping_columns
            .iter()
            .map(|col| col.deep_clone(prover.clone()))
            .collect();
        let output_grouping_columns = self
            .output_grouping_columns
            .iter()
            .map(|col| col.deep_clone(prover.clone()))
            .collect();
        Self {
            input_grouping_columns,
            output_grouping_columns,
        }
    }
}

pub struct GroupingCheckProverOutput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub super_set_multiplicity_tr_p: TrackedPoly<F, MvPCS, UvPCS>,
    pub input_folded_col: ArithCol<F, MvPCS, UvPCS>,
    pub output_folded_col: ArithCol<F, MvPCS, UvPCS>,
}

pub struct GroupingCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub input_grouping_column_comms: Vec<ColCom<F, MvPCS, UvPCS>>,
    pub output_grouping_column_comms: Vec<ColCom<F, MvPCS, UvPCS>>,
}

pub struct GroupingCheckVerifierOutput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub super_set_multiplicity_tr_com: TrackedOracle<F, MvPCS, UvPCS>,
    pub input_folded_col_com: ColCom<F, MvPCS, UvPCS>,
    pub output_folded_col_com: ColCom<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for GroupingCheckPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = GroupingCheckProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = GroupingCheckProverOutput<F, MvPCS, UvPCS>;
    type VerifierOutput = GroupingCheckVerifierOutput<F, MvPCS, UvPCS>;
    type VerifierInput = GroupingCheckVerifierInput<F, MvPCS, UvPCS>;

    #[timed]
    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        // TODO: Implement honest prover check for GroupingCheckPIOP

        Ok(())
    }

    #[timed]
    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        // Extract the columns being grouped by from the table
        let num_gpd_cols = input.input_grouping_columns.len();
        debug_assert_eq!(num_gpd_cols, input.output_grouping_columns.len());

        // Generate one random field element for each column being grouped by
        // This is used to fold these columns to a single random linearly
        // combined column
        // TODO: Fix this unwrap and do sth for the error propagation
        let gpd_cols_fld_challs: Vec<F> = (0..num_gpd_cols)
            .map(|_| {
                prover
                    .get_and_append_challenge(b"Grouping columns folding challeng")
                    .unwrap()
            })
            .collect();

        // Fold the input grouping columns to a single column using the above challenges
        let input_folded_col = fold_polys(&input.input_grouping_columns, &gpd_cols_fld_challs);
        let output_folded_col = fold_polys(&input.output_grouping_columns, &gpd_cols_fld_challs);

        let supp_check_input = SuppCheckProverInput {
            col: input_folded_col.clone(),
            supp: output_folded_col.clone(),
        };

        let supp_check_output = SuppCheckPIOP::<F, MvPCS, UvPCS>::prove(prover, supp_check_input)?;
        Ok(GroupingCheckProverOutput {
            super_set_multiplicity_tr_p: supp_check_output.super_set_multiplicity_tr_p,
            input_folded_col,
            output_folded_col,
        })
    }

    #[timed]
    fn verify(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        // Extract the columns being grouped by from the table
        let num_gpd_cols = input.input_grouping_column_comms.len();
        assert_eq!(num_gpd_cols, input.output_grouping_column_comms.len());

        // Generate one random field element for each column being grouped by
        // This is used to fold these columns to a single random linearly
        // combined column
        // TODO: Fix this unwrap and do sth for the error propagation
        let gpd_cols_fld_challs: Vec<F> = (0..num_gpd_cols)
            .map(|_| {
                verifier
                    .get_and_append_challenge(b"Grouping columns folding challeng")
                    .unwrap()
            })
            .collect();

        // Fold the input grouping columns to a single column using the above challenges
        let input_folded_col_com =
            fold_coms(&input.input_grouping_column_comms, &gpd_cols_fld_challs);
        let output_folded_col_com =
            fold_coms(&input.output_grouping_column_comms, &gpd_cols_fld_challs);
        let supp_check_input = SuppCheckVerifierInput {
            col: input_folded_col_com.clone(),
            supp: output_folded_col_com.clone(),
        };
        let supp_check_output =
            SuppCheckPIOP::<F, MvPCS, UvPCS>::verify(verifier, supp_check_input)?;
        let output = Ok(GroupingCheckVerifierOutput {
            super_set_multiplicity_tr_com: supp_check_output.super_set_multiplicity_tr_com,
            input_folded_col_com,
            output_folded_col_com,
        });
        output
    }
}
