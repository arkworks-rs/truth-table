////////////// imports //////////////

use arithmetic::{
    col::{ArithCol, ColCom},
    table::{ArithTable, TableComm},
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::Prover,
    timed,
    verifier::Verifier,
};
use ark_std::{end_timer, start_timer};
use col_toolbox::supp_check::{SuppCheckPIOP, SuppCheckProverInput, SuppCheckVerifierInput};
use derivative::Derivative;
use std::marker::PhantomData;

/// InnerJoin Prover

pub struct InnerJoinPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    PhantomData<F>,
    PhantomData<MvPCS>,
    PhantomData<UvPCS>,
);

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct InnerJoinConfig {
    pub left_key_idx: usize,
    pub right_key_idx: usize,
    pub out_key_idx: usize,
}

pub struct InnerJoinProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub left_table_comm: ArithTable<F, MvPCS, UvPCS>,
    pub right_table: ArithTable<F, MvPCS, UvPCS>,
    pub out_table: ArithTable<F, MvPCS, UvPCS>,
    pub keys: InnerJoinConfig,
    pub left_key_support: ArithCol<F, MvPCS, UvPCS>,
    pub right_key_support: ArithCol<F, MvPCS, UvPCS>,
    pub out_key_support: ArithCol<F, MvPCS, UvPCS>,
    pub all_key_support: ArithCol<F, MvPCS, UvPCS>,
    pub join_left_source: ArithCol<F, MvPCS, UvPCS>,
    pub join_right_source: ArithCol<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for InnerJoinProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            left_table_comm: self.left_table_comm.deep_clone(prover.clone()),
            right_table: self.right_table.deep_clone(prover.clone()),
            out_table: self.out_table.deep_clone(prover.clone()),
            keys: self.keys.clone(),
            left_key_support: self.left_key_support.deep_clone(prover.clone()),
            right_key_support: self.right_key_support.deep_clone(prover.clone()),
            out_key_support: self.out_key_support.deep_clone(prover.clone()),
            all_key_support: self.all_key_support.deep_clone(prover.clone()),
            join_left_source: self.join_left_source.deep_clone(prover.clone()),
            join_right_source: self.join_right_source.deep_clone(prover.clone()),
        }
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "MvPCS: PCS<F>"), PartialEq(bound = "MvPCS: PCS<F>"))]
pub struct InnerJoinVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub left_table_comm: TableComm<F, MvPCS, UvPCS>,
    pub right_table_comm: TableComm<F, MvPCS, UvPCS>,
    pub out_table_comm: TableComm<F, MvPCS, UvPCS>,
    pub keys: InnerJoinConfig,
    pub left_key_support_comm: ColCom<F, MvPCS, UvPCS>,
    pub right_key_support_comm: ColCom<F, MvPCS, UvPCS>,
    pub out_key_support_comm: ColCom<F, MvPCS, UvPCS>,
    pub all_key_support_comm: ColCom<F, MvPCS, UvPCS>,
    pub join_left_source_comm: ColCom<F, MvPCS, UvPCS>,
    pub join_right_source_comm: ColCom<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for InnerJoinPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = InnerJoinProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierInput = InnerJoinVerifierInput<F, MvPCS, UvPCS>;
    type VerifierOutput = ();

    // TODO: honest-prover check

    #[timed]
    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        // Parse the config
        let conf = input.keys.clone();
        // Support Check on left_key_support, log output
        let supp_left_prover_input = SuppCheckProverInput {
            col: input.left_table_comm.get_col(conf.left_key_idx),
            supp: input.left_key_support,
        };
        let left_supp_check_output = SuppCheckPIOP::prove(prover, supp_left_prover_input)?;

        // Support Check on right_key_support, log output
        let supp_right_prover_input = SuppCheckProverInput {
            col: input.right_table.get_col(conf.right_key_idx),
            supp: input.right_key_support,
        };
        let right_supp_check_output = SuppCheckPIOP::prove(prover, supp_right_prover_input)?;

        // Support Check on the out table
        let supp_out_prover_input = SuppCheckProverInput {
            col: input.out_table.get_col(conf.out_key_idx),
            supp: input.out_key_support,
        };
        let out_supp_check_output = SuppCheckPIOP::prove(prover, supp_out_prover_input)?;

        // (SetInterCheck) Multiplicity check on [left_key_support, right_key_support]
        // and [all_key_support] with activator + 1

        // Zero Check on act(all_keys)(left_key - all_keys)
        // Zero Check on act(all_keys)(right_key - all_keys)
        // Zero Check on act(all_keys)(multicity_L * multiplicty_R - multiplicity_O)

        // Random Challenge r picked from verifier
        // NoDupCheck on source_L + r(source_R)

        Ok(())
    }

    #[timed]
    fn verify(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        // Parse the config
        let conf = input.keys.clone();
        // Support Check on left_key_support, log output
        let supp_left_verifier_input = SuppCheckVerifierInput {
            col: input.left_table_comm.col(conf.left_key_idx),
            supp: input.left_key_support_comm,
        };
        let left_supp_check_output = SuppCheckPIOP::verify(verifier, supp_left_verifier_input)?;

        // Support Check on right_key_support, log output
        let supp_right_verifier_input = SuppCheckVerifierInput {
            col: input.right_table_comm.col(conf.right_key_idx),
            supp: input.right_key_support_comm,
        };
        let right_supp_check_output = SuppCheckPIOP::verify(verifier, supp_right_verifier_input)?;

        // Support Check on the out table
        let supp_out_verifier_input = SuppCheckVerifierInput {
            col: input.out_table_comm.col(conf.out_key_idx),
            supp: input.out_key_support_comm,
        };
        let out_supp_check_output = SuppCheckPIOP::verify(verifier, supp_out_verifier_input)?;
        // TODO: implement the verifier logic
        Ok(())
    }
}
