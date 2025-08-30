////////////// imports //////////////

use arithmetic::table::{ArithCol, ColComm, ArithTable, TableComm};
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
use derivative::Derivative;
use stat_check::StatCheckPIOP;
use std::marker::PhantomData;
use crate::supp_check::{SuppCheckPIOP, SuppCheckProverInput, SuppCheckVerifierInput};

/// InnerJoin Prover

pub struct InnerJoinPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    PhantomData<F>,
    PhantomData<MvPCS>,
    PhantomData<UvPCS>,
);

#[derive(Derivative)]
#[derivative(Clone(bound = "MvPCS: PCS<F>"), PartialEq(bound = "MvPCS: PCS<F>"))]
pub struct InnerJoinConfig {
    pub left_key_idx: usize,
    pub right_key_idx: usize,
    pub out_key_idx: usize,
}

pub struct InnerJoinProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>{
    pub left_table: ArithTable<F, MvPCS, UvPCS>,
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

 impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>> DeepClone<F, MvPCS, UvPCS> for InnerJoinProverInput<F, MvPCS, UvPCS> {
     fn deep_clone(&self) -> Self {
         Self {
             left_table: self.left_table.deep_clone(),
             right_table: self.right_table.deep_clone(),
             out_table: self.out_table.deep_clone(),
             keys: self.keys.clone(),
             left_key_support: self.left_key_support.deep_clone(),
             right_key_support: self.right_key_support.deep_clone(),
             out_key_support: self.out_key_support.deep_clone(),
             all_key_support: self.all_key_support.deep_clone(),
             join_left_source: self.join_left_source.deep_clone(),
             join_right_source: self.join_right_source.deep_clone(),
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
    pub left_key_support_comm: ColComm<F, MvPCS, UvPCS>,
    pub right_key_support_comm: ColComm<F, MvPCS, UvPCS>,
    pub out_key_support_comm: ColComm<F, MvPCS, UvPCS>,
    pub all_key_support_comm: ColComm<F, MvPCS, UvPCS>,
    pub join_left_source_comm: ColComm<F, MvPCS, UvPCS>,
    pub join_right_source_comm: ColComm<F, MvPCS, UvPCS>,
}


impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>> PIOP<F, MvPCS, UvPCS> for InnerJoinPIOP<F, MvPCS, UvPCS> {
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

    // Support Check on left_key_support, log output
    // Support Check on right_key_support, log output
    // Support Check on all_key_support, log output

    // (SetInterCheck) Multiplicity check on [left_key_support, right_key_support] and [all_key_support] with activator + 1

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
        // TODO: implement the verifier logic
        Ok(())
    }
}