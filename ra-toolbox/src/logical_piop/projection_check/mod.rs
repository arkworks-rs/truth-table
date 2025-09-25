use std::sync::Arc;

use arithmetic::table::{ArithTable, TableComm};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::Prover,
    verifier::Verifier,
};
use datafusion::logical_expr::Projection;
use derivative::Derivative;

#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct ProjectionPIOPProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub projection: Projection,
    pub expr: Vec<ArithTable<F, MvPCS, UvPCS>>,
    pub input: ArithTable<F, MvPCS, UvPCS>,
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct ProjectionPIOPVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub projection: Projection,
    pub expr: Vec<TableComm<F, MvPCS, UvPCS>>,
    pub input: Arc<TableComm<F, MvPCS, UvPCS>>,
}

pub struct ProjectionPIOP;

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for ProjectionPIOP
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = ProjectionPIOPProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = ProjectionPIOPVerifierInput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        Ok(())
    }

    fn prove_inner(
        _prover: &mut Prover<F, MvPCS, UvPCS>,
        _input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        Ok(())
    }

    fn verify_inner(
        _verifier: &mut Verifier<F, MvPCS, UvPCS>,
        _input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        Ok(())
    }
}

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for ProjectionPIOPProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, _new_prover: Prover<F, MvPCS, UvPCS>) -> Self {
        self.clone()
    }
}

#[cfg(test)]
mod e2e_test;
