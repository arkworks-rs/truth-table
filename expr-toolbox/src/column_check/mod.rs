#[cfg(test)]
mod test;

use crate::prelude::*;
use datafusion::common::Column;

pub struct ColumnCheckPiop;

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for ColumnCheckPiop
{
    type ProverInput = ExprPIOPProverInput<F, MvPCS, UvPCS, Column>;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = ExprPIOPVerifierInput<F, MvPCS, UvPCS, Column>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(_input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        todo!()
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
