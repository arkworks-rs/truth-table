use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::Prover,
    verifier::Verifier,
};
use datafusion::logical_expr::Filter;

#[derive(Debug, Clone)]
pub struct FilterPIOPProverInput {
    pub filter: Filter,
}

#[derive(Debug, Clone)]
pub struct FilterPIOPVerifierInput {
    pub filter: Filter,
}

pub struct FilterPIOP;

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for FilterPIOP
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = FilterPIOPProverInput;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = FilterPIOPVerifierInput;

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        // // First check the output column activator is valid or not
        // let binary_check_input = BinaryCheckProverInput {
        //     activator: input.output_table.actvtr_poly().as_ref().unwrap().clone(),
        // };
        // BinaryCheckPIOP::<F, MvPCS, UvPCS>::prove(prover, binary_check_input)?;

        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        // let binary_check_input = BinaryCheckVerifierInput {
        //     activator_comm: input
        //         .output_table_comm
        //         .actvtr_poly()
        //         .as_ref()
        //         .unwrap()
        //         .clone(),
        // };

        // BinaryCheckPIOP::<F, MvPCS, UvPCS>::verify(verifier, binary_check_input)?;
        Ok(())
    }
}

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for FilterPIOPProverInput
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
mod test;
