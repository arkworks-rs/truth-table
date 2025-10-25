//! Rematerialize a single tracked column.
//!
//! A filter or limit can leave a column with many inactive rows while it still
//! lives on the original hypercube dimension.  The paper’s rematerialization
//! node repacks the column onto the minimal hypercube and proves correctness by
//! (1) checking the new activator is Boolean and (2) proving a multiset
//! equality between the old and new data.  This module implements that two-step
//! PIOP for one column in the column toolbox.
#[cfg(test)]
mod test;

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{SnarkError::ProverError, SnarkResult},
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{
        Prover,
        errors::{HonestProverError::FalseClaim, ProverError::HonestProverError},
        structs::polynomial::TrackedPoly,
    },
    verifier::{Verifier, structs::oracle::TrackedOracle},
};
use derivative::Derivative;
use std::marker::PhantomData;

use crate::{
    binary_check::{BinaryCheckPIOP, BinaryCheckProverInput, BinaryCheckVerifierInput},
    multiplicity_check::{
        MultiplicityCheck, MultiplicityCheckProverInput, MultiplicityCheckVerifierInput,
    },
    perm_check::{PermPIOP, PermPIOPProverInput, PermPIOPVerifierInput},
};
pub struct RematerializeCheck<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct RematerializeCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub input_tracked_col: TrackedCol<F, MvPCS, UvPCS>,
    pub output_tracked_col: TrackedCol<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for RematerializeCheckProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            input_tracked_col: self.input_tracked_col.deep_clone(prover.clone()),
            output_tracked_col: self.output_tracked_col.deep_clone(prover),
        }
    }
}

pub struct RematerializeCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub input_tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    pub output_tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
}
impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for RematerializeCheck<F, MvPCS, UvPCS>
{
    type ProverInput = RematerializeCheckProverInput<F, MvPCS, UvPCS>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = RematerializeCheckVerifierInput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        // TODO
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        if let Some(output_activater_tracked_poly) =
            input.output_tracked_col.activator_tracked_poly()
        {
            let binary_check_prover_input = BinaryCheckProverInput {
                predicate: output_activater_tracked_poly,
            };
            BinaryCheckPIOP::prove(prover, binary_check_prover_input)?;
        }

        let perm_piop_prover_input = PermPIOPProverInput {
            left_col: input.input_tracked_col,
            right_col: input.output_tracked_col,
        };
        PermPIOP::<F, MvPCS, UvPCS>::prove(prover, perm_piop_prover_input)?;
        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        if let Some(output_activater_tracked_oracle) =
            input.output_tracked_col_oracle.activator_tracked_oracle()
        {
            let binary_check_verifier_input = BinaryCheckVerifierInput {
                predicate_oracle: output_activater_tracked_oracle,
            };
            BinaryCheckPIOP::verify(verifier, binary_check_verifier_input)?;
        }
        let perm_piop_verifier_input = PermPIOPVerifierInput {
            left_tracked_col_oracle: input.input_tracked_col_oracle,
            right_tracked_col_oracle: input.output_tracked_col_oracle,
        };
        PermPIOP::<F, MvPCS, UvPCS>::verify(verifier, perm_piop_verifier_input)?;

        Ok(())
    }
}
