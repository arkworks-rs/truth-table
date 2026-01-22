//! Rematerialize a single tracked column.
//!
//! A filter or limit can leave a column with many inactive rows while it still
//! lives on the original hypercube dimension.  The paper’s rematerialization
//! node repacks the column onto the minimal hypercube and proves correctness by
//! (1) checking the new activator is Boolean and (2) proving a multiset
//! equality between the old and new data.  This module implements that two-step
//! PIOP for one column in the column toolbox.

use crate::irs::nodes::gadget::utils::nodup::binary_check::BinaryCheckPIOP;
use crate::irs::nodes::gadget::utils::nodup::binary_check::BinaryCheckProverInput;
use crate::irs::nodes::gadget::utils::nodup::binary_check::BinaryCheckVerifierInput;
use crate::irs::nodes::gadget::utils::nodup::perm_check::PermPIOP;
use crate::irs::nodes::gadget::utils::nodup::perm_check::PermPIOPProverInput;
use crate::irs::nodes::gadget::utils::nodup::perm_check::PermPIOPVerifierInput;
use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_piop::{
    SnarkBackend,
    errors::SnarkResult,
    piop::{DeepClone, PIOP},
    prover::ArgProver,
    verifier::ArgVerifier,
};
use derivative::Derivative;
use std::marker::PhantomData;
pub struct RematerializeCheck<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct RematerializeCheckProverInput<B: SnarkBackend> {
    pub input_tracked_col: TrackedCol<B>,
    pub output_tracked_col: TrackedCol<B>,
}

impl<B: SnarkBackend> DeepClone<B> for RematerializeCheckProverInput<B> {
    fn deep_clone(&self, prover: ArgProver<B>) -> Self {
        Self {
            input_tracked_col: self.input_tracked_col.deep_clone(prover.clone()),
            output_tracked_col: self.output_tracked_col.deep_clone(prover),
        }
    }
}

pub struct RematerializeCheckVerifierInput<B: SnarkBackend> {
    pub input_tracked_col_oracle: TrackedColOracle<B>,
    pub output_tracked_col_oracle: TrackedColOracle<B>,
}
impl<B: SnarkBackend> PIOP<B> for RematerializeCheck<B> {
    type ProverInput = RematerializeCheckProverInput<B>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = RematerializeCheckVerifierInput<B>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(_input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        // TODO
        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<B>,
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
        PermPIOP::<B>::prove(prover, perm_piop_prover_input)?;
        Ok(())
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
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
        PermPIOP::<B>::verify(verifier, perm_piop_verifier_input)?;

        Ok(())
    }
}
