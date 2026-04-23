//! A PIOP to check if two columns are a permutation of each other.
// More precisely, this PIOP checks if the activated elements of one column
// are a permutation of the activated elements of another column.

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

use super::keyed_sumcheck::{KeyedSumcheck, KeyedSumcheckProverInput, KeyedSumcheckVerifierInput};

// Convinces the verifier that
pub struct PermPIOP<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct PermPIOPProverInput<B: SnarkBackend> {
    pub left_col: TrackedCol<B>,
    pub right_col: TrackedCol<B>,
}

impl<B: SnarkBackend> DeepClone<B> for PermPIOPProverInput<B> {
    fn deep_clone(&self, prover: ArgProver<B>) -> Self {
        Self {
            left_col: self.left_col.deep_clone(prover.clone()),
            right_col: self.right_col.deep_clone(prover),
        }
    }
}

pub struct PermPIOPVerifierInput<B: SnarkBackend> {
    pub left_tracked_col_oracle: TrackedColOracle<B>,
    pub right_tracked_col_oracle: TrackedColOracle<B>,
}
impl<B: SnarkBackend> PIOP<B> for PermPIOP<B> {
    type ProverInput = PermPIOPProverInput<B>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = PermPIOPVerifierInput<B>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        use std::collections::BTreeMap;

        let mut bookkeeping_map: BTreeMap<B::F, isize> = BTreeMap::new();
        for elem in input.left_col.effective_iter() {
            *bookkeeping_map.entry(elem).or_insert(0) += 1;
        }
        for elem in input.right_col.effective_iter() {
            *bookkeeping_map.entry(elem).or_insert(-1) -= 1;
        }
        for (_, count) in bookkeeping_map.iter() {
            if *count != 0 {
                return Err(ark_piop::errors::SnarkError::ProverError(
                    ark_piop::prover::errors::ProverError::HonestProverError(
                        ark_piop::prover::errors::HonestProverError::FalseClaim,
                    ),
                ));
            }
        }

        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<B>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let keyed_sumcheck_prover_input = KeyedSumcheckProverInput {
            fxs: vec![input.left_col],
            gxs: vec![input.right_col],
            mfxs: vec![None],
            mgxs: vec![None],
        };

        KeyedSumcheck::<B>::prove(prover, keyed_sumcheck_prover_input)?;
        Ok(())
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let keyed_sumcheck_vierifier_input = KeyedSumcheckVerifierInput {
            fxs: vec![input.left_tracked_col_oracle],
            gxs: vec![input.right_tracked_col_oracle],
            mfxs: vec![None],
            mgxs: vec![None],
        };

        KeyedSumcheck::<B>::verify(verifier, keyed_sumcheck_vierifier_input)?;
        Ok(())
    }
}
