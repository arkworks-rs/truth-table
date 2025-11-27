//! A PIOP for checking if a column has no zeros
//!
//! More precisely, this PIOP checks is the activated elements of a column do
//! not contain zeros.

#[cfg(test)]
mod test;
use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::One;
use ark_ff::Zero;
use ark_ff::batch_inversion;
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::SnarkResult,
    piop::{DeepClone, PIOP},
    prover::ArgProver,
    verifier::ArgVerifier,
};
use derivative::Derivative;
use std::marker::PhantomData;
pub struct NoZerosCheck<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);
#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct NoZerosCheckProverInput<B: SnarkBackend> {
    pub col: TrackedCol<B>,
}

impl<B: SnarkBackend> DeepClone<B> for NoZerosCheckProverInput<B> {
    fn deep_clone(&self, prover: ArgProver<B>) -> Self {
        Self {
            col: self.col.deep_clone(prover),
        }
    }
}

pub struct NoZerosCheckVerifierInput<B: SnarkBackend> {
    pub tracked_col_oracle: TrackedColOracle<B>,
}

impl<B: SnarkBackend> PIOP<B> for NoZerosCheck<B> {
    type ProverInput = NoZerosCheckProverInput<B>;
    type VerifierInput = NoZerosCheckVerifierInput<B>;
    type ProverOutput = ();
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        for element in input.col.effective_iter() {
            if element == B::F::zero() {
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
        prover_input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let col_poly = prover_input.col.data_tracked_poly().clone();
        let col_sel = prover_input.col.activator_tracked_poly();
        let col_poly_evals = col_poly.evaluations();
        let mut eval_inverses: Vec<B::F> = col_poly_evals.clone();

        batch_inversion(&mut eval_inverses);
        let inverses_mle = MLE::from_evaluations_vec(prover_input.col.log_size(), eval_inverses);

        // set up the tracker and add a zerocheck claim
        let inverses_poly = prover.track_and_commit_mat_mv_poly(&inverses_mle)?;
        let no_dups_check_poly = match col_sel {
            Some(col_sel) => {
                let prod = &(&col_poly * &col_sel) * &inverses_poly;
                &prod - &col_sel
            }
            None => (&col_poly * &inverses_poly) - B::F::one(),
        };

        prover.add_mv_zerocheck_claim(no_dups_check_poly.id())?;
        Ok(())
    }
    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        verifier_input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let col_poly = verifier_input
            .tracked_col_oracle
            .data_tracked_oracle()
            .clone();
        let col_sel = verifier_input
            .tracked_col_oracle
            .activator_tracked_oracle()
            .clone();
        let inverses_poly_id = verifier.peek_next_id();
        let inverses_poly = verifier.track_mv_com_by_id(inverses_poly_id)?;
        let no_dups_check_poly = match col_sel {
            Some(col_sel) => {
                let prod = &(&col_poly * &col_sel) * &inverses_poly;
                &prod - &col_sel
            }
            None => (&col_poly * &inverses_poly) - B::F::one(),
        };
        verifier.add_zerocheck_claim(no_dups_check_poly.id());

        Ok(())
    }
}
