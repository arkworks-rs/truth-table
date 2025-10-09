//! A PIOP for checking if a column has no zeros
//!
//! More precisely, this PIOP checks is the activated elements of a column do
//! not contain zeros.

#[cfg(test)]
mod test;

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::{PrimeField, batch_inversion};
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::Prover,
    verifier::Verifier,
};
use ark_std::{end_timer, start_timer};
use derivative::Derivative;
use std::marker::PhantomData;

pub struct NoZerosCheck<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);
#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct NoZerosCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub col: TrackedCol<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for NoZerosCheckProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            col: self.col.deep_clone(prover),
        }
    }
}

pub struct NoZerosCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for NoZerosCheck<F, MvPCS, UvPCS>
{
    type ProverInput = NoZerosCheckProverInput<F, MvPCS, UvPCS>;
    type VerifierInput = NoZerosCheckVerifierInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        for element in input.col.effective_iter() {
            if element == F::zero() {
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
        prover: &mut Prover<F, MvPCS, UvPCS>,
        prover_input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let col_poly = prover_input.col.data_tracked_poly().clone();
        let col_sel = prover_input.col.activator_tracked_poly();
        let col_poly_evals = col_poly.evaluations();
        let mut eval_inverses: Vec<F> = col_poly_evals.clone();

        batch_inversion(&mut eval_inverses);
        let inverses_mle = MLE::from_evaluations_vec(prover_input.col.log_size(), eval_inverses);

        // set up the tracker and add a zerocheck claim
        let inverses_poly = prover.track_and_commit_mat_mv_poly(&inverses_mle)?;
        let no_dups_check_poly = match col_sel {
            Some(col_sel) => &(&(&col_poly * &col_sel) * &inverses_poly) - &col_sel,
            None => &(&col_poly * &inverses_poly) - F::one(),
        };

        prover.add_mv_zerocheck_claim(no_dups_check_poly.id())?;
        Ok(())
    }
    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        verifier_input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let col_poly = verifier_input.tracked_col_oracle.data_tracked_oracle().clone();
        let col_sel = verifier_input.tracked_col_oracle.activator_tracked_oracle().clone();
        let inverses_poly_id = verifier.peek_next_id();
        let inverses_poly = verifier.track_mv_com_by_id(inverses_poly_id)?;
        let no_dups_check_poly = match col_sel {
            Some(col_sel) => &(&(&col_poly * &col_sel) * &inverses_poly) - &col_sel,
            None => &(&col_poly * (&inverses_poly)) - F::one(),
        };
        verifier.add_zerocheck_claim(no_dups_check_poly.id());

        Ok(())
    }
}
