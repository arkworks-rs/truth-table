#[cfg(test)]
mod test;

use arithmetic::{ark_ff, ark_poly};
use ark_ec::pairing::Pairing;
use ark_ff::{batch_inversion, Field, PrimeField};
use ark_poly::DenseMultilinearExtension;
use crypto::{ark_ec, pcs::PolynomialCommitmentScheme};
use std::marker::PhantomData;

use crate::tracker::prelude::*;

/// A PIOP for checking that the activated rows of a column are all non-zero.
///
///
/// Internally, it invokes a zerocheck for --> col.poly * col.actv_poly *
/// (1/inverses_poly) - col.actv_poly
pub struct NoZerosCheck<F:PrimeField, PCS: PolynomialCommitmentScheme<F>>(
    PhantomData<F>,
    PhantomData<PCS>,
);
impl<F:PrimeField, PCS: PolynomialCommitmentScheme<F>> NoZerosCheck<F, PCS>
where
    PCS: PolynomialCommitmentScheme<F>,
    F:PrimeField
{
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<F, PCS>,
        col: &Col<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        // compute inverses of col.poly
        let col_poly = col.inner_poly.clone();
        let col_sel = col.actv_poly.clone();
        let col_poly_evals = col.inner_poly.evaluations();
        let mut eval_inverses = col_poly_evals.clone();
        batch_inversion(&mut eval_inverses);
        let inverses_mle =
            DenseMultilinearExtension::from_evaluations_vec(col.num_vars(), eval_inverses);

        // set up the tracker and add a zerocheck claim
        let inverses_poly = prover_tracker.track_and_commit_poly(inverses_mle)?;
        let no_dups_check_poly = col_poly
            .mul_poly(&col_sel)
            .mul_poly(&inverses_poly)
            .sub_poly(&col_sel);
        prover_tracker.add_zerocheck_claim(no_dups_check_poly.id);

        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
        col: &ColComm<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let col_poly = col.poly.clone();
        let col_sel = col.selector.clone();
        let inverses_poly_id = verifier_tracker.get_next_id();
        let inverses_poly = verifier_tracker.transfer_prover_comm(inverses_poly_id);
        let no_dups_check_poly = col_poly
            .mul_comms(&col_sel)
            .mul_comms(&inverses_poly)
            .sub_comms(&col_sel);
        verifier_tracker.add_zerocheck_claim(no_dups_check_poly.id);

        Ok(())
    }
}
