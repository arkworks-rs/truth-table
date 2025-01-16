#[cfg(test)]
mod test;

use arithmetic::{
    ark_ff,
    ark_ff::{Field, PrimeField},
    ark_poly,
    ark_poly::DenseMultilinearExtension,
};
use ark_std::{One, Zero};
use crypto::{ark_ec, ark_ec::pairing::Pairing, pcs::PolynomialCommitmentScheme};
use kit::ark_std;

// use zksql_macros::same_nv;
use std::{marker::PhantomData, ops::Neg};

use crate::tracker::prelude::*;

// Convinces the verifier that
pub struct FoldCheckPIOP<F: PrimeField, PCS: PolynomialCommitmentScheme<F>>(
    PhantomData<F>,
    PhantomData<PCS>,
);

impl<F: PrimeField, PCS: PolynomialCommitmentScheme<F>> FoldCheckPIOP<F, PCS>
where
    PCS: PolynomialCommitmentScheme<F>,
    F: PrimeField,
{
    // TODO: #[same_nv(fxs, gxs, mfxs, mgxs)]
    pub fn prove(
        tracker: &mut ProverTrackerRef<F, PCS>,
        in_cols: &[Col<F, PCS>],
        fldd_col: &Col<F, PCS>,
        challs: &[F],
    ) -> Result<(), PolyIOPErrors> {
        // Step 1: Check input shapes are correct

        // Check that we do actually have some polynomial on the left hand side
        if in_cols.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters(
                "MultiplicityCheck Error: fxs is empty".to_string(),
            ));
        }
        // Fix these clones
        let mut target_tracked_poly = fldd_col.effective_poly().clone();
        for (tracked_poly, chall) in in_cols.iter().zip(challs.iter()) {
            target_tracked_poly =
                target_tracked_poly.sub_poly(&tracked_poly.effective_poly().mul_scalar(*chall));
        }
        tracker.add_zerocheck_claim(target_tracked_poly.id);
        Ok(())
    }

    pub fn verify(
        tracker: &mut VerifierTrackerRef<F, PCS>,
        in_cms: &[ColComm<F, PCS>],
        fldd_cm: &ColComm<F, PCS>,
        challs: &[F],
    ) -> Result<(), PolyIOPErrors> {
        // check input shapes are correct
        if in_cms.is_empty() {
            return Err(PolyIOPErrors::InvalidParameters(
                "MultiplicityCheck Error: fxs is empty".to_string(),
            ));
        }

        let mut zero_comm = fldd_cm.effective_poly().clone();
        for (poly_comm, chall) in in_cms.iter().zip(challs.iter()) {
            zero_comm = zero_comm.sub_comms(&poly_comm.effective_poly().mul_scalar(*chall));
        }
        tracker.add_zerocheck_claim(zero_comm.id);
        Ok(())
    }
}
