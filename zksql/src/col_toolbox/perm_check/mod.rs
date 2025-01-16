// #[cfg(test)]
// mod test;

use arithmetic::{
    ark_ff,
    ark_ff::{Field, PrimeField},
    ark_poly,
    ark_poly::DenseMultilinearExtension,
};
use ark_std::{One, Zero};
use crypto::{ark_ec, ark_ec::pairing::Pairing, pcs::PolynomialCommitmentScheme};
use datafusion::arrow::compute::kernels::sort;
use kit::ark_std;

// use zksql_macros::same_nv;
use std::{marker::PhantomData, ops::Neg};

use crate::tracker::prelude::*;

use super::prescr_perm_check::PrescrPermPIOP;

// Convinces the verifier that
pub struct PermPIOP<F: PrimeField, PCS: PolynomialCommitmentScheme<F>>(
    PhantomData<F>,
    PhantomData<PCS>,
);

impl<F: PrimeField, PCS: PolynomialCommitmentScheme<F>> PermPIOP<F, PCS>
where
    PCS: PolynomialCommitmentScheme<F>,
    F: PrimeField,
{
    // TODO: #[same_nv(fxs, gxs, mfxs, mgxs)]
    pub fn prove(
        tracker: &mut ProverTrackerRef<F, PCS>,
        f: &Col<F, PCS>,
        g: &Col<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let (sorted_col, perm_tr_poly) = sort_col::<F, PCS>()?;
        PrescrPermPIOP::prove(tracker, &sorted_col, in_col, &perm_tr_poly)?;
        Ok(())
    }

    pub fn verify(
        tracker: &mut VerifierTrackerRef<F, PCS>,
        f: &ColComm<F, PCS>,
        g: &ColComm<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let inverses_poly = verifier_tracker.transfer_prover_comm(inverses_poly_id);

        Ok(())
    }
}

fn sort_col<F: PrimeField, PCS: PolynomialCommitmentScheme<F>>(
    tracker: &mut ProverTrackerRef<F, PCS>,
    in_col: &Col<F, PCS>,
) -> Result<(Col<F, PCS>, TrackedPoly<F, PCS>), PolyIOPErrors> {
    let in_evals = in_col.inner_poly.evaluations();
    todo!()
}
