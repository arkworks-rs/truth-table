#[cfg(test)]
mod test;

use arithmetic::{ark_ff, ark_poly};
use crypto::ark_ec::pairing::Pairing;
use arithmetic::ark_ff::{Field, PrimeField};
use arithmetic::ark_poly::DenseMultilinearExtension;
use kit::ark_std::{end_timer, start_timer, One};
use crypto::{ark_ec, pcs::PolynomialCommitmentScheme};
use kit::ark_std;
use std::marker::PhantomData;
// use zksql_macros::same_nv;

use crate::{
    col_toolbox::multiplicity_check::MultiplicityCheck, tracker::prelude::{Col, ColComm, PolyIOPErrors, ProverTrackerRef, VerifierTrackerRef},
};

/// A PIOP to test if the activated rows of two columns are equal
///
/// Internally, this PIOP invokes the `MultiplicityCheck` with both multiplicity
/// vectors set to all-1 polynomials
pub struct EqCheckIOP<F: PrimeField, PCS: PolynomialCommitmentScheme<F>>(
    PhantomData<F>,
    PhantomData<PCS>,
);

impl<F: PrimeField + PrimeField, PCS: PolynomialCommitmentScheme<F>> EqCheckIOP<F, PCS>
where
    PCS: PolynomialCommitmentScheme<F>,
{
    // TODO:  #[same_nv(left_col, right_col)]
    pub fn prove(
        tracker: &mut ProverTrackerRef<F, PCS>,
        left_col: &Col<F, PCS>,
        right_col: &Col<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let start = start_timer!(|| "EqCheckCheck prove");
        let nv = left_col.num_vars();

        // initialize multiplicity vector
        let one_const_mle = DenseMultilinearExtension::from_evaluations_vec(
            nv,
            vec![F::one(); 2_usize.pow(nv as u32)],
        );
        let mx = tracker.track_mat_poly(one_const_mle);

        // call the multiplicity_check prover
        // the null_offset is set to zero here because we assume it is an exact
        // permutation without extra nulls
        MultiplicityCheck::<F, PCS>::prove(
            tracker,
            &[left_col.clone()],
            &[right_col.clone()],
            &[mx.clone()],
            &[mx.clone()],
        )?;

        end_timer!(start);
        Ok(())
    }

    pub fn verify(
        tracker: &mut VerifierTrackerRef<F, PCS>,
        left_col: &ColComm<F, PCS>,
        right_col: &ColComm<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let one_closure =
            |_: &[F]| -> Result<F, PolyIOPErrors> {
                Ok(F::one())
            };
        let one_comm = tracker.track_virtual_comm(Box::new(one_closure));
        MultiplicityCheck::verify(
            tracker,
            &[left_col.clone()],
            &[right_col.clone()],
            &[one_comm.clone()],
            &[one_comm],
        )?;
        Ok(())
    }
}
