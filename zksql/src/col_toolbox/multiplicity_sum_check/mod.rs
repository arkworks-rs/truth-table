#[cfg(test)]
mod test;

use crypto::ark_ec::pairing::Pairing;
use arithmetic::ark_ff::{Field, PrimeField};
use arithmetic::ark_poly::DenseMultilinearExtension;
use crypto::pcs::PolynomialCommitmentScheme;
use kit::ark_std::{end_timer, start_timer, One};
use std::marker::PhantomData;

use crate::tracker::prelude::{Col, ColComm, PolyIOPErrors, ProverTrackerRef, VerifierTrackerRef};
use crate::{
    col_toolbox::multiplicity_check::MultiplicityCheck,
};

/// A PIOP for checking that the activated rows of the output column is the sum
/// of activated rows of the input columns. Here, sum means the multiplicity of
/// an element in the output column is the sum of multiplicities of the same
/// element in the input columns.
///
/// Internally, it invokes a multiplicity_check for the input columns and the output
/// column, both with multiplicity polynomials of all 1s.
pub struct MultiplicitySumCheck<F:PrimeField, PCS: PolynomialCommitmentScheme<F>>(
    PhantomData<F>,
    PhantomData<PCS>,
);
impl<F:PrimeField, PCS: PolynomialCommitmentScheme<F>> MultiplicitySumCheck<F, PCS>
where
    PCS: PolynomialCommitmentScheme<F>,
    F:PrimeField
{
    pub fn prove(
        tracker: &mut ProverTrackerRef<F, PCS>,
        left_in_col: &Col<F, PCS>,
        right_in_col: &Col<F, PCS>,
        out_col: &Col<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let start = start_timer!(|| "colsumCheck prove");
        // TODO: Right now, for every constant 1 polynomials we are assigning a heap
        // memory because we are calling track_mat_poly. However, technically, only one
        // constant 1 polynomial is needed. How can we optimize this? initialize

        // multiplicity vectors
        let left_in_one_const_poly = DenseMultilinearExtension::from_evaluations_vec(
            left_in_col.num_vars(),
            vec![F::one(); 2_usize.pow(left_in_col.num_vars() as u32)],
        );
        let right_in_one_const_poly = DenseMultilinearExtension::from_evaluations_vec(
            right_in_col.num_vars(),
            vec![F::one(); 2_usize.pow(right_in_col.num_vars() as u32)],
        );
        let out_one_const_poly = DenseMultilinearExtension::from_evaluations_vec(
            out_col.num_vars(),
            vec![F::one(); 2_usize.pow(out_col.num_vars() as u32)],
        );
        let mfxs = vec![
            tracker.track_mat_poly(left_in_one_const_poly),
            tracker.track_mat_poly(right_in_one_const_poly),
        ];
        let mout_cols = vec![tracker.track_mat_poly(out_one_const_poly)];

        // use multiplicity_check
        MultiplicityCheck::<F, PCS>::prove(
            tracker,
            &[left_in_col.clone(), right_in_col.clone()],
            &[out_col.clone()],
            &mfxs.clone(),
            &mout_cols.clone(),
        )?;

        end_timer!(start);
        Ok(())
    }

    pub fn verify(
        tracker: &mut VerifierTrackerRef<F, PCS>,
        left_in_col: &ColComm<F, PCS>,
        right_in_col: &ColComm<F, PCS>,
        out_col: &ColComm<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let start = start_timer!(|| "colsumCheck verify");
        let one_closure =
            |_: &[F]| -> Result<F, PolyIOPErrors> {
                Ok(F::one())
            };
        let one_comm = tracker.track_virtual_comm(Box::new(one_closure));
        let _ = tracker.track_virtual_comm(Box::new(one_closure)); // extra virtual comm to match the prove structure
        let _ = tracker.track_virtual_comm(Box::new(one_closure)); // extra virtual comm to match the prove structure
        MultiplicityCheck::verify(
            tracker,
            &[left_in_col.clone(), right_in_col.clone()],
            &[out_col.clone()],
            &[one_comm.clone(), one_comm.clone()],
            &[one_comm.clone()],
        )?;

        end_timer!(start);
        Ok(())
    }
}
