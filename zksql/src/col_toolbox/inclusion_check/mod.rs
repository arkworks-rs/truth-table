#[cfg(test)]
mod test;
pub(crate) mod utils;

use arithmetic::{ark_ff, ark_poly};
use crypto::ark_ec::pairing::Pairing;
use arithmetic::ark_ff::{Field, PrimeField};
use arithmetic::ark_poly::DenseMultilinearExtension;
use kit::ark_std::{end_timer, start_timer, One};
use crypto::{ark_ec, pcs::PolynomialCommitmentScheme};
use kit::ark_std;
use std::marker::PhantomData;

use crate::{col_toolbox::{
    inclusion_check::utils::calc_inclusion_check_advice_from_col, multiplicity_check::MultiplicityCheck,
}, tracker::prelude::{Col, ColComm, PolyIOPErrors, ProverTrackerRef, TrackedComm, TrackedPoly, VerifierTrackerRef}};

/// A PIOP to check if the 'included_col' is included in the 'super_col'
///
/// Internally, this PIOP invokes the `MultiplicityCheck` with the multiplicity
/// polynomial of all 1 for the 'included_col' and a computed advice
/// multiplicity for 'super_col'
pub struct InclusionCheck<F:PrimeField, PCS: PolynomialCommitmentScheme<F>>(
    PhantomData<F>,
    PhantomData<PCS>,
);

impl<F:PrimeField, PCS: PolynomialCommitmentScheme<F>> InclusionCheck<F, PCS>
where
    PCS: PolynomialCommitmentScheme<F>,
    F:PrimeField
{
    pub fn prove(
        tracker: &mut ProverTrackerRef<F, PCS>,
        included_col: &Col<F, PCS>,
        super_col: &Col<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let super_col_m_mle = calc_inclusion_check_advice_from_col(included_col, super_col);
        let super_col_m = tracker.track_and_commit_poly(super_col_m_mle)?;
        Self::prove_with_advice(tracker, included_col, super_col, &super_col_m)
    }

    pub fn prove_with_advice(
        tracker: &mut ProverTrackerRef<F, PCS>,
        included_col: &Col<F, PCS>,
        super_col: &Col<F, PCS>,
        super_col_m: &TrackedPoly<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let start = start_timer!(|| "InclusionCheck prove");
        let nv = included_col.num_vars();

        // initialize multiplicity vector
        let one_const_mle = DenseMultilinearExtension::from_evaluations_vec(
            nv,
            vec![F::one(); 2_usize.pow(nv as u32)],
        );
        let included_col_m = tracker.track_mat_poly(one_const_mle);

        // call the multiplicity_check prover
        MultiplicityCheck::<F, PCS>::prove(
            tracker,
            &[included_col.clone()],
            &[super_col.clone()],
            &[included_col_m.clone()],
            &[super_col_m.clone()],
        )?;

        end_timer!(start);
        Ok(())
    }

    pub fn verify(
        tracker: &mut VerifierTrackerRef<F, PCS>,
        included_col: &ColComm<F, PCS>,
        super_col: &ColComm<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let super_col_m_id = tracker.get_next_id();
        let super_col_m = tracker.transfer_prover_comm(super_col_m_id);
        Self::verify_with_advice(tracker, included_col, super_col, &super_col_m)
    }

    pub fn verify_with_advice(
        tracker: &mut VerifierTrackerRef<F, PCS>,
        included_col: &ColComm<F, PCS>,
        super_col: &ColComm<F, PCS>,
        super_col_m: &TrackedComm<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let start = start_timer!(|| "InclusionCheck verify");

        let one_closure =
            |_: &[F]| -> Result<F, PolyIOPErrors> {
                Ok(F::one())
            };
        let one_comm = tracker.track_virtual_comm(Box::new(one_closure));
        MultiplicityCheck::verify(
            tracker,
            &[included_col.clone()],
            &[super_col.clone()],
            &[one_comm.clone()],
            &[super_col_m.clone()],
        )?;

        end_timer!(start);
        Ok(())
    }
}
