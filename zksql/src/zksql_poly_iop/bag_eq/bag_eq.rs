use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, One, start_timer};
use std::marker::PhantomData;

use crate::subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::bag_multitool::bag_multitool::BagMultitoolIOP,
};

pub struct BagEqIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagEqIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        tracker: &mut ProverTrackerRef<E, PCS>,
        fx: &Bag<E, PCS>,
        gx: &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let start = start_timer!(|| "BagEqCheck prove");
        // check input shape is correct
        if fx.num_vars() != gx.num_vars() {
            return Err(PolyIOPErrors::InvalidParameters(
                "BagEqIOP Error: fx and gx have different number of variables".to_string(),
            ));
        }
        let nv = fx.num_vars();

        // initialize multiplicity vector
        let one_const_mle = DenseMultilinearExtension::from_evaluations_vec(nv, vec![E::ScalarField::one(); 2_usize.pow(nv as u32)]);
        let mx = tracker.track_mat_poly(one_const_mle);

        // call the bag_multitool prover
        // the null_offset is set to zero here because we assume it is an exact permutation without extra nulls
        BagMultitoolIOP::<E, PCS>::prove(tracker, &[fx.clone()], &[gx.clone()], &[mx.clone()], &[mx.clone()])?;

        end_timer!(start);
        Ok(())
    }

    pub fn verify(
        tracker: &mut VerifierTrackerRef<E, PCS>,
        fx: &BagComm<E, PCS>,
        gx: &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let one_closure = |_: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {Ok(E::ScalarField::one())};
        let one_comm = tracker.track_virtual_comm(Box::new(one_closure));
        BagMultitoolIOP::verify(tracker, &[fx.clone()], &[gx.clone()], &[one_comm.clone()], &[one_comm])?;
        Ok(())
    }
}