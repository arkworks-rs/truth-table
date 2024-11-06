use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, One, start_timer};
use std::marker::PhantomData;

use crate::subroutines::pcs::PolynomialCommitmentScheme;
use crate::{
    tracker::prelude::*,
    zksql_poly_iop::bag_multitool::bag_multitool::BagMultitoolIOP,
};

pub struct BagSumIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);
impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagSumIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prove(
        tracker: &mut ProverTrackerRef<E, PCS>,
        fx0: &Bag<E, PCS>,
        fx1:  &Bag<E, PCS>,
        gx:  &Bag<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let start = start_timer!(|| "bagsumCheck prove");

        // initialize multiplicity vectors
        let f0_one_const_poly = DenseMultilinearExtension::from_evaluations_vec(fx0.num_vars(), vec![E::ScalarField::one(); 2_usize.pow(fx0.num_vars() as u32)]); 
        let f1_one_const_poly = DenseMultilinearExtension::from_evaluations_vec(fx1.num_vars(), vec![E::ScalarField::one(); 2_usize.pow(fx1.num_vars() as u32)]);
        let g_one_const_poly = DenseMultilinearExtension::from_evaluations_vec(gx.num_vars(), vec![E::ScalarField::one(); 2_usize.pow(gx.num_vars() as u32)]);
        let mfxs = vec![tracker.track_mat_poly(f0_one_const_poly), tracker.track_mat_poly(f1_one_const_poly)];
        let mgxs = vec![tracker.track_mat_poly(g_one_const_poly)];

        // use bag_multitool
        BagMultitoolIOP::<E, PCS>::prove(tracker, &[fx0.clone(), fx1.clone()], &[gx.clone()], &mfxs.clone(), &mgxs.clone())?;

        end_timer!(start);
        Ok(())
    }

    pub fn verify(
        tracker: &mut VerifierTrackerRef<E, PCS>,
        fx0: &BagComm<E, PCS>,
        fx1:  &BagComm<E, PCS>,
        gx:  &BagComm<E, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let start = start_timer!(|| "bagsumCheck verify");
        let one_closure = |_: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {Ok(E::ScalarField::one())};
        let one_comm = tracker.track_virtual_comm(Box::new(one_closure));
        let _ = tracker.track_virtual_comm(Box::new(one_closure)); // extra virtual comm to match the prove structure
        let _ = tracker.track_virtual_comm(Box::new(one_closure)); // extra virtual comm to match the prove structure
        BagMultitoolIOP::verify(tracker, &[fx0.clone(), fx1.clone()], &[gx.clone()], &[one_comm.clone(), one_comm.clone()], &[one_comm.clone()])?;
 
        end_timer!(start);
        Ok(())
    }

}