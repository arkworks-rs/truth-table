use std::{
    borrow::Borrow,
    cell::RefCell,
    rc::Rc,
    sync::Arc,
};

use ark_ec::pairing::Pairing;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::CanonicalSerialize;

use crate::arithmetic::VirtualPolynomial;

use crate::tracker::{
    prover_tracker::ProverTracker,
    tracker_structs::{CompiledZKSQLProof, TrackerID},
    errors::PolyIOPErrors,
};

use derivative::Derivative;
use crate::subroutines::{pcs::PolynomialCommitmentScheme, PCSError};
use crate::transcript::TranscriptError;


#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct ProverTrackerRef<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    tracker_rc: Rc<RefCell<ProverTracker<E, PCS>>>,
}
impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> PartialEq for ProverTrackerRef<E, PCS> {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.tracker_rc, &other.tracker_rc)
    }
}

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> ProverTrackerRef<E, PCS> {
    pub fn new(tracker_rc: Rc<RefCell<ProverTracker<E, PCS>>>) -> Self {
        Self {tracker_rc}
    }

    pub fn new_from_tracker(tracker: ProverTracker<E, PCS>) -> Self {
        Self {tracker_rc: Rc::new(RefCell::new(tracker)) }
    }
    pub fn new_from_pcs_params(pcs_params: PCS::ProverParam) -> Self {
        Self {tracker_rc: Rc::new(RefCell::new(ProverTracker::new(pcs_params))) }
    }

    pub fn track_mat_poly(
        &mut self,
        polynomial: DenseMultilinearExtension<E::ScalarField>,
    ) -> TrackedPoly<E, PCS> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        let num_vars = polynomial.num_vars();
        let res_id = tracker_ref_cell.borrow_mut().track_mat_poly(polynomial);
       TrackedPoly::new(res_id, num_vars, self.tracker_rc.clone())
    }

    pub fn track_and_commit_poly(
        &mut self,
        polynomial: DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<TrackedPoly<E, PCS>, PCSError> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        let num_vars = polynomial.num_vars();
        let res_id = tracker_ref_cell.borrow_mut().track_and_commit_mat_poly(polynomial)?;
       Ok(TrackedPoly::new(res_id, num_vars, self.tracker_rc.clone()))
    }

    pub fn get_mat_poly(&self, id: TrackerID) -> Arc<DenseMultilinearExtension<E::ScalarField>> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow().get_mat_poly(id).unwrap().clone()
    }

    pub fn get_virt_poly(&self, id: TrackerID) -> Vec<(E::ScalarField, Vec<TrackerID>)> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow().get_virt_poly(id).unwrap().clone()
    }

    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> Result<E::ScalarField, TranscriptError> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().get_and_append_challenge(label)
    }

    pub fn append_serializable_element<S: CanonicalSerialize>(
        &mut self,
        label: &'static [u8],
        group_elem: &S,
    ) -> Result<(), TranscriptError> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().append_serializable_element(label, group_elem)
    }

    pub fn add_sumcheck_claim(
        &mut self, 
        poly_id: TrackerID, 
        claimed_sum: E::ScalarField
    ) {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().add_sumcheck_claim(poly_id, claimed_sum);
    }

    pub fn add_zerocheck_claim(
        &mut self, 
        poly_id: TrackerID
    ) {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().add_zerocheck_claim(poly_id);
    }

    pub fn get_next_id(&mut self) -> TrackerID {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().get_next_id()
    }

    pub fn compile_proof(&mut self) -> Result<CompiledZKSQLProof<E, PCS>, PolyIOPErrors> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().compile_proof()
    }

    // used for testing
    pub fn clone_underlying_tracker(&self) -> ProverTracker<E, PCS> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        let tracker = tracker_ref_cell.borrow();
        (*tracker).clone()
    }

    pub fn deep_copy(&self) -> ProverTrackerRef<E, PCS> {
        let tracker_ref_cell: &RefCell<ProverTracker<E, PCS>> = self.tracker_rc.borrow();
        let tracker = tracker_ref_cell.borrow();
        ProverTrackerRef::new_from_tracker((*tracker).clone())
    }
}


#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct TrackedPoly<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub id: TrackerID,
    pub num_vars: usize,
    pub tracker: Rc<RefCell<ProverTracker<E, PCS>>>,
}
impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> PartialEq for TrackedPoly<E, PCS> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && Rc::ptr_eq(&self.tracker, &other.tracker)
    }
}
impl<E: Pairing, PCS: PolynomialCommitmentScheme<E>> TrackedPoly<E, PCS> {
    pub fn new(id: TrackerID, num_vars: usize, tracker: Rc<RefCell<ProverTracker<E, PCS>>>) -> Self {
        Self { id, num_vars, tracker }
    }

    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    pub fn same_tracker(&self, other: &TrackedPoly<E, PCS>) -> bool {
        Rc::ptr_eq(&self.tracker, &other.tracker)
    }

    pub fn assert_same_tracker(&self, other: &TrackedPoly<E, PCS>) {
        assert!(self.same_tracker(other), "TrackedPolys are not from the same tracker");
    }
    
    pub fn add_poly(&self, other: &TrackedPoly<E, PCS>) -> Self {
        self.assert_same_tracker(&other);
        assert_eq!(self.num_vars, other.num_vars);
        let tracker_ref: &RefCell<ProverTracker<E, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().add_polys(self.id.clone(), other.id.clone());
        TrackedPoly::new(res_id, self.num_vars, self.tracker.clone())
    }

    pub fn sub_poly(&self, other: &TrackedPoly<E, PCS>) -> Self {
        self.assert_same_tracker(&other);
        assert_eq!(self.num_vars, other.num_vars);
        let tracker_ref: &RefCell<ProverTracker<E, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().sub_polys(self.id.clone(), other.id.clone());
        TrackedPoly::new(res_id, self.num_vars, self.tracker.clone())
    }

    pub fn mul_poly(&self, other: &TrackedPoly<E, PCS>) -> Self {
        self.assert_same_tracker(&other);
        assert_eq!(self.num_vars, other.num_vars);
        let tracker_ref: &RefCell<ProverTracker<E, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().mul_polys(self.id.clone(), other.id.clone());
        TrackedPoly::new(res_id, self.num_vars,self.tracker.clone())
    }

    pub fn add_scalar(&self, c: E::ScalarField) -> Self {
        let tracker_ref: &RefCell<ProverTracker<E, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().add_scalar(self.id.clone(), c);
        TrackedPoly::new(res_id, self.num_vars, self.tracker.clone())
    }

    pub fn mul_scalar(&self, c: E::ScalarField) -> Self {
        let tracker_ref: &RefCell<ProverTracker<E, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().mul_scalar(self.id.clone(), c);
        TrackedPoly::new(res_id, self.num_vars, self.tracker.clone())
    }

    pub fn increase_nv_front(&self, added_nv: usize) -> Self {
        let tracker_ref: &RefCell<ProverTracker<E, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().increase_nv_front(self.id.clone(), added_nv);
        TrackedPoly::new(res_id, self.num_vars + added_nv, self.tracker.clone())
    }

    pub fn increase_nv_back(&self, added_nv: usize) -> Self {
        let tracker_ref: &RefCell<ProverTracker<E, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().increase_nv_back(self.id.clone(), added_nv);
        TrackedPoly::new(res_id, self.num_vars + added_nv, self.tracker.clone())
    }

    pub fn evaluate(&self, pt: &[E::ScalarField]) -> Option<E::ScalarField>{
        let tracker_ref: &RefCell<ProverTracker<E, PCS>> = self.tracker.borrow();
        tracker_ref.borrow().evaluate(self.id.clone(), pt)
    }

    pub fn evaluations(&self) -> Vec<E::ScalarField> {
        // note: this has to actually clone the evaluations, which can be expensive
        let tracker_ref: &RefCell<ProverTracker<E, PCS>> = self.tracker.borrow();
        tracker_ref.borrow_mut().evaluations(self.id.clone()).clone() 
    }

    pub fn to_arithmatic_virtual_poly(&self) -> VirtualPolynomial<E::ScalarField> {
        let tracker_ref: &RefCell<ProverTracker<E, PCS>> = self.tracker.borrow();
        tracker_ref.borrow().to_arithmatic_virtual_poly(self.id.clone())
    }
}

