use std::{
    borrow::Borrow,
    cell::{RefCell, RefMut},
    rc::Rc,
};

use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalSerialize;

use crate::tracker::{
    errors::PolyIOPErrors,
    tracker_structs::{TrackerID, CompiledZKSQLProof},
    verifier_tracker::VerifierTracker,
};

use derivative::Derivative;
use crate::subroutines::PolynomialCommitmentScheme;
use crate::transcript::TranscriptError;


#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct VerifierTrackerRef<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    tracker_rc: Rc<RefCell<VerifierTracker<E, PCS>>>,
}
impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> PartialEq for VerifierTrackerRef<E, PCS> {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.tracker_rc, &other.tracker_rc)
    }
}

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> VerifierTrackerRef<E, PCS> {
    pub fn new(tracker_rc: Rc<RefCell<VerifierTracker<E, PCS>>>) -> Self {
        Self {tracker_rc}
    }

    pub fn new_from_tracker(tracker: VerifierTracker<E, PCS>) -> Self {
        Self {tracker_rc: Rc::new(RefCell::new(tracker)) }
    }

    pub fn new_from_pcs_params(pcs_params: PCS::VerifierParam) -> Self {
        Self {tracker_rc: Rc::new(RefCell::new(VerifierTracker::new(pcs_params))) }
    }

    pub fn track_mat_comm(
        &self,
        comm: PCS::Commitment,
    ) -> Result<TrackedComm<E, PCS>, PolyIOPErrors> {
        let tracker_ref: &RefCell<VerifierTracker<E, PCS>> = self.tracker_rc.borrow();
        let mut tracker: RefMut<VerifierTracker<E, PCS>> = tracker_ref.borrow_mut();
        let res_id = tracker.track_mat_comm(comm)?;
        Ok(TrackedComm::new(res_id, self.tracker_rc.clone()))
    }

    pub fn track_virtual_comm(
        &self,
        eval_fn: Box<dyn Fn(&[<E as Pairing>::ScalarField]) -> Result<<E as Pairing>::ScalarField, PolyIOPErrors>>,
    ) -> TrackedComm<E, PCS> {
        let tracker_ref: &RefCell<VerifierTracker<E, PCS>> = self.tracker_rc.borrow();
        let mut tracker: RefMut<VerifierTracker<E, PCS>> = tracker_ref.borrow_mut();
        let res_id = tracker.track_virtual_comm(eval_fn);
        TrackedComm::new(res_id, self.tracker_rc.clone())
    }

    pub fn get_next_id(&mut self) -> TrackerID {
        let tracker_ref_cell: &RefCell<VerifierTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().get_next_id()
    }

    pub fn set_compiled_proof(&mut self, proof: CompiledZKSQLProof<E, PCS>) {
        let tracker_ref_cell: &RefCell<VerifierTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().set_compiled_proof(proof);
    }

    pub fn get_mat_comm(&self, id: TrackerID) -> PCS::Commitment {
        let tracker_ref_cell: &RefCell<VerifierTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow().get_mat_comm(id).unwrap().clone()
    }

    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> Result<E::ScalarField, TranscriptError> {
        let tracker_ref_cell: &RefCell<VerifierTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().get_and_append_challenge(label)
    }

    pub fn append_serializable_element<S: CanonicalSerialize>(
        &mut self,
        label: &'static [u8],
        group_elem: &S,
    ) -> Result<(), TranscriptError> {
        let tracker_ref_cell: &RefCell<VerifierTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().append_serializable_element(label, group_elem)
    }

    pub fn add_sumcheck_claim(&mut self, poly_id: TrackerID, claimed_sum: E::ScalarField) {
        let tracker_ref_cell: &RefCell<VerifierTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().add_sumcheck_claim(poly_id, claimed_sum);
    }
    pub fn add_zerocheck_claim(&mut self, poly_id: TrackerID) {
        let tracker_ref_cell: &RefCell<VerifierTracker<E, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().add_zerocheck_claim(poly_id);
    }

    pub fn get_prover_claimed_sum(&self, id: TrackerID) -> E::ScalarField {
        let tracker_ref_cell: &RefCell<VerifierTracker<E, PCS>> = self.tracker_rc.borrow();
        let tracker = tracker_ref_cell.borrow();
        let sum = tracker.get_prover_claimed_sum(id).unwrap().clone();
        return sum;
    }

    pub fn transfer_proof_poly_evals(&mut self) {
        let tracker_ref_cell: &RefCell<VerifierTracker<E, PCS>> = self.tracker_rc.borrow();
        let mut tracker = tracker_ref_cell.borrow_mut();
        tracker.transfer_proof_poly_evals();
    }

    pub fn transfer_prover_comm(&mut self,  id: TrackerID) -> TrackedComm<E, PCS> {
        let new_id: TrackerID;
        let comm: PCS::Commitment;
        let tracker_ref_cell: &RefCell<VerifierTracker<E, PCS>> = self.tracker_rc.borrow();
        {
            // Scope the immutable borrow
            let tracker = tracker_ref_cell.borrow();
            let comm_opt: Option<&PCS::Commitment> = tracker.proof.comms.get(&id);
            match comm_opt {
                Some(value) => {
                    comm = value.clone();
                },
                None => {
                    panic!("VerifierTracker Error: attempted to transfer prover comm, but id not found: {}", id);
                }
            }
        } 
        let mut tracker = tracker_ref_cell.borrow_mut();
        new_id = tracker.track_mat_comm(comm).unwrap();

        #[cfg(debug_assertions)] {
            assert_eq!(id, new_id, "VerifierTracker Error: attempted to transfer prover comm, but ids don't match: {}, {}", id, new_id);
        }

        let new_comm: TrackedComm<E, PCS> = TrackedComm::new(new_id, self.tracker_rc.clone());
        new_comm
    }

    pub fn verify_claims(&self) -> Result<(), PolyIOPErrors> {
        let tracker_ref_cell: &RefCell<VerifierTracker<E, PCS>> = self.tracker_rc.borrow();
        let mut tracker = tracker_ref_cell.borrow_mut();
        tracker.verify_claims()
    }

    // used for testing
    pub fn clone_underlying_tracker(&self) -> VerifierTracker<E, PCS> {
        let tracker_ref_cell: &RefCell<VerifierTracker<E, PCS>> = self.tracker_rc.borrow();
        let tracker = tracker_ref_cell.borrow();
        (*tracker).clone()
    }

    pub fn deep_copy(&self) -> VerifierTrackerRef<E, PCS> {
        let tracker_ref_cell: &RefCell<VerifierTracker<E, PCS>> = self.tracker_rc.borrow();
        let tracker = tracker_ref_cell.borrow();
        VerifierTrackerRef::new_from_tracker((*tracker).clone())
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct TrackedComm<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub id: TrackerID,
    pub tracker: Rc<RefCell<VerifierTracker<E, PCS>>>,
}
impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> PartialEq for TrackedComm<E, PCS> {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.tracker, &other.tracker)
    }
}
impl<E: Pairing, PCS: PolynomialCommitmentScheme<E>> TrackedComm<E, PCS> {
    pub fn new(id: TrackerID, tracker: Rc<RefCell<VerifierTracker<E, PCS>>>) -> Self {
        let new_comm: TrackedComm<E, PCS> = Self { id, tracker };
        new_comm
    }

    pub fn same_tracker(&self, other: &TrackedComm<E, PCS>) -> bool {
        Rc::ptr_eq(&self.tracker, &other.tracker)
    }

    pub fn assert_same_tracker(&self, other: &TrackedComm<E, PCS>) {
        assert!(self.same_tracker(other), "TrackedComms are not from the same tracker");
    }
    
    pub fn add_comms(&self, other: &TrackedComm<E, PCS>) -> Self {
        self.assert_same_tracker(&other);
        let tracker_ref: &RefCell<VerifierTracker<E, PCS>> = self.tracker.borrow();
        let mut tracker: RefMut<VerifierTracker<E, PCS>> = tracker_ref.borrow_mut();
        let res_id = tracker.add_comms(self.id.clone(), other.id.clone());
        TrackedComm::new(res_id, self.tracker.clone())
    }

    pub fn sub_comms(&self, other: &TrackedComm<E, PCS>) -> Self {
        self.assert_same_tracker(&other);
        let tracker_ref: &RefCell<VerifierTracker<E, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().sub_comms(self.id.clone(), other.id.clone());
        TrackedComm::new(res_id, self.tracker.clone())
    }

    pub fn mul_comms(&self, other: &TrackedComm<E, PCS>) -> Self {
        self.assert_same_tracker(&other);
        let tracker_ref: &RefCell<VerifierTracker<E, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().mul_comms(self.id.clone(), other.id.clone());
        TrackedComm::new(res_id, self.tracker.clone())
    }

    pub fn add_scalar(&self, c: E::ScalarField) -> TrackedComm<E, PCS> {
        let tracker_ref: &RefCell<VerifierTracker<E, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().add_scalar(self.id.clone(), c);
        TrackedComm::new(res_id, self.tracker.clone())
    }

    pub fn mul_scalar(&self, c: E::ScalarField) -> TrackedComm<E, PCS> {
        let tracker_ref: &RefCell<VerifierTracker<E, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().mul_scalar(self.id.clone(), c);
        TrackedComm::new(res_id, self.tracker.clone())
    }

    pub fn increase_nv_front(&self, added_nv: usize) -> TrackedComm<E, PCS> {
        let tracker_ref: &RefCell<VerifierTracker<E, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().increase_nv_front(self.id.clone(), added_nv);
        TrackedComm::new(res_id, self.tracker.clone())
    }

    pub fn increase_nv_back(&self, added_nv: usize) -> TrackedComm<E, PCS> {
        let tracker_ref: &RefCell<VerifierTracker<E, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().increase_nv_back(self.id.clone(), added_nv);
        TrackedComm::new(res_id, self.tracker.clone())
    }

    pub fn eval_virtual_comm( 
        &self, 
        point: &[E::ScalarField],
    ) -> Result<E::ScalarField, PolyIOPErrors> {
        let tracker_ref: &RefCell<VerifierTracker<E, PCS>> = self.tracker.borrow();
        let eval = tracker_ref.borrow().eval_virtual_comm(self.id.clone(), point)?;
        Ok(eval)
    }
}