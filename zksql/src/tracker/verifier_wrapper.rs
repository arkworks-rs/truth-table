use std::{
    borrow::Borrow,
    cell::{RefCell, RefMut},
    rc::Rc,
};

use arithmetic::ark_ff;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use crypto::ark_ec;
use kit::ark_serialize;
use transcript::TranscriptError;

use crate::tracker::{
    errors::PolyIOPErrors,
    tracker_structs::{CompiledZKSQLProof, TrackerID},
    verifier_tracker::VerifierTracker,
};

use crypto::pcs::PolynomialCommitmentScheme;
use kit::derivative::Derivative;

#[derive(Derivative)]
#[derivative(Clone(bound = "PCS: PolynomialCommitmentScheme<F>"))]
pub struct VerifierTrackerRef<F: PrimeField, PCS: PolynomialCommitmentScheme<F>>
where
    F: PrimeField,
{
    tracker_rc: Rc<RefCell<VerifierTracker<F, PCS>>>,
}
impl<F: PrimeField, PCS: PolynomialCommitmentScheme<F>> PartialEq for VerifierTrackerRef<F, PCS>
where
    F: PrimeField,
{
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.tracker_rc, &other.tracker_rc)
    }
}

impl<F: PrimeField, PCS: PolynomialCommitmentScheme<F>> VerifierTrackerRef<F, PCS>
where
    F: PrimeField,
{
    pub fn new(tracker_rc: Rc<RefCell<VerifierTracker<F, PCS>>>) -> Self {
        Self { tracker_rc }
    }

    pub fn new_from_tracker(tracker: VerifierTracker<F, PCS>) -> Self {
        Self {
            tracker_rc: Rc::new(RefCell::new(tracker)),
        }
    }

    pub fn new_from_pcs_params(pcs_params: PCS::VerifierParam) -> Self {
        Self {
            tracker_rc: Rc::new(RefCell::new(VerifierTracker::new(pcs_params))),
        }
    }

    pub fn track_mat_comm(
        &self,
        comm: PCS::Commitment,
    ) -> Result<TrackedComm<F, PCS>, PolyIOPErrors> {
        let tracker_ref: &RefCell<VerifierTracker<F, PCS>> = self.tracker_rc.borrow();
        let mut tracker: RefMut<VerifierTracker<F, PCS>> = tracker_ref.borrow_mut();
        let res_id = tracker.track_mat_comm(comm)?;
        Ok(TrackedComm::new(res_id, self.tracker_rc.clone()))
    }

    pub fn track_virtual_comm(
        &self,
        eval_fn: Box<dyn Fn(&[F]) -> Result<F, PolyIOPErrors>>,
    ) -> TrackedComm<F, PCS> {
        let tracker_ref: &RefCell<VerifierTracker<F, PCS>> = self.tracker_rc.borrow();
        let mut tracker: RefMut<VerifierTracker<F, PCS>> = tracker_ref.borrow_mut();
        let res_id = tracker.track_virtual_comm(eval_fn);
        TrackedComm::new(res_id, self.tracker_rc.clone())
    }

    pub fn get_next_id(&mut self) -> TrackerID {
        let tracker_ref_cell: &RefCell<VerifierTracker<F, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().get_next_id()
    }

    pub fn set_compiled_proof(&mut self, proof: CompiledZKSQLProof<F, PCS>) {
        let tracker_ref_cell: &RefCell<VerifierTracker<F, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().set_compiled_proof(proof);
    }

    pub fn get_mat_comm(&self, id: TrackerID) -> PCS::Commitment {
        let tracker_ref_cell: &RefCell<VerifierTracker<F, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow().get_mat_comm(id).unwrap().clone()
    }

    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> Result<F, TranscriptError> {
        let tracker_ref_cell: &RefCell<VerifierTracker<F, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell
            .borrow_mut()
            .get_and_append_challenge(label)
    }

    pub fn append_serializable_element<S: CanonicalSerialize>(
        &mut self,
        label: &'static [u8],
        group_elem: &S,
    ) -> Result<(), TranscriptError> {
        let tracker_ref_cell: &RefCell<VerifierTracker<F, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell
            .borrow_mut()
            .append_serializable_element(label, group_elem)
    }

    pub fn add_sumcheck_claim(&mut self, poly_id: TrackerID, claimed_sum: F) {
        let tracker_ref_cell: &RefCell<VerifierTracker<F, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell
            .borrow_mut()
            .add_sumcheck_claim(poly_id, claimed_sum);
    }
    pub fn add_zerocheck_claim(&mut self, poly_id: TrackerID) {
        let tracker_ref_cell: &RefCell<VerifierTracker<F, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().add_zerocheck_claim(poly_id);
    }

    pub fn get_prover_claimed_sum(&self, id: TrackerID) -> F {
        let tracker_ref_cell: &RefCell<VerifierTracker<F, PCS>> = self.tracker_rc.borrow();
        let tracker = tracker_ref_cell.borrow();
        let sum = tracker.get_prover_claimed_sum(id).unwrap().clone();
        return sum;
    }

    pub fn transfer_proof_poly_evals(&mut self) {
        let tracker_ref_cell: &RefCell<VerifierTracker<F, PCS>> = self.tracker_rc.borrow();
        let mut tracker = tracker_ref_cell.borrow_mut();
        tracker.transfer_proof_poly_evals();
    }

    pub fn transfer_prover_comm(&mut self, id: TrackerID) -> TrackedComm<F, PCS> {
        let new_id: TrackerID;
        let comm: PCS::Commitment;
        let tracker_ref_cell: &RefCell<VerifierTracker<F, PCS>> = self.tracker_rc.borrow();
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
                },
            }
        }
        let mut tracker = tracker_ref_cell.borrow_mut();
        new_id = tracker.track_mat_comm(comm).unwrap();

        #[cfg(debug_assertions)]
        {
            assert_eq!(id, new_id, "VerifierTracker Error: attempted to transfer prover comm, but ids don't match: {}, {}", id, new_id);
        }

        let new_comm: TrackedComm<F, PCS> = TrackedComm::new(new_id, self.tracker_rc.clone());
        new_comm
    }

    pub fn verify_claims(&self) -> Result<(), PolyIOPErrors> {
        let tracker_ref_cell: &RefCell<VerifierTracker<F, PCS>> = self.tracker_rc.borrow();
        let mut tracker = tracker_ref_cell.borrow_mut();
        tracker.verify_claims()
    }

    // used for testing
    pub fn clone_underlying_tracker(&self) -> VerifierTracker<F, PCS> {
        let tracker_ref_cell: &RefCell<VerifierTracker<F, PCS>> = self.tracker_rc.borrow();
        let tracker = tracker_ref_cell.borrow();
        (*tracker).clone()
    }

    pub fn deep_copy(&self) -> VerifierTrackerRef<F, PCS> {
        let tracker_ref_cell: &RefCell<VerifierTracker<F, PCS>> = self.tracker_rc.borrow();
        let tracker = tracker_ref_cell.borrow();
        VerifierTrackerRef::new_from_tracker((*tracker).clone())
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "PCS: PolynomialCommitmentScheme<F>"))]
pub struct TrackedComm<F: PrimeField, PCS: PolynomialCommitmentScheme<F>>
where
    F: PrimeField,
{
    pub id: TrackerID,
    pub tracker: Rc<RefCell<VerifierTracker<F, PCS>>>,
}
impl<F: PrimeField, PCS: PolynomialCommitmentScheme<F>> PartialEq for TrackedComm<F, PCS>
where
    F: PrimeField,
{
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.tracker, &other.tracker)
    }
}
impl<F: PrimeField, PCS: PolynomialCommitmentScheme<F>> TrackedComm<F, PCS>
where
    F: PrimeField,
{
    pub fn new(id: TrackerID, tracker: Rc<RefCell<VerifierTracker<F, PCS>>>) -> Self {
        let new_comm: TrackedComm<F, PCS> = Self { id, tracker };
        new_comm
    }

    pub fn same_tracker(&self, other: &TrackedComm<F, PCS>) -> bool {
        Rc::ptr_eq(&self.tracker, &other.tracker)
    }

    pub fn assert_same_tracker(&self, other: &TrackedComm<F, PCS>) {
        assert!(
            self.same_tracker(other),
            "TrackedComms are not from the same tracker"
        );
    }

    pub fn add_comms(&self, other: &TrackedComm<F, PCS>) -> Self {
        self.assert_same_tracker(&other);
        let tracker_ref: &RefCell<VerifierTracker<F, PCS>> = self.tracker.borrow();
        let mut tracker: RefMut<VerifierTracker<F, PCS>> = tracker_ref.borrow_mut();
        let res_id = tracker.add_comms(self.id.clone(), other.id.clone());
        TrackedComm::new(res_id, self.tracker.clone())
    }

    pub fn sub_comms(&self, other: &TrackedComm<F, PCS>) -> Self {
        self.assert_same_tracker(&other);
        let tracker_ref: &RefCell<VerifierTracker<F, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref
            .borrow_mut()
            .sub_comms(self.id.clone(), other.id.clone());
        TrackedComm::new(res_id, self.tracker.clone())
    }

    pub fn mul_comms(&self, other: &TrackedComm<F, PCS>) -> Self {
        self.assert_same_tracker(&other);
        let tracker_ref: &RefCell<VerifierTracker<F, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref
            .borrow_mut()
            .mul_comms(self.id.clone(), other.id.clone());
        TrackedComm::new(res_id, self.tracker.clone())
    }

    pub fn add_scalar(&self, c: F) -> TrackedComm<F, PCS> {
        let tracker_ref: &RefCell<VerifierTracker<F, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().add_scalar(self.id.clone(), c);
        TrackedComm::new(res_id, self.tracker.clone())
    }

    pub fn mul_scalar(&self, c: F) -> TrackedComm<F, PCS> {
        let tracker_ref: &RefCell<VerifierTracker<F, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().mul_scalar(self.id.clone(), c);
        TrackedComm::new(res_id, self.tracker.clone())
    }

    pub fn increase_nv_front(&self, added_nv: usize) -> TrackedComm<F, PCS> {
        let tracker_ref: &RefCell<VerifierTracker<F, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref
            .borrow_mut()
            .increase_nv_front(self.id.clone(), added_nv);
        TrackedComm::new(res_id, self.tracker.clone())
    }

    pub fn increase_nv_back(&self, added_nv: usize) -> TrackedComm<F, PCS> {
        let tracker_ref: &RefCell<VerifierTracker<F, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref
            .borrow_mut()
            .increase_nv_back(self.id.clone(), added_nv);
        TrackedComm::new(res_id, self.tracker.clone())
    }

    pub fn eval_virtual_comm(&self, point: &[F]) -> Result<F, PolyIOPErrors> {
        let tracker_ref: &RefCell<VerifierTracker<F, PCS>> = self.tracker.borrow();
        let eval = tracker_ref
            .borrow()
            .eval_virtual_comm(self.id.clone(), point)?;
        Ok(eval)
    }
}
