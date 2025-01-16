use std::{borrow::Borrow, cell::RefCell, rc::Rc, sync::Arc};

use arithmetic::{ark_ff, ark_poly};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::CanonicalSerialize;
use crypto::{ark_ec, pcs::{self, prelude::PCSError, PolynomialCommitmentScheme}};
use kit::{ark_serialize, derivative};

use arithmetic::mle::virt::VirtualPolynomial;
use transcript::TranscriptError;

use crate::tracker::{
    errors::PolyIOPErrors,
    prover_tracker::ProverTracker,
    tracker_structs::{CompiledZKSQLProof, TrackerID},
};

use derivative::Derivative;

#[derive(Derivative)]
#[derivative(Clone(bound = "PCS: PolynomialCommitmentScheme<F>"))]
pub struct ProverTrackerRef<F: PrimeField, PCS: PolynomialCommitmentScheme<F>>
where
    F: PrimeField,
{
    tracker_rc: Rc<RefCell<ProverTracker<F, PCS>>>,
}
impl<F: Pairing, PCS: PolynomialCommitmentScheme<F>> PartialEq for ProverTrackerRef<F, PCS>
where
    F: PrimeField,
{
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.tracker_rc, &other.tracker_rc)
    }
}

impl<F: PrimeField, PCS: PolynomialCommitmentScheme<F>> ProverTrackerRef<F, PCS>
where
    F: PrimeField,
{
    pub fn new(tracker_rc: Rc<RefCell<ProverTracker<F, PCS>>>) -> Self {
        Self { tracker_rc }
    }

    pub fn new_from_tracker(tracker: ProverTracker<F, PCS>) -> Self {
        Self {
            tracker_rc: Rc::new(RefCell::new(tracker)),
        }
    }
    pub fn new_from_pcs_params(pcs_params: PCS::ProverParam) -> Self {
        Self {
            tracker_rc: Rc::new(RefCell::new(ProverTracker::new(pcs_params))),
        }
    }

    pub fn track_mat_poly(
        &mut self,
        polynomial: DenseMultilinearExtension<F>,
    ) -> TrackedPoly<F, PCS> {
        let tracker_ref_cell: &RefCell<ProverTracker<F, PCS>> = self.tracker_rc.borrow();
        let num_vars = polynomial.num_vars();
        let res_id = tracker_ref_cell.borrow_mut().track_mat_poly(polynomial);
        TrackedPoly::new(res_id, num_vars, self.tracker_rc.clone())
    }

    pub fn track_and_commit_poly(
        &mut self,
        polynomial: DenseMultilinearExtension<F>,
    ) -> Result<TrackedPoly<F, PCS>, PCSError> {
        let tracker_ref_cell: &RefCell<ProverTracker<F, PCS>> = self.tracker_rc.borrow();
        let num_vars = polynomial.num_vars();
        let res_id = tracker_ref_cell
            .borrow_mut()
            .track_and_commit_mat_poly(polynomial)?;
        Ok(TrackedPoly::new(res_id, num_vars, self.tracker_rc.clone()))
    }

    pub fn get_mat_poly(&self, id: TrackerID) -> Arc<DenseMultilinearExtension<F>> {
        let tracker_ref_cell: &RefCell<ProverTracker<F, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow().get_mat_poly(id).unwrap().clone()
    }

    pub fn get_virt_poly(&self, id: TrackerID) -> Vec<(F, Vec<TrackerID>)> {
        let tracker_ref_cell: &RefCell<ProverTracker<F, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow().get_virt_poly(id).unwrap().clone()
    }

    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> Result<F, TranscriptError> {
        let tracker_ref_cell: &RefCell<ProverTracker<F, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell
            .borrow_mut()
            .get_and_append_challenge(label)
    }

    pub fn append_serializable_element<S: CanonicalSerialize>(
        &mut self,
        label: &'static [u8],
        group_elem: &S,
    ) -> Result<(), TranscriptError> {
        let tracker_ref_cell: &RefCell<ProverTracker<F, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell
            .borrow_mut()
            .append_serializable_element(label, group_elem)
    }

    pub fn add_sumcheck_claim(&mut self, poly_id: TrackerID, claimed_sum: F) {
        let tracker_ref_cell: &RefCell<ProverTracker<F, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell
            .borrow_mut()
            .add_sumcheck_claim(poly_id, claimed_sum);
    }

    pub fn add_zerocheck_claim(&mut self, poly_id: TrackerID) {
        let tracker_ref_cell: &RefCell<ProverTracker<F, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().add_zerocheck_claim(poly_id);
    }
    pub fn add_fold_claim(&mut self, folded: TrackerID, poly_ids: &[TrackerID], challs: &[F]) {
        let tracker_ref_cell: &RefCell<ProverTracker<F, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell
            .borrow_mut()
            .add_fold_claim(folded, poly_ids, challs);
    }

    pub fn get_next_id(&mut self) -> TrackerID {
        let tracker_ref_cell: &RefCell<ProverTracker<F, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().get_next_id()
    }

    pub fn compile_proof(&mut self) -> Result<CompiledZKSQLProof<F, PCS>, PolyIOPErrors> {
        let tracker_ref_cell: &RefCell<ProverTracker<F, PCS>> = self.tracker_rc.borrow();
        tracker_ref_cell.borrow_mut().compile_proof()
    }

    // used for testing
    pub fn clone_underlying_tracker(&self) -> ProverTracker<F, PCS> {
        let tracker_ref_cell: &RefCell<ProverTracker<F, PCS>> = self.tracker_rc.borrow();
        let tracker = tracker_ref_cell.borrow();
        (*tracker).clone()
    }

    pub fn deep_copy(&self) -> ProverTrackerRef<F, PCS> {
        let tracker_ref_cell: &RefCell<ProverTracker<F, PCS>> = self.tracker_rc.borrow();
        let tracker = tracker_ref_cell.borrow();
        ProverTrackerRef::new_from_tracker((*tracker).clone())
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "PCS: PolynomialCommitmentScheme<F>"))]
pub struct TrackedPoly<F: PrimeField, PCS: PolynomialCommitmentScheme<F>>
where
    F: PrimeField,
{
    pub id: TrackerID,
    pub num_vars: usize,
    pub tracker: Rc<RefCell<ProverTracker<F, PCS>>>,
}
impl<F: PrimeField, PCS: PolynomialCommitmentScheme<F>> PartialEq for TrackedPoly<F, PCS>
where
    F: PrimeField,
{
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && Rc::ptr_eq(&self.tracker, &other.tracker)
    }
}
impl<F: PrimeField, PCS: PolynomialCommitmentScheme<F>> TrackedPoly<F, PCS>
where
    F: PrimeField,
{
    pub fn new(
        id: TrackerID,
        num_vars: usize,
        tracker: Rc<RefCell<ProverTracker<F, PCS>>>,
    ) -> Self {
        Self {
            id,
            num_vars,
            tracker,
        }
    }

    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    pub fn same_tracker(&self, other: &TrackedPoly<F, PCS>) -> bool {
        Rc::ptr_eq(&self.tracker, &other.tracker)
    }

    pub fn assert_same_tracker(&self, other: &TrackedPoly<F, PCS>) {
        assert!(
            self.same_tracker(other),
            "TrackedPolys are not from the same tracker"
        );
    }

    pub fn add_poly(&self, other: &TrackedPoly<F, PCS>) -> Self {
        self.assert_same_tracker(&other);
        assert_eq!(self.num_vars, other.num_vars);
        let tracker_ref: &RefCell<ProverTracker<F, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref
            .borrow_mut()
            .add_polys(self.id.clone(), other.id.clone());
        TrackedPoly::new(res_id, self.num_vars, self.tracker.clone())
    }

    pub fn sub_poly(&self, other: &TrackedPoly<F, PCS>) -> Self {
        self.assert_same_tracker(&other);
        assert_eq!(self.num_vars, other.num_vars);
        let tracker_ref: &RefCell<ProverTracker<F, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref
            .borrow_mut()
            .sub_polys(self.id.clone(), other.id.clone());
        TrackedPoly::new(res_id, self.num_vars, self.tracker.clone())
    }

    pub fn mul_poly(&self, other: &TrackedPoly<F, PCS>) -> Self {
        self.assert_same_tracker(&other);
        assert_eq!(self.num_vars, other.num_vars);
        let tracker_ref: &RefCell<ProverTracker<F, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref
            .borrow_mut()
            .mul_polys(self.id.clone(), other.id.clone());
        TrackedPoly::new(res_id, self.num_vars, self.tracker.clone())
    }

    pub fn add_scalar(&self, c: F) -> Self {
        let tracker_ref: &RefCell<ProverTracker<F, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().add_scalar(self.id.clone(), c);
        TrackedPoly::new(res_id, self.num_vars, self.tracker.clone())
    }

    pub fn mul_scalar(&self, c: F) -> Self {
        let tracker_ref: &RefCell<ProverTracker<F, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref.borrow_mut().mul_scalar(self.id.clone(), c);
        TrackedPoly::new(res_id, self.num_vars, self.tracker.clone())
    }

    pub fn increase_nv_front(&self, added_nv: usize) -> Self {
        let tracker_ref: &RefCell<ProverTracker<F, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref
            .borrow_mut()
            .increase_nv_front(self.id.clone(), added_nv);
        TrackedPoly::new(res_id, self.num_vars + added_nv, self.tracker.clone())
    }

    pub fn increase_nv_back(&self, added_nv: usize) -> Self {
        let tracker_ref: &RefCell<ProverTracker<F, PCS>> = self.tracker.borrow();
        let res_id = tracker_ref
            .borrow_mut()
            .increase_nv_back(self.id.clone(), added_nv);
        TrackedPoly::new(res_id, self.num_vars + added_nv, self.tracker.clone())
    }

    pub fn evaluate(&self, pt: &[F]) -> Option<F> {
        let tracker_ref: &RefCell<ProverTracker<F, PCS>> = self.tracker.borrow();
        tracker_ref.borrow().evaluate(self.id.clone(), pt)
    }

    pub fn evaluations(&self) -> Vec<F> {
        // note: this has to actually clone the evaluations, which can be expensive
        let tracker_ref: &RefCell<ProverTracker<F, PCS>> = self.tracker.borrow();
        tracker_ref
            .borrow_mut()
            .evaluations(self.id.clone())
            .clone()
    }

    pub fn to_arithmatic_virtual_poly(&self) -> VirtualPolynomial<F> {
        let tracker_ref: &RefCell<ProverTracker<F, PCS>> = self.tracker.borrow();
        tracker_ref
            .borrow()
            .to_arithmatic_virtual_poly(self.id.clone())
    }
}
