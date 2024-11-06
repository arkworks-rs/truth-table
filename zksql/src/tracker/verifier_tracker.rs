/// The Tracker is a data structure for creating and managing virtual commnomials and their commitments.
/// It is in charge of  
///                      1) Recording the structure of virtual commnomials and their products
///                      2) Recording the structure of virtual commnomials and their products
///                      3) Recording the commitments of virtual commnomials and their products
///                      4) Providing methods for adding virtual commnomials together
/// 
/// 

use std::{
    borrow::Borrow,
    cell::RefCell,
    collections::HashMap,
    rc::Rc,
};

use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalSerialize;
use ark_std::Zero;

use crate::tracker::errors::PolyIOPErrors;
use crate::tracker::tracker_structs::{TrackerID, CompiledZKSQLProof, TrackerSumcheckClaim, TrackerZerocheckClaim};
use crate::tracker::dmle_utils::eq_eval;

use derivative::Derivative;
use displaydoc::Display;

use crate::subroutines::{PolyIOP, PolynomialCommitmentScheme};
use crate::subroutines::poly_iop::prelude::SumCheck;

use crate::transcript::{IOPTranscript, TranscriptError};

#[derive(Derivative, Display)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct VerifierTracker<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub pcs_params: PCS::VerifierParam,
    pub transcript: IOPTranscript<E::ScalarField>,
    pub id_counter: usize,
    pub materialized_comms: HashMap<TrackerID, PCS::Commitment>, // map from id to Commitment
    pub virtual_comms: Rc<RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>>>, // id -> eval_fn
    pub query_map: Rc<RefCell<HashMap<(TrackerID, Vec<E::ScalarField>), E::ScalarField>>>, // (poly_id, point) -> eval
    pub sum_check_claims: Vec<TrackerSumcheckClaim<E::ScalarField>>,
    pub zero_check_claims: Vec<TrackerZerocheckClaim<E::ScalarField>>,
    pub proof: CompiledZKSQLProof<E, PCS>,
}

impl<E: Pairing, PCS: PolynomialCommitmentScheme<E>> VerifierTracker<E, PCS> {
    pub fn new(pcs_params: PCS::VerifierParam) -> Self {
        Self {
            pcs_params,
            transcript: IOPTranscript::<E::ScalarField>::new(b"Initializing Tracnscript"),
            id_counter: 0,
            materialized_comms: HashMap::new(),
            virtual_comms: Rc::new(RefCell::new(HashMap::new())),
            query_map: Rc::new(RefCell::new(HashMap::new())),
            sum_check_claims: Vec::new(),
            zero_check_claims: Vec::new(),
            proof: CompiledZKSQLProof::default(),
        }
    }

    pub fn gen_id(&mut self) -> TrackerID {
        let id = self.id_counter;
        self.id_counter += 1;
        TrackerID(id)
    }

    pub fn get_next_id(&mut self) -> TrackerID {
        TrackerID(self.id_counter)
    }

    pub fn track_mat_comm(&mut self, comm: PCS::Commitment) -> Result<TrackerID, PolyIOPErrors> {
        // Create the new TrackerID
        let id = self.gen_id();
        
        // create the virtual commitment for the interaction and decision phases
        let query_map_clone = self.query_map.clone(); // need to clone so the new copy can be moved into the closure
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = self.virtual_comms.borrow();
        virtual_comms_ref_cell.borrow_mut().insert(
            id.clone(), 
            Box::new(move |point: &[E::ScalarField]| {
                let query_map_ref_cell: &RefCell<HashMap<(TrackerID, Vec<E::ScalarField>), E::ScalarField>> = query_map_clone.borrow();
                let query_map = query_map_ref_cell.borrow();
                let query_res = query_map.get(&(id.clone(), point.to_vec())).unwrap();
                Ok(query_res.clone())
            })
        );

        // add the commitment to the transcript and store it in the materialized comms map
        self.transcript.append_serializable_element(b"comm", &comm)?;
        self.materialized_comms.insert(id.clone(), comm);

        // return the new TrackerID
        Ok(id)
    }

    pub fn track_virtual_comm(
        &mut self, 
        eval_fn: Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>,
    ) -> TrackerID {
        let id = self.gen_id();
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = self.virtual_comms.borrow();
        virtual_comms_ref_cell.borrow_mut().insert(
            id.clone(), 
            eval_fn,
        );
        id
    }

    pub fn set_compiled_proof(&mut self, proof: CompiledZKSQLProof<E, PCS>) {
        self.proof = proof;
    }

    pub fn get_mat_comm(&self, id: TrackerID) -> Option<&PCS::Commitment> {
        self.materialized_comms.get(&id)
    }
    
    pub fn add_comms(
        &mut self, 
        c1_id: TrackerID, 
        c2_id: TrackerID
    ) -> TrackerID {
        // Create the new TrackerID
        let id = self.gen_id();
        
        // Create the new evaluation function using the retrieved references and 
        // insert the new evaluation function into the virtual comms map
        let virtual_comms_clone = self.virtual_comms.clone(); // need to clone so the new copy can be moved into the closure
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = self.virtual_comms.borrow();
        virtual_comms_ref_cell.borrow_mut().insert(
            id.clone(), 
            Box::new(
                move |point: &[E::ScalarField]| {
                    let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = virtual_comms_clone.borrow();
                    let virtual_comms = virtual_comms_ref_cell.borrow();
                    let c1_eval_box: &Box<dyn Fn(&[<E as Pairing>::ScalarField]) -> Result<<E as Pairing>::ScalarField, PolyIOPErrors>> = virtual_comms.get(&c1_id).unwrap();
                    let c1_eval: <E as Pairing>::ScalarField = c1_eval_box(point)?;
                    let c2_eval_box = virtual_comms.get(&c2_id).unwrap();
                    let c2_eval: <E as Pairing>::ScalarField = c2_eval_box(point)?;
                    let new_eval: <E as Pairing>::ScalarField = c1_eval + c2_eval; // add the scalars
                    Ok(new_eval)
                }
            ),
        );
                
        id
    }

    pub fn sub_comms(
        &mut self, 
        c1_id: TrackerID, 
        c2_id: TrackerID
    ) -> TrackerID {
        let id = self.gen_id();
        let virtual_comms_clone = self.virtual_comms.clone(); // need to clone so the new copy can be moved into the closure
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = self.virtual_comms.borrow();
        virtual_comms_ref_cell.borrow_mut().insert(
            id.clone(), 
            Box::new(
                move |point: &[E::ScalarField]| {
                    let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = virtual_comms_clone.borrow();
                    let virtual_comms = virtual_comms_ref_cell.borrow();
                    let c1_eval_box: &Box<dyn Fn(&[<E as Pairing>::ScalarField]) -> Result<<E as Pairing>::ScalarField, PolyIOPErrors>> = virtual_comms.get(&c1_id).unwrap();
                    let c1_eval: <E as Pairing>::ScalarField = c1_eval_box(point)?;
                    let c2_eval_box = virtual_comms.get(&c2_id).unwrap();
                    let c2_eval: <E as Pairing>::ScalarField = c2_eval_box(point)?;
                    Ok(c1_eval - c2_eval)
                }
            ),
        );
        id
    }

    pub fn mul_comms(
        &mut self, 
        c1_id: TrackerID, 
        c2_id: TrackerID
    ) -> TrackerID {
        let id = self.gen_id();
        let virtual_comms_clone = self.virtual_comms.clone(); // need to clone so the new copy can be moved into the closure
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = self.virtual_comms.borrow();
        virtual_comms_ref_cell.borrow_mut().insert(
            id.clone(), 
            Box::new(
                move |point: &[E::ScalarField]| {
                    let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = virtual_comms_clone.borrow();
                    let virtual_comms = virtual_comms_ref_cell.borrow();
                    let c1_eval_box = virtual_comms.get(&c1_id).unwrap();
                    let c1_eval: <E as Pairing>::ScalarField = c1_eval_box(point)?;
                    let c2_eval_box = virtual_comms.get(&c2_id).unwrap();
                    let c2_eval: <E as Pairing>::ScalarField = c2_eval_box(point)?;
                    let new_eval: <E as Pairing>::ScalarField = c1_eval * c2_eval; // mul the scalars
                    Ok(new_eval)
                }
            ),
        );
                
        id
    }

    pub fn add_scalar(
        &mut self, 
        poly_id: TrackerID, 
        c: E::ScalarField
    ) -> TrackerID {
        let _ = self.gen_id(); // burn a tracker id to match how prover_tracker::add_scalar works
        let id = self.gen_id();
        let virtual_comms_clone = self.virtual_comms.clone(); // need to clone so the new copy can be moved into the closure
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = self.virtual_comms.borrow();
        virtual_comms_ref_cell.borrow_mut().insert(
            id.clone(), 
            Box::new(
                move |point: &[E::ScalarField]| {
                    let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = virtual_comms_clone.borrow();
                    let virtual_comms = virtual_comms_ref_cell.borrow();
                    let poly_eval_box = virtual_comms.get(&poly_id).unwrap();
                    let poly_eval: <E as Pairing>::ScalarField = poly_eval_box(point)?;
                    let new_eval: <E as Pairing>::ScalarField = poly_eval + c; // c + old eval
                    Ok(new_eval)
                }
            ),
        );
        id
    }

    pub fn mul_scalar(
        &mut self, 
        poly_id: TrackerID, 
        c: E::ScalarField
    ) -> TrackerID {
        let id = self.gen_id();
        let virtual_comms_clone = self.virtual_comms.clone(); // need to clone so the new copy can be moved into the closure
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = self.virtual_comms.borrow();
        virtual_comms_ref_cell.borrow_mut().insert(
            id.clone(), 
            Box::new(
                move |point: &[E::ScalarField]| {
                    let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = virtual_comms_clone.borrow();
                    let virtual_comms = virtual_comms_ref_cell.borrow();
                    let poly_eval_box = virtual_comms.get(&poly_id).unwrap();
                    let poly_eval: <E as Pairing>::ScalarField = poly_eval_box(point)?;
                    let new_eval: <E as Pairing>::ScalarField = c.clone() * poly_eval; // c * old eval
                    Ok(new_eval)
                }
            ),
        );
                
        id
    }

    /// creates a new virtual comm that evaluates on an increased nv by adding variables at the front
    /// adds the new variables at the front of the polynomial, 
    /// and ignores the first 'added_nv' variables when evaluating the polynomial at a point
    pub fn increase_nv_front(&mut self, poly_id: TrackerID, added_nv: usize) -> TrackerID {
        let virtual_comms_clone = self.virtual_comms.clone(); // need to clone so the new copy can be moved into the closure
        let res_closure = move |pt: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {
            // get the eval function for poly_id
            let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = virtual_comms_clone.borrow();
            let virtual_comms = virtual_comms_ref_cell.borrow();
            let poly_eval_box = virtual_comms.get(&poly_id).unwrap();

            // evaluate the polynomial at the point, ignoring the first added_nv coordinates
            let truncated_pt = &pt[added_nv..];
            let poly_eval: <E as Pairing>::ScalarField = poly_eval_box(truncated_pt)?;
            Ok(poly_eval)
        };
        // create the new res_comm that uses the res_closure
        let res_id = self.track_virtual_comm(Box::new(res_closure));
        res_id
    }

    /// creates a new virtual comm that evaluates on an increased nv by adding variables at the back
    /// adds the new variables at the back of the polynomial, 
    /// and ignores the last 'added_nv' variables when evaluating the polynomial at a point
    pub fn increase_nv_back(&mut self, poly_id: TrackerID, added_nv: usize) -> TrackerID {
        let virtual_comms_clone = self.virtual_comms.clone(); // need to clone so the new copy can be moved into the closure
        let res_closure = move |pt: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {
            // get the eval function for poly_id
            let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = virtual_comms_clone.borrow();
            let virtual_comms = virtual_comms_ref_cell.borrow();
            let poly_eval_box = virtual_comms.get(&poly_id).unwrap();

            // evaluate the polynomial at the point, ignoring the last added_nv coordinates
            let truncated_pt = &pt[..added_nv];
            let poly_eval: <E as Pairing>::ScalarField = poly_eval_box(truncated_pt)?;
            Ok(poly_eval)
        };
        // create the new res_comm that uses the res_closure
        let res_id = self.track_virtual_comm(Box::new(res_closure));
        res_id
    }

    pub fn eval_virtual_comm( 
        &self, 
        comm_id: TrackerID, 
        point: &[E::ScalarField],
    ) -> Result<E::ScalarField, PolyIOPErrors> {
        let virtual_comms_ref_cell: &RefCell<HashMap<TrackerID, Box<dyn Fn(&[E::ScalarField]) -> Result<E::ScalarField, PolyIOPErrors>>>> = self.virtual_comms.borrow();
        let virtual_comms = virtual_comms_ref_cell.borrow();
        let comm_box = virtual_comms.get(&comm_id).unwrap();
        let eval = comm_box(point)?;
        Ok(eval)
    }

    pub fn get_and_append_challenge(&mut self, label: &'static [u8]) -> Result<E::ScalarField, TranscriptError> {
        self.transcript.get_and_append_challenge(label)
    }

    pub fn append_serializable_element<S: CanonicalSerialize>(
        &mut self,
        label: &'static [u8],
        group_elem: &S,
    ) -> Result<(), TranscriptError> {
        self.transcript.append_serializable_element(label, group_elem)
    }

    pub fn add_sumcheck_claim(&mut self, poly_id: TrackerID, claimed_sum: E::ScalarField) {
        self.sum_check_claims.push(TrackerSumcheckClaim::new(poly_id, claimed_sum));
    }
    pub fn add_zerocheck_claim(&mut self, poly_id: TrackerID) {
        self.zero_check_claims.push(TrackerZerocheckClaim::new(poly_id));
    }

    pub fn get_prover_comm(&self, id: TrackerID) -> Option<&PCS::Commitment> { 
        self.proof.comms.get(&id) 
    }

    pub fn get_prover_claimed_sum(&self, id: TrackerID) -> Option<&E::ScalarField> {
        self.proof.sumcheck_claims.get(&id)
    }

    pub fn transfer_proof_poly_evals(&mut self) {
        let query_map_ref_cell: &RefCell<HashMap<(TrackerID, Vec<E::ScalarField>), E::ScalarField>> = self.query_map.borrow();
        let mut query_map = query_map_ref_cell.borrow_mut();
        for (key, value) in &self.proof.query_map {
            query_map.insert(key.clone(), value.clone());
        }
    }

    fn convert_zerocheck_claims_to_sumcheck_claim(&mut self, nv: usize) {
        // 1)   aggregate the zerocheck claims into a single MLE
        let zero_closure = |_: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {Ok(E::ScalarField::zero())};
        let mut zerocheck_agg_comm = self.track_virtual_comm(Box::new(zero_closure));
        let zero_check_claims = self.zero_check_claims.clone();
        for claim in zero_check_claims {
            let challenge = self.get_and_append_challenge(b"zerocheck challenge").unwrap();
            let claim_poly_id = self.mul_scalar(claim.label.clone(), challenge);
            zerocheck_agg_comm = self.add_comms(zerocheck_agg_comm, claim_poly_id);
        }

        // sample r
        let r = self.transcript.get_and_append_challenge_vectors(b"0check r", nv).unwrap();
        
        // create the succint eq(x, r) closure and virtual comm
        let eq_x_r_closure = move |pt: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {
            Ok(eq_eval(pt, r.as_ref())?)
        };
        let eq_x_r_comm = self.track_virtual_comm(Box::new(eq_x_r_closure));

        // create the relevant sumcheck claim
        let new_sc_claim_comm = self.mul_comms(zerocheck_agg_comm, eq_x_r_comm); // Note: SumCheck val should be zero
        self.add_sumcheck_claim(new_sc_claim_comm, E::ScalarField::zero());
    }

    pub fn verify_claims(&mut self) -> Result<(), PolyIOPErrors> {
        let nv = self.proof.sc_aux_info.num_variables;

        // aggregate zerocheck claims into a single sumcheck claim
        self.convert_zerocheck_claims_to_sumcheck_claim(nv); // Note: SumCheck val should be zero

        // aggregate the sumcheck claims
        let zero_closure = |_: &[E::ScalarField]| -> Result<<E as Pairing>::ScalarField, PolyIOPErrors> {Ok(E::ScalarField::zero())};
        let mut sumcheck_comm = self.track_virtual_comm(Box::new(zero_closure));
        let mut sc_sum = E::ScalarField::zero();
        for claim in self.sum_check_claims.clone().iter() {
            let challenge = self.get_and_append_challenge(b"sumcheck challenge").unwrap();
            let claim_times_challenge_id = self.mul_scalar(claim.label.clone(), challenge);
            sumcheck_comm = self.add_comms(sumcheck_comm, claim_times_challenge_id);
            sc_sum += claim.claimed_sum * challenge;
        };

        // verify the sumcheck proof
        let iop_verify_res = <PolyIOP<E::ScalarField> as SumCheck<E::ScalarField>>::verify(sc_sum, &self.proof.sc_proof, &self.proof.sc_aux_info, &mut self.transcript);
        if iop_verify_res.is_err() {
            return Err(PolyIOPErrors::InvalidVerifier(iop_verify_res.err().unwrap().to_string()));
        }
        let iop_verify_subclaim = iop_verify_res.unwrap();

        // verify the batch pcs proof
        let sumcheck_point = iop_verify_subclaim.point.clone();
        let mut comm_ids = self.proof.comms.keys().cloned().collect::<Vec<TrackerID>>();
        comm_ids.sort(); // sort so the transcript is generated consistently
        let comms = comm_ids.iter().map(|id| self.get_mat_comm(*id).unwrap().clone()).collect::<Vec<PCS::Commitment>>();
        let points = vec![sumcheck_point.clone(); comm_ids.len()];
        let batch_proof = self.proof.pcs_proof[0].clone();
        let pcs_verify_res = PCS::batch_verify(&self.pcs_params, &comms, points.as_slice(), &batch_proof, &mut self.transcript);
        pcs_verify_res?;

        Ok(())
    }
}