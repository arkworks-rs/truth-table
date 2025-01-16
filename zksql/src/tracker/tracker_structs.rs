use std::{collections::HashMap, fmt::Display, marker::PhantomData};

use arithmetic::{ark_ff, mle::virt::VPAuxInfo};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use crypto::{ark_ec, pcs::PolynomialCommitmentScheme};
use derivative::Derivative;
use kit::derivative;
use sumcheck::structs::IOPProof;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TrackerID(pub usize);
impl TrackerID {
    pub fn to_int(self) -> usize {
        self.0
    }
}

impl Display for TrackerID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TrackerSumcheckClaim<F: PrimeField> {
    pub label: TrackerID, // a label refering to a polynomial stored in the tracker
    pub claimed_sum: F,
}

impl<F: PrimeField> TrackerSumcheckClaim<F> {
    pub fn new(label: TrackerID, claimed_sum: F) -> Self {
        Self { label, claimed_sum }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TrackerZerocheckClaim<F: PrimeField> {
    pub label: TrackerID, // a label refering to a polynomial stored in the tracker
    pub phantom: PhantomData<F>,
}

impl<F: PrimeField> TrackerZerocheckClaim<F> {
    pub fn new(label: TrackerID) -> Self {
        Self {
            label,
            phantom: PhantomData::default(),
        }
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<F>"),
    Default(bound = "PCS: PolynomialCommitmentScheme<F>"),
    Debug(bound = "PCS: PolynomialCommitmentScheme<F>")
)]
pub struct CompiledZKSQLProof<F, PCS: PolynomialCommitmentScheme<F>>
where
    F: PrimeField,
{
    /// The commitments to the polynomials in the tracker
    pub comms: HashMap<TrackerID, PCS::Commitment>,
    pub sumcheck_claims: HashMap<TrackerID, F>, // id -> [ sum_{i=0}^n p(i) ]
    pub sc_proof: IOPProof<F>,

    pub sc_aux_info: VPAuxInfo<F>,
    pub query_map: HashMap<(TrackerID, Vec<F>), F>, /* (id, point) -> eval, // id -> p(comm_opening_point) */
    pub pcs_proof: Vec<PCS::BatchProof>,
}
