use std::marker::PhantomData;
use std::sync::Arc;

use crate::proof_nodes::HintGenerationPlan;
use crate::proof_nodes::tree::NodeId;
use crate::proof_nodes::{
    prover::{ProverGadgetNode, ProverPlanNode},
    verifier::VerifierNode,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    prover::Prover,
    verifier::Verifier,
};
use datafusion::{arrow::datatypes::SchemaRef, common::Statistics, prelude::DataFrame};
use indexmap::IndexMap;
#[derive(Clone)]
pub struct ProverSupportGadget<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    node_id: NodeId,
    _marker: PhantomData<(F, MvPCS, UvPCS)>,
}
