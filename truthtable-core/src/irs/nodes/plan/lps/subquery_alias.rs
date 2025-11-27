use crate::nodes::{prover::ProverPlanNode, verifier::VerifierNode};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion_expr::SubqueryAlias;
use std::sync::Arc;

pub struct ProverSubqueryAliasNode<B>
where
B:SnarkBackend
{
    input: Arc<dyn ProverPlanNode<B>>,
    subquery_alias: SubqueryAlias,
}
pub struct VerifierSubqueryAliasNode<B>
where
B:SnarkBackend
{
    input: Arc<dyn VerifierNode<B>>,
    subquery_alias: SubqueryAlias,
}
