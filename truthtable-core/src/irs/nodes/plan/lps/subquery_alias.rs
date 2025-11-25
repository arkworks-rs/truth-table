use crate::nodes::{prover::ProverPlanNode, verifier::VerifierNode};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion_expr::SubqueryAlias;
use std::sync::Arc;

pub struct ProverSubqueryAliasNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    input: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    subquery_alias: SubqueryAlias,
}
pub struct VerifierSubqueryAliasNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    input: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    subquery_alias: SubqueryAlias,
}
