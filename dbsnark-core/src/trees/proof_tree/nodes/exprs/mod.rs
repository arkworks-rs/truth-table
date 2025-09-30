use std::sync::Arc;

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
};
use datafusion::logical_expr::Expr;

use crate::trees::proof_tree::nodes::{ProverNode, ProverNodeNodeId};

pub mod aggregate_function;
pub mod alias;
pub mod between;
pub mod binary_expr;
pub mod case;
pub mod cast;
pub mod column;
pub mod exists;
pub mod grouping_set;
pub mod in_list;
pub mod in_subquery;
pub mod is_false;
pub mod is_not_false;
pub mod is_not_null;
pub mod is_not_true;
pub mod is_not_unknown;
pub mod is_null;
pub mod is_true;
pub mod is_unknown;
pub mod like;
pub mod literal;
pub mod negative;
pub mod not;
pub mod outer_reference_column;
pub mod placeholder;
pub mod scalar_function;
pub mod scalar_subquery;
pub mod scalar_variable;
pub mod similar_to;
pub mod try_cast;
pub mod unnest;
pub mod wildcard;
pub mod window_function;

pub use aggregate_function::AggregateFunctionExprNode;
pub use alias::AliasExprNode;
pub use between::BetweenExprNode;
pub use binary_expr::BinaryExprNode;
pub use case::CaseExprNode;
pub use cast::CastExprNode;
pub use column::ColumnExprNode;
pub use exists::ExistsExprNode;
pub use grouping_set::GroupingSetExprNode;
pub use in_list::InListExprNode;
pub use in_subquery::InSubqueryExprNode;
pub use is_false::IsFalseExprNode;
pub use is_not_false::IsNotFalseExprNode;
pub use is_not_null::IsNotNullExprNode;
pub use is_not_true::IsNotTrueExprNode;
pub use is_not_unknown::IsNotUnknownExprNode;
pub use is_null::IsNullExprNode;
pub use is_true::IsTrueExprNode;
pub use is_unknown::IsUnknownExprNode;
pub use like::LikeExprNode;
pub use literal::LiteralExprNode;
pub use negative::NegativeExprNode;
pub use not::NotExprNode;
pub use outer_reference_column::OuterReferenceColumnExprNode;
pub use placeholder::PlaceholderExprNode;
pub use scalar_function::ScalarFunctionExprNode;
pub use scalar_subquery::ScalarSubqueryExprNode;
pub use scalar_variable::ScalarVariableExprNode;
pub use similar_to::SimilarToExprNode;
pub use try_cast::TryCastExprNode;
pub use unnest::UnnestExprNode;
pub use wildcard::WildcardExprNode;
pub use window_function::WindowFunctionExprNode;

#[derive(Clone)]
pub struct RawExprNode {
    relative_expr: Expr,
}

impl RawExprNode {
    pub fn new(relative_expr: Expr) -> Self {
        Self { relative_expr }
    }
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for RawExprNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn node_id(&self) -> ProverNodeNodeId {
        ProverNodeNodeId::Expr(self.relative_expr.clone())
    }

    fn from_expr(
        ctx: &datafusion::prelude::SessionContext,
        expr: Expr,
        parent_logical_plan: datafusion::logical_expr::LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        todo!()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut crate::trees::piop_tree::PIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }
    fn prove_piop(
        &self,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::trees::piop_tree::PIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        todo!()
    }
}

pub fn wrap_logical_expr<F, MvPCS, UvPCS>(expr: Expr) -> Arc<dyn ProverNode<F, MvPCS, UvPCS>>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    Arc::new(RawExprNode::new(expr))
}
