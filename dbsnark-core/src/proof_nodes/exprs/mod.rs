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

pub mod prover {

    use std::sync::Arc;

    pub use super::{
        aggregate_function::ProverAggregateFunctionExprNode, alias::ProverAliasExprNode,
        between::ProverBetweenExprNode, binary_expr::ProverBinaryExprNode,
        case::ProverCaseExprNode, cast::ProverCastExprNode, column::ProverColumnExprNode,
        exists::ProverExistsExprNode, grouping_set::ProverGroupingSetExprNode,
        in_list::ProverInListExprNode, in_subquery::ProverInSubqueryExprNode,
        is_false::ProverIsFalseExprNode, is_not_false::ProverIsNotFalseExprNode,
        is_not_null::ProverIsNotNullExprNode, is_not_true::ProverIsNotTrueExprNode,
        is_not_unknown::ProverIsNotUnknownExprNode, is_null::ProverIsNullExprNode,
        is_true::ProverIsTrueExprNode, is_unknown::ProverIsUnknownExprNode,
        like::ProverLikeExprNode, literal::ProverLiteralExprNode, negative::ProverNegativeExprNode,
        not::ProverNotExprNode, outer_reference_column::ProverOuterReferenceColumnExprNode,
        placeholder::ProverPlaceholderExprNode, scalar_function::ProverScalarFunctionExprNode,
        scalar_subquery::ProverScalarSubqueryExprNode,
        scalar_variable::ProverScalarVariableExprNode, similar_to::ProverSimilarToExprNode,
        try_cast::ProverTryCastExprNode, unnest::ProverUnnestExprNode,
        wildcard::ProverWildcardExprNode, window_function::ProverWindowFunctionExprNode,
    };
    use crate::proof_nodes::{cost::ProvingCost, id::NodeId, prover::ProverNode};
    use ark_ff::PrimeField;
    use ark_piop::{
        arithmetic::mat_poly::{lde::LDE, mle::MLE},
        errors::SnarkResult,
        pcs::PCS,
    };
    use datafusion::logical_expr::Expr;
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
        fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
            Vec::new()
        }

        fn node_id(&self) -> NodeId {
            NodeId::Expr(self.relative_expr.clone())
        }

        fn from_expr(
            ctx: &datafusion::prelude::SessionContext,
            _prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
            expr: Expr,
            parent_node_id: NodeId,
        ) -> Self
        where
            Self: Sized,
        {
            todo!()
        }

        fn cost(
            &self,
            _statistics: datafusion::common::Statistics,
            _schema: datafusion::arrow::datatypes::SchemaRef,
        ) -> ProvingCost {
            todo!()
        }

        fn add_virtual_witness(
            &self,
            piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
            _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
        ) {
            todo!()
        }
        fn prove_piop(
            &self,
            _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
            _piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
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
}

pub mod verifier {
    use std::sync::Arc;

    pub use super::{
        aggregate_function::VerifierAggregateFunctionExprNode, alias::VerifierAliasExprNode,
        between::VerifierBetweenExprNode, binary_expr::VerifierBinaryExprNode,
        case::VerifierCaseExprNode, cast::VerifierCastExprNode, column::VerifierColumnExprNode,
        exists::VerifierExistsExprNode, grouping_set::VerifierGroupingSetExprNode,
        in_list::VerifierInListExprNode, in_subquery::VerifierInSubqueryExprNode,
        is_false::VerifierIsFalseExprNode, is_not_false::VerifierIsNotFalseExprNode,
        is_not_null::VerifierIsNotNullExprNode, is_not_true::VerifierIsNotTrueExprNode,
        is_not_unknown::VerifierIsNotUnknownExprNode, is_null::VerifierIsNullExprNode,
        is_true::VerifierIsTrueExprNode, is_unknown::VerifierIsUnknownExprNode,
        like::VerifierLikeExprNode, literal::VerifierLiteralExprNode,
        negative::VerifierNegativeExprNode, not::VerifierNotExprNode,
        outer_reference_column::VerifierOuterReferenceColumnExprNode,
        placeholder::VerifierPlaceholderExprNode, scalar_function::VerifierScalarFunctionExprNode,
        scalar_subquery::VerifierScalarSubqueryExprNode,
        scalar_variable::VerifierScalarVariableExprNode, similar_to::VerifierSimilarToExprNode,
        try_cast::VerifierTryCastExprNode, unnest::VerifierUnnestExprNode,
        wildcard::VerifierWildcardExprNode, window_function::VerifierWindowFunctionExprNode,
    };
    use crate::proof_nodes::{id::NodeId, verifier::VerifierNode};
    use ark_ff::PrimeField;
    use ark_piop::{
        arithmetic::mat_poly::{lde::LDE, mle::MLE},
        errors::SnarkResult,
        pcs::PCS,
    };
    use datafusion::logical_expr::Expr;

    #[derive(Clone)]
    pub struct RawExprNode {
        relative_expr: Expr,
    }

    impl RawExprNode {
        pub fn new(relative_expr: Expr) -> Self {
            Self { relative_expr }
        }
    }

    impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for RawExprNode
    where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>> + 'static,
        UvPCS: PCS<F, Poly = LDE<F>> + 'static,
    {
        fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
            Vec::new()
        }

        fn node_id(&self) -> NodeId {
            NodeId::Expr(self.relative_expr.clone())
        }

        fn from_expr(
            ctx: &datafusion::prelude::SessionContext,
            _verifier_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
            expr: Expr,
            parent_node_id: NodeId,
        ) -> Self
        where
            Self: Sized,
        {
            todo!()
        }

        fn add_virtual_witness(
            &self,
            piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
            _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        ) {
            todo!()
        }
        fn verify_piop(
            &self,
            _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
            _piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
        ) -> SnarkResult<()> {
            todo!()
        }
    }

    pub fn wrap_logical_expr<F, MvPCS, UvPCS>(expr: Expr) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>>
    where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>> + 'static,
        UvPCS: PCS<F, Poly = LDE<F>> + 'static,
    {
        Arc::new(RawExprNode::new(expr))
    }
}
