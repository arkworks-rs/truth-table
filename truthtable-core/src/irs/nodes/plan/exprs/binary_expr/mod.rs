use std::sync::Arc;

use arithmetic::ACTIVATOR_EXPR;
use ark_piop::SnarkBackend;
use datafusion_expr::{BinaryExpr, Expr};

use crate::irs::{
    nodes::{IsExprNode, IsNode, IsPlanNode, Node},
    tree::Tree,
};

pub struct ProverNode<B: SnarkBackend> {
    pub binary_expression: BinaryExpr,
    pub left: Arc<Node<B>>,
    pub right: Arc<Node<B>>,
    pub scope: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "BinaryExpr".to_string()
    }

    fn cost(
        &self,
        statistics: datafusion_common::Statistics,
        schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        vec![self.left.clone(), self.right.clone()]
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ProverNode<B> {
    fn gadget(&self) -> Arc<Node<B>> {
        todo!()
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        // Project the binary expression result alongside the activator from the scope.
        let scope_hint_df = match self.scope.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("BinaryExpr scope cannot be a gadget node"),
        };

        let projected = scope_hint_df
            .data_frame()
            .clone()
            .select(vec![
                Expr::BinaryExpr(self.binary_expression.clone()),
                ACTIVATOR_EXPR.clone(),
            ])
            .expect("binary expression projection should succeed");

        crate::irs::nodes::hints::HintDF::new_virtual(projected)
    }
}

impl<B: SnarkBackend> IsExprNode<B> for ProverNode<B> {
    fn from_expr(
        _expr: datafusion_expr::Expr,
        self_ref: std::sync::Weak<Node<B>>,
        parent: Option<std::sync::Weak<Node<B>>>,
        scope: std::sync::Arc<Node<B>>,
    ) -> Self
    where
        Self: Sized,
    {
        let binary_expression = match _expr {
            datafusion_expr::Expr::BinaryExpr(bin_expr) => bin_expr,
            _ => panic!("Expected Expr::BinaryExpr"),
        };

        // Recurse into the left and right expressions to build their nodes.
        let left = Tree::<B>::from_expr(
            &binary_expression.left,
            Some(self_ref.clone()),
            scope.clone(),
        )
        .root()
        .clone();
        let right = Tree::<B>::from_expr(
            &binary_expression.right,
            Some(self_ref.clone()),
            scope.clone(),
        )
        .root()
        .clone();

        Self {
            binary_expression,
            left,
            right,
            scope,
        }
    }

    fn expr(&self) -> datafusion_expr::Expr {
        datafusion_expr::Expr::BinaryExpr(self.binary_expression.clone())
    }

    fn parent(&self) -> crate::irs::nodes::PlanNode<B>
    where
        Self: Sized,
    {
        todo!()
    }

    fn scope(&self) -> Arc<Node<B>>
    where
        Self: Sized,
    {
        self.scope.clone()
    }
}
