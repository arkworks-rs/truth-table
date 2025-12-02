use std::sync::Arc;

use arithmetic::ACTIVATOR_EXPR;
use ark_piop::SnarkBackend;
use datafusion_common::ScalarValue;
use datafusion_expr::{Expr, lit};

use crate::irs::nodes::{IsExprNode, IsNode, IsPlanNode, Node};
pub struct ProverNode<B: SnarkBackend> {
    pub literal: ScalarValue,
    pub scope: Arc<Node<B>>,
}
impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "Literal".to_string()
    }

    fn cost(
        &self,
        statistics: datafusion_common::Statistics,
        schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<crate::irs::nodes::Node<B>>> {
        vec![]
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ProverNode<B> {
    fn gadget(&self) -> std::sync::Arc<crate::irs::nodes::Node<B>> {
        todo!()
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        // Produce a virtual DataFrame with the literal and activator columns from the scope.
        let scope_hint_df = match self.scope().as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("Literal scope cannot be a gadget node"),
        };

        let projected = scope_hint_df
            .data_frame()
            .clone()
            .select(vec![lit(self.literal.clone()), ACTIVATOR_EXPR.clone()])
            .expect("literal projection should succeed");

        crate::irs::nodes::hints::HintDF::new_virtual(projected)
    }
}

impl<B: SnarkBackend> IsExprNode<B> for ProverNode<B> {
    fn from_expr(
        _expr: datafusion_expr::Expr,
        _self_ref: std::sync::Weak<crate::irs::nodes::Node<B>>,
        _parent: Option<std::sync::Weak<crate::irs::nodes::Node<B>>>,
        scope: std::sync::Arc<crate::irs::nodes::Node<B>>,
    ) -> Self
    where
        Self: Sized,
    {
        let literal = match _expr {
            datafusion_expr::Expr::Literal(scalar_value) => scalar_value,
            _ => panic!("Expected Expr::Literal"),
        };
        Self { literal, scope }
    }

    fn expr(&self) -> datafusion_expr::Expr {
        Expr::Literal(self.literal.clone())
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
