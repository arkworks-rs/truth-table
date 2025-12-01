use std::{rc::Weak, sync::Arc};

use ark_piop::SnarkBackend;
use datafusion_common::ScalarValue;
use datafusion_expr::Expr;

use crate::irs::nodes::{IsExprNode, IsNode, IsPlanNode, Node, NodeId};
#[derive(Debug)]
pub struct ProverNode {
    pub literal: ScalarValue,
}
impl<B: SnarkBackend> IsNode<B> for ProverNode {
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

impl<B: SnarkBackend> IsPlanNode<B> for ProverNode {
    fn gadget(&self) -> std::sync::Arc<crate::irs::nodes::Node<B>> {
        todo!()
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        todo!()
    }
}

impl<B: SnarkBackend> IsExprNode<B> for ProverNode {
    fn from_expr(
        _expr: datafusion_expr::Expr,
        self_ref: std::sync::Weak<crate::irs::nodes::Node<B>>,
        parent: Option<std::sync::Weak<crate::irs::nodes::Node<B>>>,
    ) -> Self
    where
        Self: Sized,
    {
        let literal = match _expr {
            datafusion_expr::Expr::Literal(scalar_value) => scalar_value,
            _ => panic!("Expected Expr::Literal"),
        };
        Self { literal }
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
}
