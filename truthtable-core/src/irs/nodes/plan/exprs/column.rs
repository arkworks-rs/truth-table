use ark_piop::SnarkBackend;
use datafusion::parquet::column;
use datafusion_common::{Column, Statistics};

use crate::irs::nodes::{IsExprNode, IsNode, IsPlanNode, Node};

#[derive(Debug)]
pub struct ProverNode {
    pub column: Column,
}

impl<B: SnarkBackend> IsNode<B> for ProverNode {
    fn name(&self) -> String {
        "Column".to_string()
    }

    fn cost(
        &self,
        statistics: Statistics,
        schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![]
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ProverNode {
    fn gadget(&self) -> std::sync::Arc<Node<B>> {
        todo!()
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        todo!()
    }
}

impl<B: SnarkBackend> IsExprNode<B> for ProverNode {
    fn from_expr(
        _expr: datafusion_expr::Expr,
        self_ref: std::sync::Weak<Node<B>>,
        parent: Option<std::sync::Weak<Node<B>>>,
    ) -> Self
    where
        Self: Sized,
    {
        let column = match _expr {
            datafusion_expr::Expr::Column(col) => col,
            _ => panic!("Expected Column expression"),
        };
        Self { column }
    }

    fn expr(&self) -> datafusion_expr::Expr {
        todo!()
    }

    fn parent(&self) -> crate::irs::nodes::PlanNode<B>
    where
        Self: Sized,
    {
        todo!()
    }
}
