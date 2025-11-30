use std::{
    hash::Hash,
    sync::{Arc, Weak},
};

use ark_piop::SnarkBackend;
use datafusion_expr::{LogicalPlan, Projection};

use crate::irs::{
    nodes::{IsLpNode, IsNode, IsPlanNode, Node},
    tree::Tree,
};

pub(super) mod hints;

pub struct ProverNode<B>
where
    B: SnarkBackend,
{
    projection: Projection,
    input: Arc<Node<B>>,
    exprs: Vec<Arc<Node<B>>>,
}

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "Projection".to_string()
    }

    fn cost(
        &self,
        statistics: datafusion_common::Statistics,
        schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        let mut out = Vec::with_capacity(1 + self.exprs.len());
        out.push(self.input.clone());
        out.extend(self.exprs.iter().cloned());
        out
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ProverNode<B> {
    fn gadget(&self) -> Arc<Node<B>> {
        todo!()
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        todo!()
    }
}

impl<B: SnarkBackend> IsLpNode<B> for ProverNode<B> {
    fn from_lp(plan: datafusion_expr::LogicalPlan, self_ref: Weak<Node<B>>) -> Self
    where
        Self: Sized,
    {
        let projection = match plan {
            LogicalPlan::Projection(p) => p,
            _ => panic!("expected projection logical plan"),
        };

        // Recurse into the input subtree and fetch the logical plan that feeds this
        // projection.
        let input = Tree::<B>::from_logical_plan(&projection.input)
            .root()
            .clone();
        // Build expression proof plans for the projection expressions (excluding the
        // retained activator).
        let exprs = projection
            .expr
            .iter()
            .map(|expr| {
                Tree::<B>::from_expr(expr, Some(self_ref.clone()))
                    .root()
                    .clone()
            })
            .collect();

        Self {
            projection,
            input,
            exprs,
        }
    }

    fn lp(&self) -> LogicalPlan {
        LogicalPlan::Projection(self.projection.clone())
    }
}
