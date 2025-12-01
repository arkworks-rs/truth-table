use std::sync::Arc;

use ark_piop::SnarkBackend;
use datafusion_expr::{Filter, LogicalPlan};

use crate::irs::{
    nodes::{IsLpNode, IsNode, IsPlanNode, Node},
    tree::Tree,
};

/// The implementation of a filter node in the prover proof tree.
pub struct ProverNode<B>
where
    B: SnarkBackend,
{
    // The filter information from DataFusion
    filter: Filter,
    // The prover plan children nodes for the Filter expressions
    input: Arc<Node<B>>,
    // The prover predicate expression node for the filter condition
    predicate: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "Filter".to_string()
    }

    fn cost(
        &self,
        statistics: datafusion_common::Statistics,
        schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.input.clone(), self.predicate.clone()]
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
    fn from_lp(_plan: LogicalPlan, self_ref: std::sync::Weak<Node<B>>) -> Self
    where
        Self: Sized,
    {
        let filter = match _plan {
            LogicalPlan::Filter(filter) => filter,
            _ => panic!("Expected LogicalPlan::Filter"),
        };

        // Recurse into the input subtree and fetch the logical plan that feeds this
        // filter.
        let input = Tree::<B>::from_logical_plan(&filter.input).root().clone();

        // Recurse into the input subtree and fetch the expr that feeds this
        // filter.
        let predicate = Tree::<B>::from_expr(&filter.predicate, Some(self_ref))
            .root()
            .clone();
        Self {
            filter,
            input,
            predicate,
        }
    }

    fn lp(&self) -> LogicalPlan {
        LogicalPlan::Filter(self.filter.clone())
    }
}
