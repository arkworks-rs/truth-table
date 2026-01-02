use std::sync::Arc;

use ark_piop::SnarkBackend;
use datafusion_expr::{Aggregate, LogicalPlan};

use crate::irs::{
    nodes::{IsLpNode, IsNode, IsPlanNode, Node, ProverNodeOps, VerifierNodeOps},
    tree::Tree,
};

mod hints;

pub struct ProverAggregateNode<B>
where
    B: SnarkBackend,
{
    // The aggregate information from DataFusion.
    aggregate: Aggregate,
    // The prover plan child node for the aggregate input.
    input: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for ProverAggregateNode<B> {
    fn name(&self) -> String {
        "Aggregate".to_string()
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.input.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ProverAggregateNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ProverAggregateNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        None
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("Aggregate input cannot be a gadget node"),
        };

        let output = hints::build_output_dataframe(input_hint_df.data_frame(), &self.aggregate);
        crate::irs::nodes::hints::HintDF::new_materialized(output)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ProverAggregateNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsLpNode<B> for ProverAggregateNode<B> {
    fn from_lp(plan: LogicalPlan, _self_ref: std::sync::Weak<Node<B>>) -> Self
    where
        Self: Sized,
    {
        let aggregate = match plan {
            LogicalPlan::Aggregate(p) => p,
            _ => panic!("expected aggregate logical plan"),
        };

        let input = Tree::<B>::from_logical_plan(&aggregate.input)
            .root()
            .clone();

        Self { aggregate, input }
    }

    fn lp(&self) -> LogicalPlan {
        LogicalPlan::Aggregate(self.aggregate.clone())
    }
}
