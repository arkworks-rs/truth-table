use std::sync::{Arc, Weak};

use ark_piop::SnarkBackend;
use datafusion_expr::{LogicalPlan, SubqueryAlias};

use crate::irs::{
    nodes::{IsLpNode, IsNode, IsPlanNode, Node, ProverNodeOps, VerifierNodeOps},
    tree::Tree,
};

pub struct SubqueryAliasNode<B>
where
    B: SnarkBackend,
{
    input: Arc<Node<B>>,
    subquery_alias: SubqueryAlias,
}

impl<B: SnarkBackend> IsNode<B> for SubqueryAliasNode<B> {
    fn name(&self) -> String {
        "Subquery Alias".to_string()
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn initialize_gadget_plans(
        &self,
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        vec![self.input.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for SubqueryAliasNode<B> {
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        todo!()
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for SubqueryAliasNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        None
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("Subquery alias input cannot be a gadget node"),
        };

        let aliased_df = input_hint_df
            .data_frame()
            .clone()
            .alias(&self.subquery_alias.alias.to_string())
            .expect("subquery alias should succeed");
        let aliased_df = crate::irs::nodes::hints::sort_by_row_id_if_present(aliased_df)
            .expect("subquery alias output sort should succeed");
        crate::irs::nodes::hints::HintDF::new_virtual(aliased_df)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for SubqueryAliasNode<B> {
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        todo!()
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsLpNode<B> for SubqueryAliasNode<B> {
    fn from_lp(plan: datafusion_expr::LogicalPlan, self_ref: Weak<Node<B>>) -> Self
    where
        Self: Sized,
    {
        let subquery_alias =
            if let datafusion_expr::LogicalPlan::SubqueryAlias(subquery_alias) = plan {
                subquery_alias
            } else {
                panic!("Expected LogicalPlan::SubqueryAlias");
            };

        let input = Tree::<B>::from_logical_plan(&subquery_alias.input)
            .root()
            .clone();
        SubqueryAliasNode {
            input,
            subquery_alias,
        }
    }

    fn lp(&self) -> LogicalPlan {
        LogicalPlan::SubqueryAlias(self.subquery_alias.clone())
    }
}
