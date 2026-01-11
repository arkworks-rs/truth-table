use std::sync::{Arc, Weak};

use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME, table_oracle::TrackedTableOracle};
use ark_piop::SnarkBackend;
use datafusion_expr::{Join, LogicalPlan};
use indexmap::IndexMap;

use crate::irs::{
    nodes::{IsLpNode, IsNode, IsPlanNode, Node, ProverNodeOps, VerifierNodeOps},
    payloads::PayloadStructure,
    tree::Tree,
};

#[allow(clippy::type_complexity)]
pub struct JoinNode<B>
where
    B: SnarkBackend,
{
    left: Arc<Node<B>>,
    right: Arc<Node<B>>,
    on: Vec<(Arc<Node<B>>, Arc<Node<B>>)>,
    filter: Option<Arc<Node<B>>>,
    join: Join,
}

impl<B: SnarkBackend> IsNode<B> for JoinNode<B> {
    fn name(&self) -> String {
        "Join".to_string()
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
        todo!()
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for JoinNode<B> {
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

impl<B: SnarkBackend> IsPlanNode<B> for JoinNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        None
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        todo!()
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for JoinNode<B> {
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

impl<B: SnarkBackend> IsLpNode<B> for JoinNode<B> {
    fn from_lp(plan: datafusion_expr::LogicalPlan, self_ref: Weak<Node<B>>) -> Self
    where
        Self: Sized,
    {
        let join = if let datafusion_expr::LogicalPlan::Join(join) = plan {
            join
        } else {
            panic!("Expected Join LogicalPlan");
        };
        let left = Tree::<B>::from_logical_plan(&join.left).root().clone();
        let right = Tree::<B>::from_logical_plan(&join.right).root().clone();
        let on = join
            .on
            .iter()
            .map(|(l, r)| {
                let left_node = Tree::<B>::from_expr(l, Some(self_ref.clone()), left.clone())
                    .root()
                    .clone();
                let right_node = Tree::<B>::from_expr(r, Some(self_ref.clone()), right.clone())
                    .root()
                    .clone();
                (left_node, right_node)
            })
            .collect();
        let filter = join.filter.as_ref().map(|expr| {
            Tree::<B>::from_expr(expr, Some(self_ref.clone()), left.clone())
                .root()
                .clone()
        });
        JoinNode {
            left,
            right,
            on,
            filter,
            join,
        }
    }

    fn lp(&self) -> LogicalPlan {
        LogicalPlan::Join(self.join.clone())
    }
}
