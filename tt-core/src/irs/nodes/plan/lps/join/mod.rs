use std::sync::{Arc, Weak};

use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME, table_oracle::TrackedTableOracle};
use ark_piop::SnarkBackend;
use datafusion_common::Column;
use datafusion_expr::{Expr, Join, LogicalPlan, SortExpr};
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
        let mut children = vec![self.left.clone(), self.right.clone()];
        if let Some(filter) = &self.filter {
            children.push(filter.clone());
        }
        self.on.iter().for_each(|(l, r)| {
            children.push(l.clone());
            children.push(r.clone());
        });
        children
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
        let left_hint_df = match self.left.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("Join left input cannot be a gadget node"),
        };
        let right_hint_df = match self.right.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("Join right input cannot be a gadget node"),
        };

        let mut join_exprs: Vec<Expr> = self
            .join
            .on
            .iter()
            .map(|(left_expr, right_expr)| left_expr.clone().eq(right_expr.clone()))
            .collect();
        if let Some(filter) = &self.join.filter {
            join_exprs.push(filter.clone());
        }

        let joined = left_hint_df
            .data_frame()
            .clone()
            .join_on(
                right_hint_df.data_frame().clone(),
                self.join.join_type,
                join_exprs,
            )
            .expect("join output should succeed");

        // Use all row_id columns (with qualifiers) to keep ordering deterministic.
        let row_id_sort_exprs: Vec<SortExpr> = self
            .join
            .schema
            .iter()
            .filter_map(|(qualifier, field)| {
                if field.name() != ROW_ID_COL_NAME {
                    return None;
                }
                Some(
                    Expr::Column(Column::new(qualifier.cloned(), ROW_ID_COL_NAME)).sort(true, true),
                )
            })
            .collect();

        let joined = if row_id_sort_exprs.is_empty() {
            joined
        } else {
            joined
                .sort(row_id_sort_exprs)
                .expect("join output sort should succeed")
        };
        crate::irs::nodes::hints::HintDF::new_materialized(joined)
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
