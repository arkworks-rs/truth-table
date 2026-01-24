use std::sync::{Arc, Weak};

use crate::irs::{
    nodes::{
        gadget::lps::join as join_gadget, IsLpNode, IsNode, IsPlanNode, Node, NodeId,
        ProverNodeOps, VerifierNodeOps,
    },
    payloads::PayloadStructure,
    tree::Tree,
};
use arithmetic::ROW_ID_COL_NAME;
use ark_piop::SnarkBackend;
use datafusion_expr::{Join, LogicalPlan};
use indexmap::IndexMap;
mod hints;
#[allow(clippy::type_complexity)]
pub struct JoinNode<B>
where
    B: SnarkBackend,
{
    left: Arc<Node<B>>,
    right: Arc<Node<B>>,
    on: Vec<(Arc<Node<B>>, Arc<Node<B>>)>,
    filter: Option<Arc<Node<B>>>,
    gadget: Arc<Node<B>>,
    join: Join,
}

impl<B: SnarkBackend> IsNode<B> for JoinNode<B> {
    fn name(&self) -> String {
        "Join".to_string()
    }

    fn display(&self) -> String {
        let on_pairs = if self.on.is_empty() {
            "none".to_string()
        } else {
            self.on
                .iter()
                .map(|(left, right)| format!("{}={}", left.name(), right.name()))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let filter = self
            .filter
            .as_ref()
            .map(|node| node.name())
            .unwrap_or_else(|| "none".to_string());
        format!(
            "Join\nLeft: {}, Right: {}, type: {:?}, on: {}, filter: {}",
            self.left.name(),
            self.right.name(),
            self.join.join_type,
            on_pairs,
            filter
        )
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
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let left_hint_df = match planned_ir.payload_for_node(&self.left.id()) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df.clone(),
            _ => return Ok(()),
        };
        let right_hint_df = match planned_ir.payload_for_node(&self.right.id()) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df.clone(),
            _ => return Ok(()),
        };
        let output_hint_df = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df.clone(),
            _ => return Ok(()),
        };

        let mut gadget_payload = match planned_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(
            join_gadget::LEFT_LABEL.to_string(),
            crate::irs::nodes::hints::HintDF::new_virtual(left_hint_df.data_frame().clone()),
        );
        gadget_payload.insert(
            join_gadget::RIGHT_LABEL.to_string(),
            crate::irs::nodes::hints::HintDF::new_virtual(right_hint_df.data_frame().clone()),
        );
        gadget_payload.insert(
            join_gadget::OUTPUT_LABEL.to_string(),
            crate::irs::nodes::hints::HintDF::new_virtual(output_hint_df.data_frame().clone()),
        );

        planned_ir.set_payload_for_node(
            self.gadget.id(),
            Some(PayloadStructure::GadgetPayload(gadget_payload)),
        );
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
        children.push(self.gadget.clone());
        children
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for JoinNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let output_table = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Join output payload missing"),
        };
        let left_table = match virtualized_ir.payload_for_node(&self.left.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Join left payload missing"),
        };
        let right_table = match virtualized_ir.payload_for_node(&self.right.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Join right payload missing"),
        };

        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(join_gadget::LEFT_LABEL.to_string(), left_table);
        gadget_payload.insert(join_gadget::RIGHT_LABEL.to_string(), right_table);
        gadget_payload.insert(join_gadget::OUTPUT_LABEL.to_string(), output_table);
        virtualized_ir.set_payload_for_node(
            self.gadget.id(),
            Some(PayloadStructure::GadgetPayload(gadget_payload)),
        );

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
        let joined = hints::build_output_dataframe(
            left_hint_df.data_frame().clone(),
            right_hint_df.data_frame().clone(),
            &self.join,
        );

        let should_materialize: IndexMap<_, _> = joined
            .schema()
            .fields()
            .iter()
            .map(|field| {
                let name = field.name();
                let mat = name != ROW_ID_COL_NAME;
                (field.clone(), mat)
            })
            .collect();
        crate::irs::nodes::hints::HintDF::new(joined, should_materialize)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for JoinNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let output_table = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Join output payload missing"),
        };
        let left_table = match virtualized_ir.payload_for_node(&self.left.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Join left payload missing"),
        };
        let right_table = match virtualized_ir.payload_for_node(&self.right.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Join right payload missing"),
        };

        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(join_gadget::LEFT_LABEL.to_string(), left_table);
        gadget_payload.insert(join_gadget::RIGHT_LABEL.to_string(), right_table);
        gadget_payload.insert(join_gadget::OUTPUT_LABEL.to_string(), output_table);
        virtualized_ir.set_payload_for_node(
            self.gadget.id(),
            Some(PayloadStructure::GadgetPayload(gadget_payload)),
        );

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
        let join_scope_node = self_ref.clone();
        let on = join
            .on
            .iter()
            .map(|(l, r)| {
                let left_node =
                    Tree::<B>::from_expr(l, Some(self_ref.clone()), join_scope_node.clone())
                        .root()
                        .clone();
                let right_node =
                    Tree::<B>::from_expr(r, Some(self_ref.clone()), join_scope_node.clone())
                        .root()
                        .clone();
                (left_node, right_node)
            })
            .collect();
        let filter = join.filter.as_ref().map(|expr| {
            Tree::<B>::from_expr(expr, Some(self_ref.clone()), join_scope_node.clone())
                .root()
                .clone()
        });
        let gadget = Arc::new(Node::Gadget(Arc::new(
            crate::irs::nodes::gadget::lps::join::GadgetNode::<B>::new(join.clone()),
        )));
        JoinNode {
            left,
            right,
            on,
            filter,
            gadget,
            join,
        }
    }

    fn lp(&self) -> LogicalPlan {
        LogicalPlan::Join(self.join.clone())
    }
}
