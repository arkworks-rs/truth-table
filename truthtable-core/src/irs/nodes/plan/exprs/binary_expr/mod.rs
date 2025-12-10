use std::sync::Arc;

use arithmetic::ACTIVATOR_EXPR;
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::FieldRef;
use datafusion_expr::{BinaryExpr, Expr};
use indexmap::IndexMap;

use crate::irs::{
    nodes::{IsExprNode, IsGadgetNode, IsNode, IsPlanNode, Node},
    payloads::PayloadStructure,
    tree::Tree,
};
use crate::irs::nodes::gadget::exprs::bin_eq::{
    LEFT_INPUT_LABEL, OUTPUT_LABEL, RIGHT_INPUT_LABEL,
};

pub struct ProverNode<B: SnarkBackend> {
    pub binary_expression: BinaryExpr,
    pub left: Arc<Node<B>>,
    pub right: Arc<Node<B>>,
    pub scope: Arc<Node<B>>,
    pub gadget: Arc<Node<B>>,
}

impl<B: SnarkBackend> ProverNode<B> {
    fn should_materialize(&self) -> bool {
        matches!(
            self.binary_expression.op,
            datafusion_expr::Operator::Eq
                | datafusion_expr::Operator::NotEq
                | datafusion_expr::Operator::Lt
                | datafusion_expr::Operator::LtEq
                | datafusion_expr::Operator::Gt
                | datafusion_expr::Operator::GtEq
        )
    }
}

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "BinaryExpr".to_string()
    }

    fn cost(
        &self,
        statistics: datafusion_common::Statistics,
        schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        vec![self.left.clone(), self.right.clone(), self.gadget().clone()]
    }
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let extract_plan_payload =
            |node_id: &crate::irs::nodes::NodeId| -> Option<arithmetic::table::TrackedTable<B>> {
                virtualized_ir
                    .payload_for_node(node_id)
                    .and_then(|payload| match payload {
                        PayloadStructure::PlanPayload(table) => Some(table.clone()),
                        _ => None,
                    })
            };

        let left_payload = extract_plan_payload(&self.left.id());
        let right_payload = extract_plan_payload(&self.right.id());
        let output_payload = extract_plan_payload(&_id);

        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };

        if let Some(table) = left_payload {
            gadget_payload.insert(LEFT_INPUT_LABEL.to_string(), table);
        }
        if let Some(table) = right_payload {
            gadget_payload.insert(RIGHT_INPUT_LABEL.to_string(), table);
        }
        if let Some(table) = output_payload {
            gadget_payload.insert(OUTPUT_LABEL.to_string(), table);
        }

        if !gadget_payload.is_empty() {
            virtualized_ir.set_payload_for_node(
                self.gadget.id(),
                Some(PayloadStructure::GadgetPayload(gadget_payload)),
            );
        }
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ProverNode<B> {
    fn gadget(&self) -> Arc<Node<B>> {
        self.gadget.clone()
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        // Project the binary expression result alongside the activator from the scope.
        let scope_hint_df = match self.scope.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("BinaryExpr scope cannot be a gadget node"),
        };

        let projected = scope_hint_df
            .data_frame()
            .clone()
            .select(vec![
                Expr::BinaryExpr(self.binary_expression.clone()),
                ACTIVATOR_EXPR.clone(),
            ])
            .expect("binary expression projection should succeed");

        // Activator is always virtual; the expression column follows this node's
        // materialization policy.
        let should_materialize: IndexMap<FieldRef, bool> = projected
            .schema()
            .fields()
            .iter()
            .map(|field| {
                let mat = if field.name() == arithmetic::ACTIVATOR_COL_NAME {
                    false
                } else {
                    self.should_materialize()
                };
                (field.clone(), mat)
            })
            .collect();

        crate::irs::nodes::hints::HintDF::new(projected, should_materialize)
    }
}

impl<B: SnarkBackend> IsExprNode<B> for ProverNode<B> {
    fn from_expr(
        _expr: datafusion_expr::Expr,
        self_ref: std::sync::Weak<Node<B>>,
        parent: Option<std::sync::Weak<Node<B>>>,
        scope: std::sync::Arc<Node<B>>,
    ) -> Self
    where
        Self: Sized,
    {
        let binary_expression = match _expr {
            datafusion_expr::Expr::BinaryExpr(bin_expr) => bin_expr,
            _ => panic!("Expected Expr::BinaryExpr"),
        };

        // Recurse into the left and right expressions to build their nodes.
        let left = Tree::<B>::from_expr(
            &binary_expression.left,
            Some(self_ref.clone()),
            scope.clone(),
        )
        .root()
        .clone();
        let right = Tree::<B>::from_expr(
            &binary_expression.right,
            Some(self_ref.clone()),
            scope.clone(),
        )
        .root()
        .clone();
        let gadget = match binary_expression.op {
            datafusion_expr::Operator::Eq => Arc::new(Node::<B>::Gadget(Arc::new(
                crate::irs::nodes::gadget::exprs::bin_eq::ProverNode::new(),
            ))),
            _ => panic!("Unsupported operator for binary expression gadget"),
        };
        Self {
            binary_expression,
            left,
            right,
            scope,
            gadget,
        }
    }

    fn expr(&self) -> datafusion_expr::Expr {
        datafusion_expr::Expr::BinaryExpr(self.binary_expression.clone())
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
