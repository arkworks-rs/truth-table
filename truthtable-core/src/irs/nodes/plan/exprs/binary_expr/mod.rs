use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_EXPR, ACTIVATOR_FIELD};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{Field, FieldRef, Schema};
use datafusion_expr::{BinaryExpr, Expr};
use indexmap::IndexMap;

use crate::irs::{
    nodes::{IsExprNode, IsNode, IsPlanNode, Node, ProverNodeOps, VerifierNodeOps},
    payloads::PayloadStructure,
    tree::Tree,
};
use crate::{
    irs::nodes::{
        NodeId,
        gadget::exprs::{
            bin_cmp::{self, BinCmpOp},
            bin_eq::{self, LEFT_INPUT_LABEL, OUTPUT_LABEL, RIGHT_INPUT_LABEL},
        },
    },
    prover::irs::VirtualizedIr as ProverVirtualizedIr,
    verifier::irs::VirtualizedIr as VerifierVirtualizedIr,
};

#[cfg(test)]
mod tests;
mod virtual_ops;

pub struct BinaryExprNode<B: SnarkBackend> {
    /// The binary expression being represented.
    pub binary_expression: BinaryExpr,
    /// The left child node.
    pub left: Arc<Node<B>>,
    /// The right child node.
    pub right: Arc<Node<B>>,
    /// The scope node.
    pub scope: Arc<Node<B>>,
    /// The gadget node.
    pub gadget: Arc<Node<B>>,
}

impl<B: SnarkBackend> BinaryExprNode<B> {
    /// Determines whether the result of the binary expression should be materialized or not.
    /// Some operators require materialization (e.g., comparisions), while others may not (e.g., arithmetic operations).
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
    /// Dispatches to the appropriate gadget node based on the binary operator.
    /// Since binary expressions can represent a variety of operations, we need to select the correct gadget node.
    fn dispatch_gadget(op: datafusion_expr::Operator) -> Arc<Node<B>> {
        match op {
            datafusion_expr::Operator::Eq => {
                Arc::new(Node::<B>::Gadget(Arc::new(bin_eq::BinEqNode::new())))
            }
            datafusion_expr::Operator::GtEq => Arc::new(Node::<B>::Gadget(Arc::new(
                bin_cmp::BinCmpNode::new(BinCmpOp::Geq),
            ))),
            datafusion_expr::Operator::LtEq => Arc::new(Node::<B>::Gadget(Arc::new(
                bin_cmp::BinCmpNode::new(BinCmpOp::Leq),
            ))),
            datafusion_expr::Operator::Gt => Arc::new(Node::<B>::Gadget(Arc::new(
                bin_cmp::BinCmpNode::new(BinCmpOp::Gt),
            ))),
            datafusion_expr::Operator::Lt => Arc::new(Node::<B>::Gadget(Arc::new(
                bin_cmp::BinCmpNode::new(BinCmpOp::Lt),
            ))),
            _ => panic!("Unsupported operator for binary expression gadget"),
        }
    }
}

impl<B: SnarkBackend> IsNode<B> for BinaryExprNode<B> {
    fn name(&self) -> String {
        "BinaryExpr".to_string()
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        vec![self.left.clone(), self.right.clone(), self.gadget().clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for BinaryExprNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Pull activator from the left child.
        let left_table = match virtualized_ir.payload_for_node(&self.left.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Expected PlanPayload for left child in BinaryExprNode"),
        };
        let left_activator = left_table.activator_tracked_poly();

        // Pull activator from the right child.
        let right_table = match virtualized_ir.payload_for_node(&self.right.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Expected PlanPayload for right child in BinaryExprNode"),
        };
        let right_activator = right_table.activator_tracked_poly();

        // Assert that the left and right activators are the same.
        debug_assert!(
            match (left_activator.as_ref(), right_activator.as_ref()) {
                (Some(l), Some(r)) => l == r,
                (None, None) => true,
                _ => false,
            },
            "Left and right activators should match in BinaryExprNode"
        );

        let output_activator = left_activator.clone();
        let output_tracked_poly = if self.should_materialize() {
            None
        } else {
            let left_data_indices = left_table.data_tracked_polys_indices();
            let right_data_indices = right_table.data_tracked_polys_indices();
            debug_assert_eq!(
                left_data_indices.len(),
                1,
                "BinaryExpr virtual ops expect one left data column"
            );
            debug_assert_eq!(
                right_data_indices.len(),
                1,
                "BinaryExpr virtual ops expect one right data column"
            );

            let left_col = left_table.tracked_col_by_ind(left_data_indices[0]);
            let right_col = right_table.tracked_col_by_ind(right_data_indices[0]);
            Some(virtual_ops::output_virtual_table(
                &self.binary_expression,
                &left_col.data_tracked_poly(),
                &right_col.data_tracked_poly(),
            ))
        };

        // Start from existing payload (if any).
        let current_table = virtualized_ir
            .payload_for_node(&id)
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(table.clone()),
                _ => None,
            })
            .unwrap_or_default();

        let mut merged_polys = current_table.tracked_polys();
        if let Some(output_poly) = output_tracked_poly {
            let output_field = self
                .output()
                .data_frame()
                .schema()
                .fields()
                .iter()
                .find(|field| field.name() != ACTIVATOR_COL_NAME)
                .cloned()
                .expect("BinaryExpr output should include a data column");
            merged_polys.insert(output_field, output_poly);
        }

        if let Some(activator) = output_activator {
            merged_polys.insert(ACTIVATOR_FIELD.clone(), activator);
        }

        let metadata = current_table
            .schema_ref()
            .map(|s| s.metadata().clone())
            .or_else(|| left_table.schema_ref().map(|s| s.metadata().clone()))
            .unwrap_or_default();
        let fields = merged_polys
            .keys()
            .map(|f| f.as_ref().clone())
            .collect::<Vec<_>>();
        let schema = Some(Schema::new_with_metadata(fields, metadata));

        let log_size = match (current_table.log_size(), left_table.log_size()) {
            (0, other) => other,
            (curr, 0) => curr,
            (curr, left) => {
                debug_assert_eq!(curr, left, "BinaryExpr log sizes should agree");
                curr
            }
        };

        let updated_table = arithmetic::table::TrackedTable::new(schema, merged_polys, log_size);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: NodeId,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
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

impl<B: SnarkBackend> VerifierNodeOps<B> for BinaryExprNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Pull activator from the left child.
        let left_table = match virtualized_ir.payload_for_node(&self.left.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Expected PlanPayload for left child in BinaryExprNode"),
        };
        let left_activator = left_table.activator_tracked_poly();

        // Pull activator from the right child.
        let right_table = match virtualized_ir.payload_for_node(&self.right.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Expected PlanPayload for right child in BinaryExprNode"),
        };
        let right_activator = right_table.activator_tracked_poly();

        // Assert that the left and right activators are the same.
        debug_assert!(
            match (left_activator.as_ref(), right_activator.as_ref()) {
                (Some(l), Some(r)) => l == r,
                (None, None) => true,
                _ => false,
            },
            "Left and right activators should match in BinaryExprNode"
        );

        let output_activator = left_activator.clone();
        let output_table = if self.should_materialize() {
            None
        } else {
            let left_data_indices = left_table.data_tracked_oracles_indices();
            let right_data_indices = right_table.data_tracked_oracles_indices();
            debug_assert_eq!(
                left_data_indices.len(),
                1,
                "BinaryExpr virtual ops expect one left data column"
            );
            debug_assert_eq!(
                right_data_indices.len(),
                1,
                "BinaryExpr virtual ops expect one right data column"
            );

            let left_col = left_table.tracked_col_oracle_by_ind(left_data_indices[0]);
            let right_col = right_table.tracked_col_oracle_by_ind(right_data_indices[0]);
            Some(virtual_ops::output_virtual_table_oracle(
                &self.binary_expression,
                &left_col.data_tracked_oracle(),
                &right_col.data_tracked_oracle(),
            ))
        };

        // Start from existing payload (if any).
        let current_table = virtualized_ir
            .payload_for_node(&id)
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(table.clone()),
                _ => None,
            })
            .unwrap_or_default();

        let mut merged_oracles = current_table.tracked_oracles();
        if let Some(output_oracle) = output_table {
            let output_field = self
                .output()
                .data_frame()
                .schema()
                .fields()
                .iter()
                .find(|field| field.name() != ACTIVATOR_COL_NAME)
                .cloned()
                .expect("BinaryExpr output should include a data column");
            merged_oracles.insert(output_field, output_oracle);
        }
        if let Some(activator) = output_activator {
            merged_oracles.insert(ACTIVATOR_FIELD.clone(), activator);
        }

        let metadata = current_table
            .schema_ref()
            .map(|s| s.metadata().clone())
            .or_else(|| left_table.schema_ref().map(|s| s.metadata().clone()))
            .unwrap_or_default();
        let fields = merged_oracles
            .keys()
            .map(|f| f.as_ref().clone())
            .collect::<Vec<_>>();
        let schema = Some(Schema::new_with_metadata(fields, metadata));

        let log_size = match (current_table.log_size(), left_table.log_size()) {
            (0, other) => other,
            (curr, 0) => curr,
            (curr, left) => {
                debug_assert_eq!(curr, left, "BinaryExpr log sizes should agree");
                curr
            }
        };

        let updated_table =
            arithmetic::table_oracle::TrackedTableOracle::new(schema, merged_oracles, log_size);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let extract_plan_payload = |node_id: &NodeId| {
            virtualized_ir
                .payload_for_node(node_id)
                .and_then(|payload| match payload {
                    PayloadStructure::PlanPayload(table) => Some(table.clone()),
                    _ => None,
                })
        };

        let left_payload = extract_plan_payload(&self.left.id());
        let right_payload = extract_plan_payload(&self.right.id());
        let output_payload = extract_plan_payload(&id);

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

impl<B: SnarkBackend> IsPlanNode<B> for BinaryExprNode<B> {
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

impl<B: SnarkBackend> IsExprNode<B> for BinaryExprNode<B> {
    fn from_expr(
        expr: datafusion_expr::Expr,
        self_ref: std::sync::Weak<Node<B>>,
        _parent: Option<std::sync::Weak<Node<B>>>,
        scope: std::sync::Arc<Node<B>>,
    ) -> Self
    where
        Self: Sized,
    {
        // Extract the binary expression.
        let binary_expression = match expr {
            datafusion_expr::Expr::BinaryExpr(bin_expr) => bin_expr,
            _ => panic!("Expected Expr::BinaryExpr"),
        };

        // Recurse into the left expression to build its nodes.
        let left = Tree::<B>::from_expr(
            &binary_expression.left,
            Some(self_ref.clone()),
            scope.clone(),
        )
        .root()
        .clone();
        // Recurse into the right expression to build its nodes.
        let right = Tree::<B>::from_expr(
            &binary_expression.right,
            Some(self_ref.clone()),
            scope.clone(),
        )
        .root()
        .clone();
        // Dispatch to the appropriate gadget node.
        let gadget = Self::dispatch_gadget(binary_expression.op);
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
