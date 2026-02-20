use std::sync::Arc;

use arithmetic::{ACTIVATOR_FIELD, ROW_ID_COL_NAME, is_system_column};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{FieldRef, Schema};
use datafusion_expr::{BinaryExpr, Expr, expr_fn::when, lit};
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

pub struct ExprNode<B: SnarkBackend> {
    /// The binary expression being represented.
    pub binary_expression: BinaryExpr,
    /// The left child node.
    pub left: Arc<Node<B>>,
    /// The right child node.
    pub right: Arc<Node<B>>,
    /// The scope node.
    pub scope: Vec<std::sync::Weak<Node<B>>>,
    /// The gadget node.
    pub gadget: Option<Arc<Node<B>>>,
}

impl<B: SnarkBackend> ExprNode<B> {
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
    fn dispatch_gadget(op: datafusion_expr::Operator) -> Option<Arc<Node<B>>> {
        match op {
            datafusion_expr::Operator::Eq => Some(Arc::new(Node::<B>::Gadget(Arc::new(
                bin_eq::BinEqNode::new(),
            )))),
            datafusion_expr::Operator::GtEq => Some(Arc::new(Node::<B>::Gadget(Arc::new(
                bin_cmp::BinCmpNode::new(BinCmpOp::Geq),
            )))),
            datafusion_expr::Operator::LtEq => Some(Arc::new(Node::<B>::Gadget(Arc::new(
                bin_cmp::BinCmpNode::new(BinCmpOp::Leq),
            )))),
            datafusion_expr::Operator::Gt => Some(Arc::new(Node::<B>::Gadget(Arc::new(
                bin_cmp::BinCmpNode::new(BinCmpOp::Gt),
            )))),
            datafusion_expr::Operator::Lt => Some(Arc::new(Node::<B>::Gadget(Arc::new(
                bin_cmp::BinCmpNode::new(BinCmpOp::Lt),
            )))),
            datafusion_expr::Operator::Multiply => None,
            datafusion_expr::Operator::Plus => None,
            datafusion_expr::Operator::Minus => None,
            datafusion_expr::Operator::And => None,
            datafusion_expr::Operator::Or => None,
            _ => panic!("Unsupported operator for binary expression gadget"),
        }
    }

    fn activator_expr_for_df(input_df: &datafusion::prelude::DataFrame) -> Option<Expr> {
        let activator_exprs: Vec<Expr> = input_df
            .schema()
            .iter()
            .filter_map(|(qualifier, field)| {
                if field.name() != arithmetic::ACTIVATOR_COL_NAME {
                    return None;
                }
                Some(Expr::Column(datafusion_common::Column::new(
                    qualifier.cloned(),
                    arithmetic::ACTIVATOR_COL_NAME,
                )))
            })
            .collect();
        if activator_exprs.is_empty() {
            return None;
        }
        let mut qualified: Vec<Expr> = activator_exprs
            .iter()
            .filter(|&expr| matches!(expr, Expr::Column(col) if col.relation.is_some()))
            .cloned()
            .collect();
        if !qualified.is_empty() {
            return Some(qualified.remove(0));
        }
        if activator_exprs.len() == 1 {
            return Some(activator_exprs[0].clone());
        }
        None
    }
}

impl<B: SnarkBackend> IsNode<B> for ExprNode<B> {
    fn name(&self) -> String {
        "BinaryExpr".to_string()
    }

    fn display(&self) -> String {
        format!(
            "BinaryExpr\nLeft: {}, Right: {}, op: {:?}",
            self.left.name(),
            self.right.name(),
            self.binary_expression.op
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
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        let mut children = vec![self.left.clone(), self.right.clone()];
        if let Some(gadget) = &self.gadget {
            children.push(gadget.clone());
        }
        children
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ExprNode<B> {
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
                .find(|field| !is_system_column(field.name()))
                .cloned()
                .expect("BinaryExpr output should include a data column");
            merged_polys.insert(output_field, output_poly);
        }

        if let Some((row_id_field, row_id_poly)) = left_table
            .tracked_polys_iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
        {
            merged_polys
                .entry(row_id_field.clone())
                .or_insert_with(|| row_id_poly.clone());
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
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        if self.gadget.is_none() {
            return Ok(());
        }
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

        let mut gadget_payload =
            match virtualized_ir.payload_for_node(&self.gadget.as_ref().unwrap().id()) {
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
                self.gadget.as_ref().unwrap().id(),
                Some(PayloadStructure::GadgetPayload(gadget_payload)),
            );
        }
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ExprNode<B> {
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
                .find(|field| !is_system_column(field.name()))
                .cloned()
                .expect("BinaryExpr output should include a data column");
            merged_oracles.insert(output_field, output_oracle);
        }
        if let Some((row_id_field, row_id_oracle)) = left_table
            .tracked_oracles_iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
        {
            merged_oracles
                .entry(row_id_field.clone())
                .or_insert_with(|| row_id_oracle.clone());
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
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        if self.gadget.is_none() {
            return Ok(());
        }
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

        let mut gadget_payload =
            match virtualized_ir.payload_for_node(&self.gadget.as_ref().unwrap().id()) {
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
                self.gadget.as_ref().unwrap().id(),
                Some(PayloadStructure::GadgetPayload(gadget_payload)),
            );
        }
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ExprNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        self.gadget.as_ref().map(|gadget| gadget.as_ref().clone())
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        // Project the binary expression result alongside the activator from the scope.
        let scope = self.scope[0]
            .upgrade()
            .expect("BinaryExpr scope should be available during output");
        let scope_hint_df = match scope.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("BinaryExpr scope cannot be a gadget node"),
        };

        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(scope_hint_df.data_frame().clone())
                .expect("binary expr row-id sort should succeed");

        let output_expr = Expr::BinaryExpr(self.binary_expression.clone());
        let output_expr = if self.should_materialize() {
            // Comparison outputs should be false on inactive rows.
            if let Some(activator_expr) = Self::activator_expr_for_df(&input_df) {
                when(activator_expr, output_expr)
                    .otherwise(lit(false))
                    .expect("binary expression masking case should succeed")
            } else {
                output_expr
            }
        } else {
            output_expr
        };

        let mut exprs = vec![output_expr];
        crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut exprs);
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);

        let projected = input_df
            .select(exprs)
            .expect("binary expression projection should succeed");

        // Activator is always virtual; the expression column follows this node's
        // materialization policy.
        let should_materialize: IndexMap<FieldRef, bool> = projected
            .schema()
            .fields()
            .iter()
            .map(|field| {
                let mat = if field.name() == arithmetic::ACTIVATOR_COL_NAME
                    || field.name() == ROW_ID_COL_NAME
                {
                    false
                } else {
                    self.should_materialize()
                };
                (field.clone(), mat)
            })
            .collect();

        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("binary expr output sort should succeed");
        crate::irs::nodes::hints::HintDF::new(projected, should_materialize)
    }
}

impl<B: SnarkBackend> IsExprNode<B> for ExprNode<B> {
    fn from_expr(
        expr: datafusion_expr::Expr,
        self_ref: std::sync::Weak<Node<B>>,
        _parent: Option<std::sync::Weak<Node<B>>>,
        scope: Vec<std::sync::Weak<Node<B>>>,
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

    fn scope(&self) -> Vec<std::sync::Arc<Node<B>>>
    where
        Self: Sized,
    {
        self.scope
            .iter()
            .map(|s| {
                s.upgrade()
                    .expect("ScalarFunction scope should be available")
            })
            .collect()
    }
}
