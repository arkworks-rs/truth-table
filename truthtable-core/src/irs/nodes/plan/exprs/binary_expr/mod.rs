use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_EXPR};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{FieldRef, Schema};
use datafusion_expr::{BinaryExpr, Expr};
use indexmap::IndexMap;

use crate::irs::nodes::gadget::exprs::{
    bin_cmp::{self, BinCmpOp},
    bin_eq::{self, LEFT_INPUT_LABEL, OUTPUT_LABEL, RIGHT_INPUT_LABEL},
};
use crate::irs::{
    nodes::{IsExprNode, IsNode, IsPlanNode, Node, ProverNodeOps, VerifierNodeOps},
    payloads::PayloadStructure,
    tree::Tree,
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
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        vec![self.left.clone(), self.right.clone(), self.gadget().clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Pull activator from the left child.
        let left_table = match virtualized_ir.payload_for_node(&self.left.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };
        let activator_entry = left_table
            .tracked_polys_iter()
            .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
            .map(|(f, p)| (f.clone(), p.clone()));
        let Some((act_field, act_poly)) = activator_entry else {
            return Ok(());
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
        merged_polys.insert(act_field.clone(), act_poly.clone());

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

        let left_input = match self.binary_expression.op {
            datafusion_expr::Operator::GtEq
            | datafusion_expr::Operator::LtEq
            | datafusion_expr::Operator::Gt
            | datafusion_expr::Operator::Lt => match (left_payload.as_ref(), right_payload.as_ref()) {
                (Some(left), Some(right)) => {
                    debug_assert_eq!(
                        left.data_tracked_polys_indices().len(),
                        1,
                        "BinaryExpr comparison expects one left data column"
                    );
                    debug_assert_eq!(
                        right.data_tracked_polys_indices().len(),
                        1,
                        "BinaryExpr comparison expects one right data column"
                    );

                    let left_col = left.tracked_col_by_ind(left.data_tracked_polys_indices()[0]);
                    let right_col = right.tracked_col_by_ind(right.data_tracked_polys_indices()[0]);
                    let left_poly = left_col.data_tracked_poly();
                    let right_poly = right_col.data_tracked_poly();
                    let diff_poly = &left_poly - &right_poly;
                    let diff_field = left_col
                        .field_ref()
                        .expect("BinaryExpr comparison expects a left field reference");

                    Some(arithmetic::table::TrackedTable::single_column_with_activator(
                        diff_field,
                        diff_poly,
                        left_col.activator_tracked_poly(),
                    ))
                }
                _ => None,
            },
            _ => left_payload.clone(),
        };

        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };

        if let Some(table) = left_input {
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

impl<B: SnarkBackend> VerifierNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Pull activator from the left child.
        let left_table = match virtualized_ir.payload_for_node(&self.left.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };
        let activator_entry = left_table
            .tracked_oracles_iter()
            .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
            .map(|(f, o)| (f.clone(), o.clone()));
        let Some((act_field, act_oracle)) = activator_entry else {
            return Ok(());
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
        merged_oracles.insert(act_field.clone(), act_oracle.clone());

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
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let extract_plan_payload = |node_id: &crate::irs::nodes::NodeId| {
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

        let left_input = match self.binary_expression.op {
            datafusion_expr::Operator::GtEq
            | datafusion_expr::Operator::LtEq
            | datafusion_expr::Operator::Gt
            | datafusion_expr::Operator::Lt => match (left_payload.as_ref(), right_payload.as_ref()) {
                (Some(left), Some(right)) => {
                    debug_assert_eq!(
                        left.data_tracked_oracles_indices().len(),
                        1,
                        "BinaryExpr comparison expects one left data column"
                    );
                    debug_assert_eq!(
                        right.data_tracked_oracles_indices().len(),
                        1,
                        "BinaryExpr comparison expects one right data column"
                    );

                    let left_col =
                        left.tracked_col_oracle_by_ind(left.data_tracked_oracles_indices()[0]);
                    let right_col =
                        right.tracked_col_oracle_by_ind(right.data_tracked_oracles_indices()[0]);
                    let left_oracle = left_col.data_tracked_oracle();
                    let right_oracle = right_col.data_tracked_oracle();
                    let diff_oracle = &left_oracle - &right_oracle;
                    let diff_field = left_col
                        .field_ref()
                        .expect("BinaryExpr comparison expects a left field reference");

                    Some(
                        arithmetic::table_oracle::TrackedTableOracle::single_column_with_activator(
                            diff_field,
                            diff_oracle,
                            left_col.activator_tracked_oracle(),
                        ),
                    )
                }
                _ => None,
            },
            _ => left_payload.clone(),
        };

        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };

        if let Some(table) = left_input {
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
