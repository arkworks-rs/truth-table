//! `x [NOT] IN (v1, .., vk)` over literal values: the result is committed and
//! proved by a membership gadget, `gadget` for a list of at most
//! [`MAX_PRODUCT_VALUES`] distinct values and `long_list` for a longer one. A
//! list with a non-literal value is rewritten into comparisons before the IR
//! is built.

use std::sync::Arc;

use arithmetic::{ACTIVATOR_FIELD, ROW_ID_COL_NAME, is_system_column};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use datafusion_common::ScalarValue;
use datafusion_expr::{Expr, ExprSchemable, expr::InList, expr_fn::when, lit};
use indexmap::IndexMap;

use crate::irs::nodes::{
    IsExprNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
};
use crate::irs::payloads::PayloadStructure;
use crate::irs::tree::Tree;

pub mod gadget;
pub mod long_list;

/// The longest list `gadget` proves. Its zerocheck has degree `k + 1`, so its
/// cost grows faster than linearly in `k`; `long_list` costs a sort of the
/// distinct values and a lookup, whatever `k`.
pub const MAX_PRODUCT_VALUES: usize = 8;

pub struct ExprNode<B: SnarkBackend> {
    in_list: InList,
    expr: Arc<Node<B>>,
    gadget: Arc<Node<B>>,
    long_list: bool,
    scope: Vec<std::sync::Weak<Node<B>>>,
    parent: Option<std::sync::Weak<Node<B>>>,
}

/// The list's values, when every one is a non-null literal.
pub fn literal_values(in_list: &InList) -> Option<Vec<ScalarValue>> {
    in_list
        .list
        .iter()
        .map(|value| match value {
            Expr::Literal(value) if !value.is_null() => Some(value.clone()),
            _ => None,
        })
        .collect()
}

impl<B: SnarkBackend> ExprNode<B> {
    /// `value` as the output column: false on inactive rows, which the gadget
    /// checks, and named as the IN list, which a parent looks it up by.
    fn output_expr(&self, input_df: &datafusion::prelude::DataFrame, value: Expr) -> Expr {
        let name = Expr::InList(self.in_list.clone()).schema_name().to_string();
        match crate::irs::nodes::hints::activator_expr(input_df) {
            Some(activator) => when(activator, value)
                .otherwise(lit(false))
                .expect("IN list masking case should succeed")
                .alias(name),
            None => value.alias_if_changed(name).expect("IN list output alias"),
        }
    }

    fn scope_output<T>(&self, output: impl Fn(&crate::irs::nodes::PlanNode<B>) -> T) -> T {
        let scope = self.scope[0]
            .upgrade()
            .expect("InList scope should be available during output");
        match scope.as_ref() {
            Node::Plan(plan_node) => output(plan_node),
            Node::Gadget(_) => panic!("InList scope cannot be a gadget node"),
        }
    }

    /// The long-list gadget's plan-time keys: `x`, whether it is in the list,
    /// the activator (all true without one) and the row id.
    fn prover_keys_hint(&self) -> crate::irs::nodes::hints::HintDF {
        let scope_hint_df = self.scope_output(|plan_node| {
            <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsProverPlanNode<B>>::output(
                plan_node,
            )
        });
        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(scope_hint_df.data_frame().clone())
                .expect("in-list row-id sort should succeed");
        let member = Expr::InList(InList {
            negated: false,
            ..self.in_list.clone()
        });
        let activator = crate::irs::nodes::hints::activator_expr(&input_df).unwrap_or(lit(true));
        let mut exprs = vec![
            self.in_list.expr.as_ref().clone().alias(long_list::KEY_COL),
            member.alias(long_list::MEMBER_COL),
            activator.alias(arithmetic::ACTIVATOR_COL_NAME),
        ];
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);
        let keys = input_df
            .select(exprs)
            .expect("in-list keys projection should succeed");
        crate::irs::nodes::hints::HintDF::new_virtual(keys)
    }

    fn verifier_keys_hint(&self) -> crate::irs::nodes::hints::HintDF {
        let scope_hint_df = self.scope_output(|plan_node| {
            <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                plan_node,
            )
        });
        let key_type = self
            .in_list
            .expr
            .get_type(scope_hint_df.data_frame().schema())
            .expect("the IN list's tested expression has a type");
        crate::irs::nodes::hints::HintDF::new_virtual(crate::irs::nodes::hints::schema_only_df(
            vec![
                Field::new(long_list::KEY_COL, key_type, true),
                Field::new(long_list::MEMBER_COL, DataType::Boolean, true),
                ACTIVATOR_FIELD.as_ref().clone(),
                Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
            ],
        ))
    }

    fn hand_keys_to_gadget(
        &self,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
        keys: crate::irs::nodes::hints::HintDF,
    ) {
        let mut payload = match planned_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(payload)) => payload.clone(),
            _ => IndexMap::new(),
        };
        payload.insert(long_list::KEYS_LABEL.to_string(), keys);
        planned_ir.set_payload_for_node(
            self.gadget.id(),
            Some(PayloadStructure::GadgetPayload(payload)),
        );
    }

    fn should_materialize(fields: &[FieldRef]) -> IndexMap<FieldRef, bool> {
        fields
            .iter()
            .map(|field| (field.clone(), !is_system_column(field.name())))
            .collect()
    }
}

impl<B: SnarkBackend> IsNode<B> for ExprNode<B> {
    fn name(&self) -> String {
        "InList".to_string()
    }

    fn display(&self) -> String {
        format!(
            "InList\nInput: {}, Values: {}, Negated: {}",
            self.expr.name(),
            self.in_list.list.len(),
            self.in_list.negated
        )
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        vec![self.expr.clone(), self.gadget.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ExprNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::PlanPayload(input)) =
            virtualized_ir.payload_for_node(&self.expr.id()).cloned()
        else {
            panic!("Expected PlanPayload for the InList input");
        };
        let current = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => Default::default(),
        };

        let mut polys = IndexMap::new();
        if let Some((field, poly)) = current
            .tracked_polys_iter()
            .find(|(field, _)| !is_system_column(field.name()))
        {
            polys.insert(field.clone(), poly.clone());
        }
        if let Some((field, poly)) = input
            .tracked_polys_iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
        {
            polys.insert(field.clone(), poly.clone());
        }
        if let Some(activator) = input.activator_tracked_poly() {
            polys.insert(ACTIVATOR_FIELD.clone(), activator);
        }
        let metadata = current
            .schema_ref()
            .or_else(|| input.schema_ref())
            .map(|schema| schema.metadata().clone())
            .unwrap_or_default();
        let fields = polys.keys().map(|f| f.as_ref().clone()).collect::<Vec<_>>();
        let schema = Some(Schema::new_with_metadata(fields, metadata));
        let log_size = match current.log_size() {
            0 => input.log_size(),
            log_size => log_size,
        };
        virtualized_ir.set_payload_for_node(
            id,
            Some(PayloadStructure::PlanPayload(
                arithmetic::table::TrackedTable::new(schema, polys, log_size),
            )),
        );
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let table = |node_id: &NodeId| match virtualized_ir.payload_for_node(node_id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Expected PlanPayload for an InList table"),
        };
        let (input, output) = (table(&self.expr.id()), table(&id));
        let mut payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(payload)) => payload.clone(),
            _ => IndexMap::new(),
        };
        payload.insert(gadget::INPUT_LABEL.to_string(), input);
        payload.insert(gadget::OUTPUT_LABEL.to_string(), output);
        virtualized_ir.set_payload_for_node(
            self.gadget.id(),
            Some(PayloadStructure::GadgetPayload(payload)),
        );
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        if self.long_list {
            let keys = self.prover_keys_hint();
            self.hand_keys_to_gadget(planned_ir, keys);
        }
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ExprNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::PlanPayload(input)) =
            virtualized_ir.payload_for_node(&self.expr.id()).cloned()
        else {
            panic!("Expected PlanPayload for the InList input");
        };
        let current = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => Default::default(),
        };

        let mut oracles = IndexMap::new();
        if let Some((field, oracle)) = current
            .tracked_oracles_iter()
            .find(|(field, _)| !is_system_column(field.name()))
        {
            oracles.insert(field.clone(), oracle.clone());
        }
        if let Some((field, oracle)) = input
            .tracked_oracles_iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
        {
            oracles.insert(field.clone(), oracle.clone());
        }
        if let Some(activator) = input.activator_tracked_poly() {
            oracles.insert(ACTIVATOR_FIELD.clone(), activator);
        }
        let metadata = current
            .schema_ref()
            .or_else(|| input.schema_ref())
            .map(|schema| schema.metadata().clone())
            .unwrap_or_default();
        let fields = oracles
            .keys()
            .map(|f| f.as_ref().clone())
            .collect::<Vec<_>>();
        let schema = Some(Schema::new_with_metadata(fields, metadata));
        let log_size = match current.log_size() {
            0 => input.log_size(),
            log_size => log_size,
        };
        virtualized_ir.set_payload_for_node(
            id,
            Some(PayloadStructure::PlanPayload(
                arithmetic::table_oracle::TrackedTableOracle::new(schema, oracles, log_size),
            )),
        );
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let table = |node_id: &NodeId| match virtualized_ir.payload_for_node(node_id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Expected PlanPayload for an InList table"),
        };
        let (input, output) = (table(&self.expr.id()), table(&id));
        let mut payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(payload)) => payload.clone(),
            _ => IndexMap::new(),
        };
        payload.insert(gadget::INPUT_LABEL.to_string(), input);
        payload.insert(gadget::OUTPUT_LABEL.to_string(), output);
        virtualized_ir.set_payload_for_node(
            self.gadget.id(),
            Some(PayloadStructure::GadgetPayload(payload)),
        );
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        if self.long_list {
            let keys = self.verifier_keys_hint();
            self.hand_keys_to_gadget(planned_ir, keys);
        }
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ExprNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        Some(self.gadget.as_ref().clone())
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsProverPlanNode<B> for ExprNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let scope_hint_df = self.scope_output(|plan_node| {
            <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsProverPlanNode<B>>::output(
                plan_node,
            )
        });
        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(scope_hint_df.data_frame().clone())
                .expect("in-list row-id sort should succeed");

        let value = Expr::InList(self.in_list.clone());
        #[cfg(feature = "test-utils")]
        let value = crate::test_utils::dishonest_prover::forge_in_list(value);
        let mut exprs = vec![self.output_expr(&input_df, value)];
        crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut exprs);
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);
        let projected = input_df
            .select(exprs)
            .expect("in-list projection should succeed");
        let should_materialize = Self::should_materialize(projected.schema().fields());
        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("in-list output sort should succeed");
        crate::irs::nodes::hints::HintDF::new(projected, should_materialize)
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for ExprNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let scope_hint_df = self.scope_output(|plan_node| {
            <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                plan_node,
            )
        });
        let input_df = scope_hint_df.data_frame();
        let output_expr = self.output_expr(input_df, Expr::InList(self.in_list.clone()));
        let output_type = output_expr
            .get_type(input_df.schema())
            .unwrap_or(DataType::Boolean);
        let mut fields = vec![Field::new(
            output_expr.schema_name().to_string(),
            output_type,
            true,
        )];
        fields.extend(
            input_df
                .schema()
                .as_arrow()
                .fields()
                .iter()
                .filter(|field| {
                    field.name() == arithmetic::ACTIVATOR_COL_NAME
                        || field.name() == ROW_ID_COL_NAME
                })
                .map(|field| field.as_ref().clone()),
        );
        let projected = crate::irs::nodes::hints::schema_only_df(fields);
        let should_materialize = Self::should_materialize(projected.schema().fields());
        crate::irs::nodes::hints::HintDF::new(projected, should_materialize)
    }
}

impl<B: SnarkBackend> IsExprNode<B> for ExprNode<B> {
    fn from_expr(
        expr: Expr,
        self_ref: std::sync::Weak<Node<B>>,
        parent: Option<std::sync::Weak<Node<B>>>,
        scope: Vec<std::sync::Weak<Node<B>>>,
    ) -> Self
    where
        Self: Sized,
    {
        let Expr::InList(in_list) = expr else {
            panic!("Expected Expr::InList");
        };
        let values = literal_values(&in_list)
            .expect("an IN list in the IR has only non-null literal values");
        let expr = Tree::<B>::from_expr(&in_list.expr, Some(self_ref.clone()), scope.clone())
            .root()
            .clone();
        let distinct: Vec<ScalarValue> = values
            .iter()
            .cloned()
            .collect::<indexmap::IndexSet<_>>()
            .into_iter()
            .collect();
        let long_list = distinct.len() > MAX_PRODUCT_VALUES;
        let gadget: Arc<dyn crate::irs::nodes::IsGadgetNode<B>> = if long_list {
            Arc::new(long_list::LongListNode::new(distinct, in_list.negated))
        } else {
            Arc::new(gadget::InListNode::new(&values, in_list.negated))
        };
        Self {
            in_list,
            expr,
            gadget: Arc::new(Node::<B>::Gadget(gadget)),
            long_list,
            scope,
            parent,
        }
    }

    fn expr(&self) -> Expr {
        Expr::InList(self.in_list.clone())
    }

    fn parent(&self) -> crate::irs::nodes::PlanNode<B>
    where
        Self: Sized,
    {
        self.parent
            .as_ref()
            .and_then(|weak| weak.upgrade())
            .map(|node| match node.as_ref() {
                Node::Plan(plan_node) => plan_node.clone(),
                Node::Gadget(_) => panic!("InList parent cannot be a gadget node"),
            })
            .expect("InList node must have a parent")
    }

    fn scope(&self) -> Vec<Arc<Node<B>>>
    where
        Self: Sized,
    {
        self.scope
            .iter()
            .map(|s| s.upgrade().expect("InList scope should be available"))
            .collect()
    }
}
