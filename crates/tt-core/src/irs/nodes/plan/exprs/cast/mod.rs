//! A cast between integers, decimals and from a boolean to an integer. Each
//! is encoded as the integer it holds unscaled, so a cast multiplies that
//! integer by `10^k` or divides it by `10^k`. A product is the input's
//! column scaled, with nothing committed; a quotient is committed and goes
//! through the division check (`rescale`).
//!
//! A narrower type keeps the value: one that does not fit fails the
//! execution, and a gadget that bounds a column range checks the bound it
//! uses.

mod rescale;

use std::sync::Arc;

use arithmetic::col::is_system_column;
use arithmetic::table::TrackedTable;
use arithmetic::table_oracle::TrackedTableOracle;
use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, ROW_ID_COL_NAME};
use ark_ff::Field as _;
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use datafusion_common::Statistics;
use datafusion_expr::{Cast, ExprSchemable};
use indexmap::IndexMap;

use crate::irs::nodes::hints::HintDF;
use crate::irs::nodes::utils::division::Rounding;
use crate::irs::nodes::{
    IsExprNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
};
use crate::irs::payloads::PayloadStructure;
use crate::irs::tree::Tree;

pub(crate) enum Rescale {
    Up(u32),
    Down(Rounding),
}

/// `None` for a cast the proof has no check for.
pub(crate) fn rescale(from: &DataType, to: &DataType) -> Option<Rescale> {
    if from == to {
        return Some(Rescale::Up(0));
    }
    let scale = |data_type: &DataType| match data_type {
        DataType::Decimal128(_, scale) => Some(i32::from(*scale)),
        other if other.is_integer() => Some(0),
        _ => None,
    };
    let from_scale = match from {
        DataType::Boolean => 0,
        other => scale(other)?,
    };
    match scale(to)? - from_scale {
        k if k >= 0 => Some(Rescale::Up(k as u32)),
        // Arrow's decimal rescale rounds; its decimal-to-integer cast
        // truncates.
        _ if matches!(to, DataType::Decimal128(..)) => {
            Some(Rescale::Down(Rounding::HalfAwayFromZero))
        }
        _ => Some(Rescale::Down(Rounding::TowardZero)),
    }
}

fn output_field(hint: HintDF) -> FieldRef {
    hint.data_frame()
        .schema()
        .fields()
        .iter()
        .find(|field| !is_system_column(field.name()))
        .cloned()
        .expect("a cast outputs a data column")
}

pub struct ExprNode<B: SnarkBackend> {
    pub scope: Vec<std::sync::Weak<Node<B>>>,
    pub expr: Arc<Node<B>>,
    pub parent: Option<std::sync::Weak<Node<B>>>,
    pub cast: Cast,
    gadget: Arc<Node<B>>,
}

impl<B: SnarkBackend> ExprNode<B> {
    fn rescale(&self, from: &DataType) -> Rescale {
        rescale(from, &self.cast.data_type).unwrap_or_else(|| {
            panic!(
                "planning refuses a cast from {from} to {}",
                self.cast.data_type
            )
        })
    }
}

impl<B: SnarkBackend> IsNode<B> for ExprNode<B> {
    fn name(&self) -> String {
        "Cast".to_string()
    }

    fn display(&self) -> String {
        format!(
            "Cast\nInput: {}, data_type: {:?}",
            self.expr.name(),
            self.cast.data_type
        )
    }

    fn cost(
        &self,
        _statistics: Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.expr.clone(), self.gadget.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ExprNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let expr_id = self.expr.id();
        let expr_table = match virtualized_ir.payload_for_node(&expr_id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        let current_table = virtualized_ir
            .payload_for_node(&id)
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(table.clone()),
                _ => None,
            })
            .unwrap_or_default();

        let mut merged_polys = current_table.tracked_polys();
        let input = expr_table.tracked_col_by_ind(expr_table.data_tracked_polys_indices()[0]);
        let input_type = input
            .field_ref()
            .expect("a cast's input is typed")
            .data_type()
            .clone();
        if let Rescale::Up(k) = self.rescale(&input_type) {
            let data = input.data_tracked_poly();
            let data = if k == 0 {
                data
            } else {
                data.mul_scalar_poly(B::F::from(10u64).pow([u64::from(k)]))
            };
            merged_polys.insert(
                output_field(<Self as crate::irs::nodes::IsProverPlanNode<B>>::output(
                    self,
                )),
                data,
            );
        }
        if let Some((row_id_field, row_id_poly)) = expr_table
            .tracked_polys_iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
        {
            merged_polys
                .entry(row_id_field.clone())
                .or_insert_with(|| row_id_poly.clone());
        }
        if let Some(activator) = expr_table.activator_tracked_poly() {
            merged_polys.insert(ACTIVATOR_FIELD.clone(), activator);
        }

        let metadata = current_table
            .schema_ref()
            .map(|s| s.metadata().clone())
            .or_else(|| expr_table.schema_ref().map(|s| s.metadata().clone()))
            .unwrap_or_default();
        let fields = merged_polys
            .keys()
            .map(|f| f.as_ref().clone())
            .collect::<Vec<_>>();
        let schema = Some(Schema::new_with_metadata(fields, metadata));

        let log_size = match (current_table.log_size(), expr_table.log_size()) {
            (0, other) => other,
            (curr, 0) => curr,
            (curr, expr) => {
                debug_assert_eq!(curr, expr, "Cast log sizes should agree");
                curr
            }
        };

        let updated_table = TrackedTable::new(schema, merged_polys, log_size);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let table = |node_id: &NodeId| match virtualized_ir.payload_for_node(node_id) {
            Some(PayloadStructure::PlanPayload(table)) => Some(table.clone()),
            _ => None,
        };
        let (Some(input), Some(output)) = (table(&self.expr.id()), table(&id)) else {
            return Ok(());
        };
        let input_type = input
            .tracked_col_by_ind(input.data_tracked_polys_indices()[0])
            .field_ref()
            .expect("a cast's input is typed")
            .data_type()
            .clone();
        if let Rescale::Down(_) = self.rescale(&input_type) {
            virtualized_ir.set_payload_for_node(
                self.gadget.id(),
                Some(PayloadStructure::GadgetPayload(IndexMap::from([
                    (rescale::INPUT_LABEL.to_string(), input),
                    (rescale::OUTPUT_LABEL.to_string(), output),
                ]))),
            );
        }
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
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
        let scope = self.scope[0]
            .upgrade()
            .expect("Cast scope should be available during output");
        let scope_hint_df = match scope.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsProverPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Cast scope cannot be a gadget node"),
        };

        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(scope_hint_df.data_frame().clone())
                .expect("cast row-id sort should succeed");
        let input_type = self
            .cast
            .expr
            .get_type(input_df.schema())
            .expect("a cast's input is typed");
        let materialize = matches!(self.rescale(&input_type), Rescale::Down(_));

        let cast_expr = datafusion_expr::Expr::Cast(self.cast.clone());
        #[cfg(feature = "test-utils")]
        let cast_expr = if materialize {
            crate::test_utils::dishonest_prover::forge_rescale(cast_expr, &self.cast.data_type)
        } else {
            cast_expr
        };
        let mut exprs = vec![cast_expr];
        crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut exprs);
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);
        let projected = input_df
            .select(exprs)
            .expect("cast projection should succeed");

        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("cast output sort should succeed");
        let should_materialize = projected
            .schema()
            .fields()
            .iter()
            .map(|field| {
                (
                    field.clone(),
                    materialize && !is_system_column(field.name()),
                )
            })
            .collect();
        crate::irs::nodes::hints::HintDF::new(projected, should_materialize)
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for ExprNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let scope = self.scope[0]
            .upgrade()
            .expect("Cast scope should be available during output");
        let scope_hint_df = match scope.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Cast scope cannot be a gadget node"),
        };

        // Verifier planning only needs output schema/materialization metadata.
        // Avoid DataFusion projection execution for cast expressions.
        let input_schema = scope_hint_df.data_frame().schema().as_arrow();
        let input_type = self
            .cast
            .expr
            .get_type(scope_hint_df.data_frame().schema())
            .expect("a cast's input is typed");
        let materialize = matches!(self.rescale(&input_type), Rescale::Down(_));
        let cast_expr = datafusion_expr::Expr::Cast(self.cast.clone());
        let output_name = cast_expr.schema_name().to_string();

        let mut fields = vec![Field::new(output_name, self.cast.data_type.clone(), true)];
        fields.extend(
            input_schema
                .fields()
                .iter()
                .filter(|field| field.name() == ROW_ID_COL_NAME)
                .map(|field| field.as_ref().clone()),
        );
        fields.extend(
            input_schema
                .fields()
                .iter()
                .filter(|field| field.name() == ACTIVATOR_COL_NAME)
                .map(|field| field.as_ref().clone()),
        );

        let projected = crate::irs::nodes::hints::schema_only_df(fields);
        let should_materialize = projected
            .schema()
            .fields()
            .iter()
            .map(|field| {
                (
                    field.clone(),
                    materialize && !is_system_column(field.name()),
                )
            })
            .collect();
        crate::irs::nodes::hints::HintDF::new(projected, should_materialize)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ExprNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let expr_id = self.expr.id();
        let expr_table = match virtualized_ir.payload_for_node(&expr_id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        let (mut merged_oracles, current_log_size, current_metadata) =
            match virtualized_ir.payload_for_node(&id) {
                Some(PayloadStructure::PlanPayload(table)) => (
                    table.tracked_oracles(),
                    table.log_size(),
                    table.schema_ref().map(|s| s.metadata().clone()),
                ),
                _ => (Default::default(), 0, None),
            };

        let input =
            expr_table.tracked_col_oracle_by_ind(expr_table.data_tracked_oracles_indices()[0]);
        let input_type = input
            .field_ref()
            .expect("a cast's input is typed")
            .data_type()
            .clone();
        if let Rescale::Up(k) = self.rescale(&input_type) {
            let data = input.data_tracked_oracle();
            let data = if k == 0 {
                data
            } else {
                data.mul_scalar_oracle(B::F::from(10u64).pow([u64::from(k)]))
            };
            merged_oracles.insert(
                output_field(<Self as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                    self,
                )),
                data,
            );
        }
        if let Some((row_id_field, row_id_oracle)) = expr_table
            .tracked_oracles_iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
        {
            merged_oracles
                .entry(row_id_field.clone())
                .or_insert_with(|| row_id_oracle.clone());
        }
        if let Some(activator) = expr_table.activator_tracked_poly() {
            merged_oracles.insert(ACTIVATOR_FIELD.clone(), activator);
        }

        let metadata = current_metadata
            .or_else(|| expr_table.schema_ref().map(|s| s.metadata().clone()))
            .unwrap_or_default();
        let fields = merged_oracles
            .keys()
            .map(|f| f.as_ref().clone())
            .collect::<Vec<_>>();
        let schema = Some(Schema::new_with_metadata(fields, metadata));

        let log_size = match (current_log_size, expr_table.log_size()) {
            (0, other) => other,
            (curr, 0) => curr,
            (curr, expr) => {
                debug_assert_eq!(curr, expr, "Cast log sizes should agree");
                curr
            }
        };

        let updated_table = TrackedTableOracle::new(schema, merged_oracles, log_size);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let table = |node_id: &NodeId| match virtualized_ir.payload_for_node(node_id) {
            Some(PayloadStructure::PlanPayload(table)) => Some(table.clone()),
            _ => None,
        };
        let (Some(input), Some(output)) = (table(&self.expr.id()), table(&id)) else {
            return Ok(());
        };
        let input_type = input
            .tracked_col_oracle_by_ind(input.data_tracked_oracles_indices()[0])
            .field_ref()
            .expect("a cast's input is typed")
            .data_type()
            .clone();
        if let Rescale::Down(_) = self.rescale(&input_type) {
            virtualized_ir.set_payload_for_node(
                self.gadget.id(),
                Some(PayloadStructure::GadgetPayload(IndexMap::from([
                    (rescale::INPUT_LABEL.to_string(), input),
                    (rescale::OUTPUT_LABEL.to_string(), output),
                ]))),
            );
        }
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsExprNode<B> for ExprNode<B> {
    fn from_expr(
        expr: datafusion_expr::Expr,
        self_ref: std::sync::Weak<Node<B>>,
        parent: Option<std::sync::Weak<Node<B>>>,
        scope: Vec<std::sync::Weak<Node<B>>>,
    ) -> Self
    where
        Self: Sized,
    {
        let cast = match expr {
            datafusion_expr::Expr::Cast(col) => col,
            _ => panic!("Expected Cast expression"),
        };

        let expr_node = Tree::<B>::from_expr(&cast.expr, Some(self_ref.clone()), scope.clone())
            .root()
            .clone();

        Self {
            cast,
            expr: expr_node,
            scope,
            parent,
            gadget: Arc::new(Node::Gadget(Arc::new(rescale::RescaleNode::new()))),
        }
    }

    fn expr(&self) -> datafusion_expr::Expr {
        todo!()
    }

    fn parent(&self) -> crate::irs::nodes::PlanNode<B>
    where
        Self: Sized,
    {
        self.parent
            .as_ref()
            .and_then(|weak_ref| weak_ref.upgrade())
            .map(|arc_node| match arc_node.as_ref() {
                Node::Plan(plan_node) => plan_node.clone(),
                Node::Gadget(_) => panic!("Cast parent cannot be a gadget node"),
            })
            .expect("Cast node must have a parent")
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
