use std::sync::Arc;

use arithmetic::encoding::is_segment_of;
use arithmetic::table::TrackedTable;
use arithmetic::table_oracle::TrackedTableOracle;
use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use datafusion_common::Statistics;
use datafusion_expr::{ExprSchemable, expr::Alias};
use indexmap::IndexMap;

use crate::irs::nodes::{
    IsExprNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
    plan::lps::projection::forwards_side_columns,
};
use crate::irs::payloads::PayloadStructure;
use crate::irs::tree::Tree;

pub struct ExprNode<B: SnarkBackend> {
    pub scope: Vec<std::sync::Weak<Node<B>>>,
    pub expr: Arc<Node<B>>,
    pub parent: Option<std::sync::Weak<Node<B>>>,
    pub alias: Alias,
}

/// The side columns an aliased table passes on, when column references pass
/// theirs ([`forwards_side_columns`]): those of the aliased column `base`
/// renamed after `alias`, the others as they are.
fn aliased_side_cols<T>(
    side_cols: IndexMap<FieldRef, T>,
    base: Option<&str>,
    alias: &str,
) -> IndexMap<FieldRef, T> {
    if !forwards_side_columns() {
        return IndexMap::new();
    }
    side_cols
        .into_iter()
        .map(|(field, side)| match base {
            Some(base) if is_segment_of(field.name(), base) => {
                let renamed = Field::new(
                    format!("{alias}{}", &field.name()[base.len()..]),
                    field.data_type().clone(),
                    field.is_nullable(),
                )
                .with_metadata(field.metadata().clone());
                (Arc::new(renamed), side)
            }
            _ => (field, side),
        })
        .collect()
}

impl<B: SnarkBackend> IsNode<B> for ExprNode<B> {
    fn name(&self) -> String {
        "Alias".to_string()
    }

    fn display(&self) -> String {
        format!(
            "Alias\nInput: {}, alias: {}, scope: {}",
            self.expr.name(),
            self.alias.name,
            self.scope()[0].name()
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
        vec![self.expr.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ExprNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let alias_name = self.alias.name.clone();

        let expr_table = match virtualized_ir.payload_for_node(&self.expr.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        let mut tracked_polys = IndexMap::new();
        let mut schema_fields = Vec::new();
        let mut primary_base: Option<String> = None;
        let mut in_aliased_run = false;

        for (field, poly) in expr_table.tracked_polys_iter() {
            // The alias goes to the first non-system column and to its
            // segments (e.g. `n_name__length`), keeping field metadata.
            // `tracked_polys_iter` yields a primary followed by its own
            // segments, so those are the run right after it. Matching
            // segments by name alone would also re-base a same-named column's
            // segments (an un-aliased self-join, e.g. TPC-H Q7's two `nation`s).
            let new_field = if primary_base.is_none()
                && field.name() != ACTIVATOR_COL_NAME
                && field.name() != ROW_ID_COL_NAME
            {
                primary_base = Some(field.name().to_string());
                in_aliased_run = true;
                let mut updated = Field::new(
                    alias_name.clone(),
                    field.data_type().clone(),
                    field.is_nullable(),
                );
                if !field.metadata().is_empty() {
                    updated = updated.with_metadata(field.metadata().clone());
                }
                Arc::new(updated)
            } else if in_aliased_run
                && let Some(base) = primary_base.as_deref()
                && field.name() != base
                && is_segment_of(field.name(), base)
            {
                let suffix = &field.name()[base.len()..];
                let mut updated = Field::new(
                    format!("{}{}", alias_name, suffix),
                    field.data_type().clone(),
                    field.is_nullable(),
                );
                if !field.metadata().is_empty() {
                    updated = updated.with_metadata(field.metadata().clone());
                }
                Arc::new(updated)
            } else {
                in_aliased_run = false;
                field.clone()
            };
            schema_fields.push(new_field.clone());
            tracked_polys.insert(new_field, poly.clone());
        }

        let fields: Vec<Field> = schema_fields
            .iter()
            .map(|field_ref| field_ref.as_ref().clone())
            .collect();
        // Rebuild a schema that reflects the aliased column name so later lookups can resolve it.
        let new_schema = expr_table
            .schema_ref()
            .map(|schema| Schema::new_with_metadata(fields.clone(), schema.metadata().clone()))
            .or_else(|| Some(Schema::new(fields)));

        let side_cols =
            aliased_side_cols(expr_table.side_cols(), primary_base.as_deref(), &alias_name);
        let aliased_table = TrackedTable::new_with_side_cols(
            new_schema,
            tracked_polys,
            expr_table.log_size(),
            side_cols,
        );
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(aliased_table)));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
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
        None
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsProverPlanNode<B> for ExprNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let scope = self.scope[0]
            .upgrade()
            .expect("Alias scope should be available during output");
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

        let mut exprs = vec![datafusion_expr::Expr::Alias(self.alias.clone())];
        crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut exprs);
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);
        let projected = input_df
            .select(exprs)
            .expect("cast projection should succeed");

        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("cast output sort should succeed");
        crate::irs::nodes::hints::HintDF::new_virtual(projected)
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for ExprNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        // Keep verifier output traversal independent from prover traversal.
        let scope = self.scope[0]
            .upgrade()
            .expect("Alias scope should be available during output");
        let scope_hint_df = match scope.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Cast scope cannot be a gadget node"),
        };

        // Verifier planning only needs output schema/materialization metadata.
        // Avoid DataFusion projection execution for alias expressions.
        let input_schema = scope_hint_df.data_frame().schema().as_arrow();
        let alias_expr = datafusion_expr::Expr::Alias(self.alias.clone());
        let output_name = alias_expr.schema_name().to_string();
        let output_type = alias_expr
            .get_type(scope_hint_df.data_frame().schema())
            .unwrap_or(DataType::Null);

        let mut fields = vec![Field::new(output_name, output_type, true)];
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
        crate::irs::nodes::hints::HintDF::new_virtual(projected)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ExprNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let alias_name = self.alias.name.clone();

        let (tracked_oracles, new_schema, log_size, side_cols) =
            match virtualized_ir.payload_for_node(&self.expr.id()) {
                Some(PayloadStructure::PlanPayload(table)) => {
                    let mut tracked_oracles = IndexMap::new();
                    let mut schema_fields = Vec::new();
                    let mut primary_base: Option<String> = None;
                    let mut in_aliased_run = false;

                    for (field, oracle) in table.tracked_oracles_iter() {
                        // Same renaming as the prover side.
                        let new_field = if primary_base.is_none()
                            && field.name() != ACTIVATOR_COL_NAME
                            && field.name() != ROW_ID_COL_NAME
                        {
                            primary_base = Some(field.name().to_string());
                            in_aliased_run = true;
                            let mut updated = Field::new(
                                alias_name.clone(),
                                field.data_type().clone(),
                                field.is_nullable(),
                            );
                            if !field.metadata().is_empty() {
                                updated = updated.with_metadata(field.metadata().clone());
                            }
                            Arc::new(updated)
                        } else if in_aliased_run
                            && let Some(base) = primary_base.as_deref()
                            && field.name() != base
                            && is_segment_of(field.name(), base)
                        {
                            let suffix = &field.name()[base.len()..];
                            let mut updated = Field::new(
                                format!("{}{}", alias_name, suffix),
                                field.data_type().clone(),
                                field.is_nullable(),
                            );
                            if !field.metadata().is_empty() {
                                updated = updated.with_metadata(field.metadata().clone());
                            }
                            Arc::new(updated)
                        } else {
                            in_aliased_run = false;
                            field.clone()
                        };
                        schema_fields.push(new_field.clone());
                        tracked_oracles.insert(new_field, oracle.clone());
                    }

                    let fields: Vec<Field> = schema_fields
                        .iter()
                        .map(|field_ref| field_ref.as_ref().clone())
                        .collect();
                    // Rebuild a schema that reflects the aliased column name so later lookups can resolve it.
                    let new_schema = table
                        .schema_ref()
                        .map(|schema| {
                            Schema::new_with_metadata(fields.clone(), schema.metadata().clone())
                        })
                        .or_else(|| Some(Schema::new(fields)));
                    let side_cols =
                        aliased_side_cols(table.side_cols(), primary_base.as_deref(), &alias_name);
                    (tracked_oracles, new_schema, table.log_size(), side_cols)
                }
                _ => return Ok(()),
            };

        let aliased_table = TrackedTableOracle::new_with_side_cols(
            new_schema,
            tracked_oracles,
            log_size,
            side_cols,
        );
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(aliased_table)));
        Ok(())
    }
    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
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
        _self_ref: std::sync::Weak<Node<B>>,
        parent: Option<std::sync::Weak<Node<B>>>,
        scope: Vec<std::sync::Weak<Node<B>>>,
    ) -> Self
    where
        Self: Sized,
    {
        let alias = match expr {
            datafusion_expr::Expr::Alias(alias) => alias,
            _ => panic!("Expected Alias expression"),
        };
        // Preserve parent so aggregate expressions resolve against the aggregate plan.
        let expr_gadget = Tree::<B>::from_expr(&alias.expr, parent.clone(), scope.clone())
            .root()
            .clone();
        Self {
            alias,
            expr: expr_gadget,
            scope,
            parent,
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
