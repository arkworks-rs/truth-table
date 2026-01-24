use std::sync::Arc;

use arithmetic::table::TrackedTable;
use arithmetic::table_oracle::TrackedTableOracle;
use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{Field, Schema};
use datafusion_common::Statistics;
use datafusion_expr::expr::Alias;
use indexmap::IndexMap;

use crate::irs::nodes::{
    IsExprNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
};
use crate::irs::payloads::PayloadStructure;
use crate::irs::tree::Tree;

pub struct ProverNode<B: SnarkBackend> {
    pub scope: Vec<Arc<Node<B>>>,
    pub expr: Arc<Node<B>>,
    pub parent: Option<std::sync::Weak<Node<B>>>,
    pub alias: Alias,
}

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "Alias".to_string()
    }

    fn display(&self) -> String {
        format!(
            "Alias\nInput: {}, alias: {}, scope: {}",
            self.expr.name(),
            self.alias.name,
            self.scope
                .iter()
                .map(|n| n.name())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }

    fn cost(
        &self,
        _statistics: Statistics,
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

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let alias_name = self.alias.name.clone();

        let mut scope_table = None;
        for scope_node in &self.scope {
            let scope_id = scope_node.id();
            if let Some(PayloadStructure::PlanPayload(table)) =
                virtualized_ir.payload_for_node(&scope_id)
            {
                scope_table = Some(table.clone());
                break;
            }
        }
        let Some(scope_table) = scope_table else {
            return Ok(());
        };

        let mut tracked_polys = IndexMap::new();
        let mut schema_fields = Vec::new();
        let mut alias_applied = false;

        for (field, poly) in scope_table.tracked_polys_iter() {
            let new_field = if !alias_applied
                && field.name() != ACTIVATOR_COL_NAME
                && field.name() != ROW_ID_COL_NAME
            {
                alias_applied = true;
                let mut updated = Field::new(
                    alias_name.clone(),
                    field.data_type().clone(),
                    field.is_nullable(),
                );
                if !field.metadata().is_empty() {
                    updated = updated.with_metadata(field.metadata().clone());
                }
                Arc::new(updated)
            } else {
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
        let new_schema = scope_table
            .schema_ref()
            .map(|schema| Schema::new_with_metadata(fields.clone(), schema.metadata().clone()))
            .or_else(|| Some(Schema::new(fields)));

        let aliased_table = TrackedTable::new(new_schema, tracked_polys, scope_table.log_size());
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
}

impl<B: SnarkBackend> IsPlanNode<B> for ProverNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        None
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let mut projected = None;
        let mut last_error = None;
        for scope_node in &self.scope {
            let scope_hint_df = match scope_node.as_ref() {
                Node::Plan(plan_node) => plan_node.output(),
                Node::Gadget(_) => panic!("Alias scope cannot be a gadget node"),
            };

            let input_df = crate::irs::nodes::hints::sort_by_row_id_if_present(
                scope_hint_df.data_frame().clone(),
            )
            .expect("alias row-id sort should succeed");

            let mut exprs = vec![datafusion_expr::Expr::Alias(self.alias.clone())];
            crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut exprs);
            crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);
            match input_df.select(exprs) {
                Ok(df) => {
                    projected = Some(df);
                    break;
                }
                Err(err) => {
                    last_error = Some(err);
                }
            }
        }

        let projected = projected.unwrap_or_else(|| {
            panic!(
                "alias projection should succeed in some scope, last error: {:?}",
                last_error
            )
        });

        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("cast output sort should succeed");
        crate::irs::nodes::hints::HintDF::new_virtual(projected)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let alias_name = self.alias.name.clone();

        let mut scope_table = None;
        for scope_node in &self.scope {
            let scope_id = scope_node.id();
            if let Some(PayloadStructure::PlanPayload(table)) =
                virtualized_ir.payload_for_node(&scope_id)
            {
                scope_table = Some(table.clone());
                break;
            }
        }
        let Some(scope_table) = scope_table else {
            return Ok(());
        };

        let mut tracked_oracles = IndexMap::new();
        let mut schema_fields = Vec::new();
        let mut alias_applied = false;

        for (field, oracle) in scope_table.tracked_oracles_iter() {
            let new_field = if !alias_applied
                && field.name() != ACTIVATOR_COL_NAME
                && field.name() != ROW_ID_COL_NAME
            {
                alias_applied = true;
                let mut updated = Field::new(
                    alias_name.clone(),
                    field.data_type().clone(),
                    field.is_nullable(),
                );
                if !field.metadata().is_empty() {
                    updated = updated.with_metadata(field.metadata().clone());
                }
                Arc::new(updated)
            } else {
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
        let new_schema = scope_table
            .schema_ref()
            .map(|schema| Schema::new_with_metadata(fields.clone(), schema.metadata().clone()))
            .or_else(|| Some(Schema::new(fields)));

        let aliased_table =
            TrackedTableOracle::new(new_schema, tracked_oracles, scope_table.log_size());
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
}

impl<B: SnarkBackend> IsExprNode<B> for ProverNode<B> {
    fn from_expr(
        expr: datafusion_expr::Expr,
        _self_ref: std::sync::Weak<Node<B>>,
        parent: Option<std::sync::Weak<Node<B>>>,
        scope: Vec<std::sync::Arc<Node<B>>>,
    ) -> Self
    where
        Self: Sized,
    {
        let alias = match expr {
            datafusion_expr::Expr::Alias(alias) => alias,
            _ => panic!("Expected Alias expression"),
        };
        let expr_gadget = Tree::<B>::from_expr(&alias.expr, None, scope.clone())
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
        self.scope.clone()
    }
}
