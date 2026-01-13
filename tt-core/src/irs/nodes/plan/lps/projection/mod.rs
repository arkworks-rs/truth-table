use std::sync::{Arc, Weak};

use arithmetic::table_oracle::TrackedTableOracle;
use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::Schema;
use datafusion_expr::{LogicalPlan, Projection};
use indexmap::IndexMap;

use crate::irs::{
    nodes::{IsLpNode, IsNode, IsPlanNode, Node, ProverNodeOps, VerifierNodeOps},
    payloads::PayloadStructure,
    tree::Tree,
};

pub(super) mod hints;

pub struct ProverNode<B>
where
    B: SnarkBackend,
{
    projection: Projection,
    input: Arc<Node<B>>,
    exprs: Vec<Arc<Node<B>>>,
}

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "Projection".to_string()
    }

    fn display(&self) -> String {
        let exprs = if self.exprs.is_empty() {
            "none".to_string()
        } else {
            self.exprs
                .iter()
                .map(|node| node.name())
                .collect::<Vec<_>>()
                .join(", ")
        };
        format!("Projection\nInput: {}, exprs: {}", self.input.name(), exprs)
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
        let mut out = Vec::with_capacity(1 + self.exprs.len());
        out.push(self.input.clone());
        out.extend(self.exprs.iter().cloned());
        out
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Collect the tracked tables produced by each projection expression.
        let mut output_cols: IndexMap<_, _> = IndexMap::new();
        let mut activator: Option<(datafusion::arrow::datatypes::FieldRef, _)> = None;
        let mut row_id: Option<(datafusion::arrow::datatypes::FieldRef, _)> = None;
        let mut log_size: Option<usize> = None;

        for expr_node in &self.exprs {
            let expr_id = expr_node.id();
            let expr_table = match virtualized_ir.payload_for_node(&expr_id) {
                Some(PayloadStructure::PlanPayload(table)) => table.clone(),
                _ => panic!("Projection expression missing tracked table payload"),
            };

            // Keep the first activator we see; all expression nodes share the same one.
            if activator.is_none() {
                let activator_field = expr_table
                    .tracked_polys()
                    .keys()
                    .find(|field| field.name() == ACTIVATOR_COL_NAME)
                    .cloned()
                    .expect("expression table should carry an activator column");
                let activator_poly = expr_table
                    .activator_tracked_poly()
                    .expect("expression table should carry an activator polynomial");
                activator = Some((activator_field, activator_poly));
            }
            if row_id.is_none() {
                let row_id_field = expr_table
                    .tracked_polys()
                    .keys()
                    .find(|field| field.name() == ROW_ID_COL_NAME)
                    .cloned();
                if let Some(field) = row_id_field {
                    let row_id_poly = expr_table
                        .tracked_polys()
                        .get(&field)
                        .expect("row id field should be in tracked polys")
                        .clone();
                    row_id = Some((field, row_id_poly));
                }
            }

            let expr_log_size = expr_table.log_size();
            if let Some(ls) = log_size {
                debug_assert_eq!(ls, expr_log_size);
            } else {
                log_size = Some(expr_log_size);
            }

            // Each expression contributes its data columns (excluding activator) to the projection output.
            let tracked_polys = expr_table.tracked_polys();
            for idx in expr_table.data_tracked_polys_indices() {
                let (field, poly) = tracked_polys
                    .get_index(idx)
                    .expect("expression column index should be in bounds");
                output_cols.insert(field.clone(), poly.clone());
            }
        }

        // Append system columns in a stable order: row_id then activator.
        if let Some((field, poly)) = row_id {
            output_cols.insert(field, poly);
        }
        if let Some((field, poly)) = activator {
            output_cols.insert(field, poly);
        } else {
            panic!("Projection expected at least one activator column from its expressions");
        }

        // Build the output schema in projection order + activator.
        let schema = Schema::new(
            output_cols
                .keys()
                .map(|f| f.as_ref().clone())
                .collect::<Vec<_>>(),
        );
        let log_size = log_size.unwrap_or(0);
        let projected_table =
            arithmetic::table::TrackedTable::new(Some(schema), output_cols, log_size);
        virtualized_ir
            .set_payload_for_node(id, Some(PayloadStructure::PlanPayload(projected_table)));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
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
        // Evaluate the projection against the virtual/physical data produced by the
        // child node, then keep the result virtual (no eager materialization).
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("Projection input cannot be a gadget node"),
        };

        let projected = hints::build_output_dataframe(input_hint_df.data_frame(), &self.projection);
        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("projection output sort should succeed");
        crate::irs::nodes::hints::HintDF::new_virtual(projected)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Mirror the prover behavior: stitch together the projection outputs from the
        // tracked oracles produced by each expression node.
        let mut output_cols: IndexMap<_, _> = IndexMap::new();
        let mut activator: Option<(datafusion::arrow::datatypes::FieldRef, _)> = None;
        let mut row_id: Option<(datafusion::arrow::datatypes::FieldRef, _)> = None;
        let mut log_size: Option<usize> = None;

        for expr_node in &self.exprs {
            let expr_id = expr_node.id();
            let expr_table = match virtualized_ir.payload_for_node(&expr_id) {
                Some(PayloadStructure::PlanPayload(table)) => table.clone(),
                _ => panic!("Projection expression missing tracked oracle payload"),
            };

            if activator.is_none() {
                let activator_field = expr_table
                    .tracked_oracles()
                    .keys()
                    .find(|field| field.name() == ACTIVATOR_COL_NAME)
                    .cloned()
                    .expect("expression table should carry an activator column");
                let activator_oracle = expr_table
                    .tracked_oracles()
                    .get(&activator_field)
                    .expect("activator oracle should exist")
                    .clone();
                activator = Some((activator_field, activator_oracle));
            }

            if row_id.is_none() {
                let row_id_field = expr_table
                    .tracked_oracles()
                    .keys()
                    .find(|field| field.name() == ROW_ID_COL_NAME)
                    .cloned();
                if let Some(field) = row_id_field {
                    let row_id_oracle = expr_table
                        .tracked_oracles()
                        .get(&field)
                        .expect("row id oracle should exist")
                        .clone();
                    row_id = Some((field, row_id_oracle));
                }
            }

            let expr_log_size = expr_table.log_size();
            if let Some(ls) = log_size {
                debug_assert_eq!(ls, expr_log_size);
            } else {
                log_size = Some(expr_log_size);
            }

            let tracked_oracles = expr_table.tracked_oracles();
            for idx in expr_table.data_tracked_oracles_indices() {
                let (field, oracle) = tracked_oracles
                    .get_index(idx)
                    .expect("expression column index should be in bounds");
                output_cols.insert(field.clone(), oracle.clone());
            }
        }

        // Append system columns in a stable order: row_id then activator.
        if let Some((field, oracle)) = row_id {
            output_cols.insert(field, oracle);
        }
        if let Some((field, oracle)) = activator {
            output_cols.insert(field, oracle);
        } else {
            panic!("Projection expected at least one activator column from its expressions");
        }

        let schema = Schema::new(
            output_cols
                .keys()
                .map(|f| f.as_ref().clone())
                .collect::<Vec<_>>(),
        );
        let log_size = log_size.unwrap_or(0);
        let projected_table = TrackedTableOracle::new(Some(schema), output_cols, log_size);
        virtualized_ir
            .set_payload_for_node(id, Some(PayloadStructure::PlanPayload(projected_table)));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsLpNode<B> for ProverNode<B> {
    fn from_lp(plan: datafusion_expr::LogicalPlan, self_ref: Weak<Node<B>>) -> Self
    where
        Self: Sized,
    {
        let projection = match plan {
            LogicalPlan::Projection(p) => p,
            _ => panic!("expected projection logical plan"),
        };

        // Recurse into the input subtree and fetch the logical plan that feeds this
        // projection.
        let input = Tree::<B>::from_logical_plan(&projection.input)
            .root()
            .clone();
        // Build expression proof plans for the projection expressions (excluding the
        // retained activator).
        let exprs = projection
            .expr
            .iter()
            .map(|expr| {
                Tree::<B>::from_expr(expr, Some(self_ref.clone()), input.clone())
                    .root()
                    .clone()
            })
            .collect();

        Self {
            projection,
            input,
            exprs,
        }
    }

    fn lp(&self) -> LogicalPlan {
        LogicalPlan::Projection(self.projection.clone())
    }
}
