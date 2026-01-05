use std::{collections::HashSet, sync::Arc};

use arithmetic::{ACTIVATOR_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{FieldRef, Schema};
use datafusion_expr::{Aggregate, Expr, LogicalPlan};
use indexmap::IndexMap;

use crate::irs::{
    nodes::{IsLpNode, IsNode, IsPlanNode, Node, ProverNodeOps, VerifierNodeOps},
    payloads::PayloadStructure,
    tree::Tree,
};

mod hints;

pub struct ProverAggregateNode<B>
where
    B: SnarkBackend,
{
    // The aggregate information from DataFusion.
    aggregate: Aggregate,
    // The prover plan child node for the aggregate input.
    input: Arc<Node<B>>,
    // Aggregate expression child nodes (one per aggregate expression).
    aggr_exprs: Vec<Arc<Node<B>>>,
    // The aggregate gadget node.
    gadget: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for ProverAggregateNode<B> {
    fn name(&self) -> String {
        "Aggregate".to_string()
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        let mut children = vec![self.input.clone()];
        children.extend(self.aggr_exprs.iter().cloned());
        children.push(self.gadget.clone());
        children
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ProverAggregateNode<B> {
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
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
        let mut existing_names: HashSet<String> = merged_polys
            .keys()
            .map(|field| field.name().to_string())
            .collect();

        for (field, poly) in input_table.tracked_polys_iter() {
            if field.name() == ACTIVATOR_COL_NAME {
                continue;
            }
            if existing_names.contains(field.name()) {
                continue;
            }
            merged_polys.insert(field.clone(), poly.clone());
            existing_names.insert(field.name().to_string());
        }

        let metadata = current_table
            .schema_ref()
            .map(|s| s.metadata().clone())
            .or_else(|| input_table.schema_ref().map(|s| s.metadata().clone()))
            .unwrap_or_default();
        let fields = merged_polys
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        let schema = Some(Schema::new_with_metadata(fields, metadata));

        let log_size = match (current_table.log_size(), input_table.log_size()) {
            (0, other) => other,
            (current, 0) => current,
            (current, input) => {
                debug_assert_eq!(current, input, "Aggregate log sizes should match input");
                current
            }
        };

        let updated_table = TrackedTable::new(schema, merged_polys, log_size);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let current_table = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        let schema = match current_table.schema_ref() {
            Some(schema) => schema,
            None => return Ok(()),
        };

        let mut group_indices = Vec::with_capacity(self.aggregate.group_expr.len());
        for expr in &self.aggregate.group_expr {
            let Expr::Column(col) = expr else {
                panic!("Aggregate group expressions must be column references");
            };
            let idx = schema
                .index_of(&col.name)
                .expect("Aggregate group column missing from payload schema");
            group_indices.push(idx);
        }
        let groups_table = current_table.tracked_subtable_by_indices(&group_indices);

        debug_assert_eq!(
            self.aggregate.aggr_expr.len(),
            self.aggr_exprs.len(),
            "Aggregate aggr expr list must align with expr nodes"
        );

        for (expr, expr_node) in self.aggregate.aggr_expr.iter().zip(self.aggr_exprs.iter()) {
            let column_name = expr.schema_name().to_string();
            let col_idx = schema
                .index_of(&column_name)
                .expect("Aggregate result column missing from payload schema");
            let aggr_table = current_table.tracked_subtable_by_indices(&[col_idx]);

            let mut gadget_payload = match virtualized_ir.payload_for_node(&expr_node.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };

            gadget_payload.insert(
                crate::irs::nodes::plan::exprs::aggregate_function::INPUT_GROUPS_LABEL.to_string(),
                groups_table.clone(),
            );
            gadget_payload.insert(
                crate::irs::nodes::plan::exprs::aggregate_function::INPUT_AGGR_EXPR_LABEL
                    .to_string(),
                aggr_table,
            );

            virtualized_ir.set_payload_for_node(
                expr_node.id(),
                Some(PayloadStructure::GadgetPayload(gadget_payload)),
            );
        }
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ProverAggregateNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        Some(self.gadget.as_ref().clone())
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("Aggregate input cannot be a gadget node"),
        };

        let output = hints::build_output_dataframe(input_hint_df.data_frame(), &self.aggregate);

        let schema_fields = self.aggregate.schema.fields();
        let aggr_count = self.aggregate.aggr_expr.len();
        let aggr_start = schema_fields.len().saturating_sub(aggr_count);
        let aggregate_field_names: std::collections::HashSet<String> = schema_fields[aggr_start..]
            .iter()
            .map(|field| field.name().to_string())
            .collect();

        let should_materialize: IndexMap<FieldRef, bool> = output
            .schema()
            .fields()
            .iter()
            .map(|field| {
                (
                    field.clone(),
                    field.name() == ACTIVATOR_COL_NAME
                        || aggregate_field_names.contains(field.name()),
                )
            })
            .collect();

        crate::irs::nodes::hints::HintDF::new(output, should_materialize)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ProverAggregateNode<B> {
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
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

        let mut merged_oracles = current_table.tracked_oracles();
        let mut existing_names: HashSet<String> = merged_oracles
            .keys()
            .map(|field| field.name().to_string())
            .collect();

        for (field, oracle) in input_table.tracked_oracles_iter() {
            if field.name() == ACTIVATOR_COL_NAME {
                continue;
            }
            if existing_names.contains(field.name()) {
                continue;
            }
            merged_oracles.insert(field.clone(), oracle.clone());
            existing_names.insert(field.name().to_string());
        }

        let metadata = current_table
            .schema_ref()
            .map(|s| s.metadata().clone())
            .or_else(|| input_table.schema_ref().map(|s| s.metadata().clone()))
            .unwrap_or_default();
        let fields = merged_oracles
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        let schema = Some(Schema::new_with_metadata(fields, metadata));

        let log_size = match (current_table.log_size(), input_table.log_size()) {
            (0, other) => other,
            (current, 0) => current,
            (current, input) => {
                debug_assert_eq!(current, input, "Aggregate log sizes should match input");
                current
            }
        };

        let updated_table = TrackedTableOracle::new(schema, merged_oracles, log_size);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let current_table = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        let schema = match current_table.schema_ref() {
            Some(schema) => schema,
            None => return Ok(()),
        };

        let mut group_indices = Vec::with_capacity(self.aggregate.group_expr.len());
        for expr in &self.aggregate.group_expr {
            let Expr::Column(col) = expr else {
                panic!("Aggregate group expressions must be column references");
            };
            let idx = schema
                .index_of(&col.name)
                .expect("Aggregate group column missing from payload schema");
            group_indices.push(idx);
        }
        let groups_table = current_table.tracked_subtable_by_indices(&group_indices);

        debug_assert_eq!(
            self.aggregate.aggr_expr.len(),
            self.aggr_exprs.len(),
            "Aggregate aggr expr list must align with expr nodes"
        );

        for (expr, expr_node) in self.aggregate.aggr_expr.iter().zip(self.aggr_exprs.iter()) {
            let column_name = expr.schema_name().to_string();
            let col_idx = schema
                .index_of(&column_name)
                .expect("Aggregate result column missing from payload schema");
            let aggr_table = current_table.tracked_subtable_by_indices(&[col_idx]);

            let mut gadget_payload = match virtualized_ir.payload_for_node(&expr_node.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };

            gadget_payload.insert(
                crate::irs::nodes::plan::exprs::aggregate_function::INPUT_GROUPS_LABEL.to_string(),
                groups_table.clone(),
            );
            gadget_payload.insert(
                crate::irs::nodes::plan::exprs::aggregate_function::INPUT_AGGR_EXPR_LABEL
                    .to_string(),
                aggr_table,
            );

            virtualized_ir.set_payload_for_node(
                expr_node.id(),
                Some(PayloadStructure::GadgetPayload(gadget_payload)),
            );
        }
        Ok(())
    }
}

impl<B: SnarkBackend> IsLpNode<B> for ProverAggregateNode<B> {
    fn from_lp(plan: LogicalPlan, _self_ref: std::sync::Weak<Node<B>>) -> Self
    where
        Self: Sized,
    {
        let aggregate = match plan {
            LogicalPlan::Aggregate(p) => p,
            _ => panic!("expected aggregate logical plan"),
        };

        let input = Tree::<B>::from_logical_plan(&aggregate.input)
            .root()
            .clone();

        let aggr_exprs = aggregate
            .aggr_expr
            .iter()
            .map(|expr| {
                Tree::<B>::from_expr(expr, Some(_self_ref.clone()), input.clone())
                    .root()
                    .clone()
            })
            .collect();

        let gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::lps::aggregate::GadgetNode::new(),
        )));

        Self {
            aggregate,
            input,
            aggr_exprs,
            gadget,
        }
    }

    fn lp(&self) -> LogicalPlan {
        LogicalPlan::Aggregate(self.aggregate.clone())
    }
}
