use std::{collections::HashSet, sync::Arc};

use arithmetic::{
    ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_ff::One;
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{Field, FieldRef, Schema};
use datafusion_expr::{Aggregate, Expr, LogicalPlan};
use either::Either;
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
    // Group-by expression child nodes (one per group expression).
    group_exprs: Vec<Arc<Node<B>>>,
    // Aggregate expression child nodes (one per aggregate expression).
    aggr_exprs: Vec<Arc<Node<B>>>,
    // The aggregate gadget node.
    gadget: Arc<Node<B>>,
}

const AGG_GROUP_KEY_COL_NAME: &str = "__agg_group_key__";

fn agg_group_key_field() -> FieldRef {
    Arc::new(Field::new(
        AGG_GROUP_KEY_COL_NAME,
        datafusion::arrow::datatypes::DataType::Boolean,
        false,
    ))
}

fn constant_one_poly_from_table<B: SnarkBackend>(
    table: &TrackedTable<B>,
) -> Option<ark_piop::prover::structs::polynomial::TrackedPoly<B>> {
    table.tracked_polys_iter().next().map(|(_, poly)| {
        // Use a constant tracked polynomial so no new commitments are introduced.
        ark_piop::prover::structs::polynomial::TrackedPoly::new(
            Either::Right(B::F::one()),
            poly.log_size(),
            poly.tracker(),
        )
    })
}

fn constant_one_oracle_from_table<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
) -> Option<ark_piop::verifier::structs::oracle::TrackedOracle<B>> {
    table.tracked_oracles_iter().next().map(|(_, oracle)| {
        // Use a constant tracked oracle so no new commitments are introduced.
        ark_piop::verifier::structs::oracle::TrackedOracle::new(
            Either::Right(B::F::one()),
            oracle.tracker(),
            oracle.log_size(),
        )
    })
}

fn single_group_table<B: SnarkBackend>(table: &TrackedTable<B>) -> Option<TrackedTable<B>> {
    let group_key = constant_one_poly_from_table(table)?;
    let mut polys = IndexMap::new();
    // Use a deterministic constant group key when there are no group-by expressions.
    polys.insert(agg_group_key_field(), group_key);
    if let Some(activator) = table.activator_tracked_poly() {
        polys.insert(ACTIVATOR_FIELD.clone(), activator);
    }
    let metadata = table
        .schema_ref()
        .map(|schema| schema.metadata().clone())
        .unwrap_or_default();
    let fields = polys
        .keys()
        .map(|field| field.as_ref().clone())
        .collect::<Vec<_>>();
    let schema = Some(Schema::new_with_metadata(fields, metadata));
    Some(TrackedTable::new(schema, polys, table.log_size()))
}

fn single_group_oracle<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
) -> Option<TrackedTableOracle<B>> {
    let group_key = constant_one_oracle_from_table(table)?;
    let mut oracles = IndexMap::new();
    // Use a deterministic constant group key when there are no group-by expressions.
    oracles.insert(agg_group_key_field(), group_key);
    if let Some(activator) = table.activator_tracked_poly() {
        oracles.insert(ACTIVATOR_FIELD.clone(), activator);
    }
    let metadata = table
        .schema_ref()
        .map(|schema| schema.metadata().clone())
        .unwrap_or_default();
    let fields = oracles
        .keys()
        .map(|field| field.as_ref().clone())
        .collect::<Vec<_>>();
    let schema = Some(Schema::new_with_metadata(fields, metadata));
    Some(TrackedTableOracle::new(schema, oracles, table.log_size()))
}

impl<B: SnarkBackend> IsNode<B> for ProverAggregateNode<B> {
    fn name(&self) -> String {
        "Aggregate".to_string()
    }

    fn display(&self) -> String {
        let groups = if self.group_exprs.is_empty() {
            "none".to_string()
        } else {
            self.group_exprs
                .iter()
                .map(|node| node.name())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let aggs = if self.aggr_exprs.is_empty() {
            "none".to_string()
        } else {
            self.aggr_exprs
                .iter()
                .map(|node| node.name())
                .collect::<Vec<_>>()
                .join(", ")
        };
        format!(
            "Aggregate\nInput: {}, groups: {}, aggs: {}",
            self.input.name(),
            groups,
            aggs
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
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let input_hint_df = match planned_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df.clone(),
            _ => return Ok(()),
        };
        let output_hint_df = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df.clone(),
            _ => return Ok(()),
        };

        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(input_hint_df.data_frame().clone())
                .expect("aggregate input row-id sort should succeed");
        let output_df = crate::irs::nodes::hints::sort_by_row_id_if_present(
            output_hint_df.data_frame().clone(),
        )
        .expect("aggregate output row-id sort should succeed");

        let mut input_projection_exprs = self.aggregate.group_expr.clone();
        crate::irs::nodes::hints::append_activator_exprs_if_present(
            &input_df,
            &mut input_projection_exprs,
        );
        crate::irs::nodes::hints::append_row_id_expr_if_present(
            &input_df,
            &mut input_projection_exprs,
        );

        let mut output_projection_exprs = self.aggregate.group_expr.clone();
        crate::irs::nodes::hints::append_activator_exprs_if_present(
            &output_df,
            &mut output_projection_exprs,
        );
        crate::irs::nodes::hints::append_row_id_expr_if_present(
            &output_df,
            &mut output_projection_exprs,
        );

        let input_projected = input_df
            .select(input_projection_exprs)
            .expect("aggregate input group projection should succeed");
        let output_projected = output_df
            .select(output_projection_exprs)
            .expect("aggregate output group projection should succeed");

        let input_projected = crate::irs::nodes::hints::sort_by_row_id_if_present(input_projected)
            .expect("aggregate input group sort should succeed");
        let output_projected =
            crate::irs::nodes::hints::sort_by_row_id_if_present(output_projected)
                .expect("aggregate output group sort should succeed");

        let input_groups_hint = crate::irs::nodes::hints::HintDF::new_virtual(input_projected);
        let output_groups_hint = crate::irs::nodes::hints::HintDF::new_virtual(output_projected);

        let mut gadget_payload = match planned_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };

        gadget_payload.insert(
            crate::irs::nodes::gadget::lps::aggregate::INPUT_LABEL.to_string(),
            input_groups_hint,
        );
        gadget_payload.insert(
            crate::irs::nodes::gadget::lps::aggregate::OUTPUT_LABEL.to_string(),
            output_groups_hint,
        );

        planned_ir.set_payload_for_node(
            self.gadget.id(),
            Some(PayloadStructure::GadgetPayload(gadget_payload)),
        );
        Ok(())
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        let mut children = vec![self.input.clone()];
        // The order of children matters for tree traversal.
        children.push(self.gadget.clone());
        children.extend(self.group_exprs.iter().cloned());
        children.extend(self.aggr_exprs.iter().cloned());
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

        // COUNT outputs are sourced from lookup multiplicities; override those
        // columns here instead of materializing separate aggregates.
        let count_output_names = count_output_names(&self.aggregate.aggr_expr);
        if !count_output_names.is_empty() {
            let multiplicities_table =
                lookup_super_multiplicities_table(&self.gadget, virtualized_ir)
                    .expect("Lookup super multiplicities missing for count aggregate");
            let data_indices = multiplicities_table.data_tracked_polys_indices();
            if data_indices.len() != 1 {
                panic!("Lookup multiplicities must have exactly one data column");
            }
            let multiplicity_col = multiplicities_table.tracked_col_by_ind(data_indices[0]);
            let multiplicity_field = multiplicity_col
                .field_ref()
                .expect("Lookup multiplicity column should have field metadata");
            let multiplicity_poly = multiplicity_col.data_tracked_poly();

            for col_name in count_output_names {
                let field_ref = merged_polys
                    .keys()
                    .find(|field| *field.name() == col_name)
                    .cloned()
                    .unwrap_or_else(|| {
                        Arc::new(Field::new(
                            col_name,
                            multiplicity_field.data_type().clone(),
                            multiplicity_field.is_nullable(),
                        ))
                    });
                merged_polys.insert(field_ref, multiplicity_poly.clone());
            }
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
        prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let current_table = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        // populate_aggregate_function_exprs(
        //     &self.aggregate,
        //     &self.aggr_exprs,
        //     &current_table,
        //     virtualized_ir,
        // )?;

        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => Some(table.clone()),
            _ => None,
        };
        if let Some(input_table) = input_table {
            populate_aggregate_gadget(
                &self.aggregate,
                &input_table,
                &current_table,
                self.gadget.id(),
                virtualized_ir,
            )?;
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
        let output = crate::irs::nodes::hints::sort_by_row_id_if_present(output)
            .expect("aggregate output sort should succeed");

        let schema_fields = self.aggregate.schema.fields();
        let aggr_count = self.aggregate.aggr_expr.len();
        let aggr_start = schema_fields.len().saturating_sub(aggr_count);
        // COUNT outputs are supplied by lookup multiplicities, so they should
        // remain virtual (do not materialize them here).
        let count_output_names: std::collections::HashSet<String> =
            count_output_names(&self.aggregate.aggr_expr)
                .into_iter()
                .collect();
        let aggregate_field_names: std::collections::HashSet<String> = schema_fields[aggr_start..]
            .iter()
            .map(|field| field.name().to_string())
            .filter(|name| !count_output_names.contains(name))
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

        // COUNT outputs are sourced from lookup multiplicities; override those
        // columns here instead of materializing separate aggregates.
        let count_output_names = count_output_names(&self.aggregate.aggr_expr);
        if !count_output_names.is_empty() {
            let multiplicities_table =
                lookup_super_multiplicities_oracle(&self.gadget, virtualized_ir)
                    .expect("Lookup super multiplicities missing for count aggregate");
            let data_indices = multiplicities_table.data_tracked_oracles_indices();
            if data_indices.len() != 1 {
                panic!("Lookup multiplicities must have exactly one data column");
            }
            let multiplicity_col = multiplicities_table.tracked_col_oracle_by_ind(data_indices[0]);
            let multiplicity_field = multiplicity_col
                .field_ref()
                .expect("Lookup multiplicity column should have field metadata");
            let multiplicity_oracle = multiplicity_col.data_tracked_oracle();

            for col_name in count_output_names {
                let field_ref = merged_oracles
                    .keys()
                    .find(|field| *field.name() == col_name)
                    .cloned()
                    .unwrap_or_else(|| {
                        Arc::new(Field::new(
                            col_name,
                            multiplicity_field.data_type().clone(),
                            multiplicity_field.is_nullable(),
                        ))
                    });
                merged_oracles.insert(field_ref, multiplicity_oracle.clone());
            }
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
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        fn populate_aggregate_function_exprs<B: SnarkBackend>(
            aggregate: &Aggregate,
            aggr_exprs: &[Arc<Node<B>>],
            current_table: &TrackedTableOracle<B>,
            virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
        ) -> ark_piop::errors::SnarkResult<()> {
            let schema = match current_table.schema_ref() {
                Some(schema) => schema,
                None => return Ok(()),
            };

            let mut group_indices = Vec::with_capacity(aggregate.group_expr.len());
            for expr in &aggregate.group_expr {
                let Expr::Column(col) = expr else {
                    panic!("Aggregate group expressions must be column references");
                };
                let idx = schema
                    .index_of(&col.name)
                    .expect("Aggregate group column missing from payload schema");
                group_indices.push(idx);
            }
            let groups_table = if group_indices.is_empty() {
                single_group_oracle(current_table)
                    .expect("Aggregate inputs must have at least one tracked oracle")
            } else {
                current_table.tracked_subtable_by_indices(&group_indices)
            };

            debug_assert_eq!(
                aggregate.aggr_expr.len(),
                aggr_exprs.len(),
                "Aggregate aggr expr list must align with expr nodes"
            );

            for (expr, expr_node) in aggregate.aggr_expr.iter().zip(aggr_exprs.iter()) {
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
                    crate::irs::nodes::plan::exprs::aggregate_function::OUTPUT_AGGR_EXPR_LABEL
                        .to_string(),
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

        fn populate_aggregate_gadget<B: SnarkBackend>(
            aggregate: &Aggregate,
            input_table: &TrackedTableOracle<B>,
            output_table: &TrackedTableOracle<B>,
            gadget_id: crate::irs::nodes::NodeId,
            virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
        ) -> ark_piop::errors::SnarkResult<()> {
            let input_schema = match input_table.schema_ref() {
                Some(schema) => schema,
                None => return Ok(()),
            };
            let output_schema = match output_table.schema_ref() {
                Some(schema) => schema,
                None => return Ok(()),
            };

            let mut input_group_indices = Vec::with_capacity(aggregate.group_expr.len() + 1);
            let mut output_group_indices = Vec::with_capacity(aggregate.group_expr.len() + 1);
            for expr in &aggregate.group_expr {
                let Expr::Column(col) = expr else {
                    panic!("Aggregate group expressions must be column references");
                };
                let input_idx = input_schema
                    .index_of(&col.name)
                    .expect("Aggregate input group column missing from payload schema");
                let output_idx = output_schema
                    .index_of(&col.name)
                    .expect("Aggregate output group column missing from payload schema");
                input_group_indices.push(input_idx);
                output_group_indices.push(output_idx);
            }
            if let Ok(input_idx) = input_schema.index_of(ACTIVATOR_COL_NAME) {
                if !input_group_indices.contains(&input_idx) {
                    input_group_indices.push(input_idx);
                }
            }
            if let Ok(output_idx) = output_schema.index_of(ACTIVATOR_COL_NAME) {
                if !output_group_indices.contains(&output_idx) {
                    output_group_indices.push(output_idx);
                }
            }

            let use_single_group = aggregate.group_expr.is_empty();
            let input_groups_table = if use_single_group {
                single_group_oracle(input_table)
                    .expect("Aggregate inputs must have at least one tracked oracle")
            } else {
                input_table.tracked_subtable_by_indices(&input_group_indices)
            };
            let output_groups_table = if use_single_group {
                single_group_oracle(output_table)
                    .expect("Aggregate outputs must have at least one tracked oracle")
            } else {
                output_table.tracked_subtable_by_indices(&output_group_indices)
            };

            let mut gadget_payload = match virtualized_ir.payload_for_node(&gadget_id) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };

            gadget_payload.insert(
                crate::irs::nodes::gadget::lps::aggregate::INPUT_LABEL.to_string(),
                input_groups_table,
            );
            gadget_payload.insert(
                crate::irs::nodes::gadget::lps::aggregate::OUTPUT_LABEL.to_string(),
                output_groups_table,
            );

            virtualized_ir.set_payload_for_node(
                gadget_id,
                Some(PayloadStructure::GadgetPayload(gadget_payload)),
            );
            Ok(())
        }

        let current_table = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        populate_aggregate_function_exprs(
            &self.aggregate,
            &self.aggr_exprs,
            &current_table,
            virtualized_ir,
        )?;

        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => Some(table.clone()),
            _ => None,
        };
        if let Some(input_table) = input_table {
            populate_aggregate_gadget(
                &self.aggregate,
                &input_table,
                &current_table,
                self.gadget.id(),
                virtualized_ir,
            )?;
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
        let group_exprs = aggregate
            .group_expr
            .iter()
            .map(|expr| {
                Tree::<B>::from_expr(expr, Some(_self_ref.clone()), input.clone())
                    .root()
                    .clone()
            })
            .collect();

        let gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::lps::aggregate::GadgetNode::new(aggregate.clone()),
        )));

        Self {
            aggregate,
            input,
            group_exprs,
            aggr_exprs,
            gadget,
        }
    }

    fn lp(&self) -> LogicalPlan {
        LogicalPlan::Aggregate(self.aggregate.clone())
    }
}
fn populate_aggregate_function_exprs<B: SnarkBackend>(
    aggregate: &Aggregate,
    aggr_exprs: &[Arc<Node<B>>],
    current_table: &TrackedTable<B>,
    prover: &mut ark_piop::prover::ArgProver<B>,
    virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let schema = match current_table.schema_ref() {
        Some(schema) => schema,
        None => return Ok(()),
    };

    let mut group_indices = Vec::with_capacity(aggregate.group_expr.len());
    for expr in &aggregate.group_expr {
        let Expr::Column(col) = expr else {
            panic!("Aggregate group expressions must be column references");
        };
        let idx = schema
            .index_of(&col.name)
            .expect("Aggregate group column missing from payload schema");
        group_indices.push(idx);
    }
    let groups_table = if group_indices.is_empty() {
        single_group_table(current_table)
            .expect("Aggregate inputs must have at least one tracked column")
    } else {
        current_table.tracked_subtable_by_indices(&group_indices)
    };

    debug_assert_eq!(
        aggregate.aggr_expr.len(),
        aggr_exprs.len(),
        "Aggregate aggr expr list must align with expr nodes"
    );

    for (expr, expr_node) in aggregate.aggr_expr.iter().zip(aggr_exprs.iter()) {
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
            crate::irs::nodes::plan::exprs::aggregate_function::OUTPUT_AGGR_EXPR_LABEL.to_string(),
            groups_table.clone(),
        );
        gadget_payload.insert(
            crate::irs::nodes::plan::exprs::aggregate_function::INPUT_AGGR_EXPR_LABEL.to_string(),
            aggr_table,
        );

        virtualized_ir.set_payload_for_node(
            expr_node.id(),
            Some(PayloadStructure::GadgetPayload(gadget_payload)),
        );
    }
    Ok(())
}

fn populate_aggregate_gadget<B: SnarkBackend>(
    aggregate: &Aggregate,
    input_table: &TrackedTable<B>,
    output_table: &TrackedTable<B>,
    gadget_id: crate::irs::nodes::NodeId,
    virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let input_schema = match input_table.schema_ref() {
        Some(schema) => schema,
        None => return Ok(()),
    };
    let output_schema = match output_table.schema_ref() {
        Some(schema) => schema,
        None => return Ok(()),
    };

    let mut input_group_indices = Vec::with_capacity(aggregate.group_expr.len() + 1);
    let mut output_group_indices = Vec::with_capacity(aggregate.group_expr.len() + 1);
    for expr in &aggregate.group_expr {
        let Expr::Column(col) = expr else {
            panic!("Aggregate group expressions must be column references");
        };
        let input_idx = input_schema
            .index_of(&col.name)
            .expect("Aggregate input group column missing from payload schema");
        let output_idx = output_schema
            .index_of(&col.name)
            .expect("Aggregate output group column missing from payload schema");
        input_group_indices.push(input_idx);
        output_group_indices.push(output_idx);
    }
    if let Ok(input_idx) = input_schema.index_of(ACTIVATOR_COL_NAME) {
        if !input_group_indices.contains(&input_idx) {
            input_group_indices.push(input_idx);
        }
    }
    if let Ok(output_idx) = output_schema.index_of(ACTIVATOR_COL_NAME) {
        if !output_group_indices.contains(&output_idx) {
            output_group_indices.push(output_idx);
        }
    }

    let use_single_group = aggregate.group_expr.is_empty();
    let input_groups_table = if use_single_group {
        single_group_table(input_table)
            .expect("Aggregate inputs must have at least one tracked column")
    } else {
        input_table.tracked_subtable_by_indices(&input_group_indices)
    };
    let output_groups_table = if use_single_group {
        single_group_table(output_table)
            .expect("Aggregate outputs must have at least one tracked column")
    } else {
        output_table.tracked_subtable_by_indices(&output_group_indices)
    };

    let mut gadget_payload = match virtualized_ir.payload_for_node(&gadget_id) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };

    gadget_payload.insert(
        crate::irs::nodes::gadget::lps::aggregate::INPUT_LABEL.to_string(),
        input_groups_table,
    );
    gadget_payload.insert(
        crate::irs::nodes::gadget::lps::aggregate::OUTPUT_LABEL.to_string(),
        output_groups_table,
    );

    virtualized_ir.set_payload_for_node(
        gadget_id,
        Some(PayloadStructure::GadgetPayload(gadget_payload)),
    );
    Ok(())
}

fn count_output_names(aggr_exprs: &[Expr]) -> Vec<String> {
    fn is_count_expr(expr: &Expr) -> bool {
        match expr {
            Expr::AggregateFunction(func) => func.func.name() == "count",
            Expr::Alias(alias) => is_count_expr(&alias.expr),
            _ => false,
        }
    }

    aggr_exprs
        .iter()
        .filter(|expr| is_count_expr(expr))
        .map(|expr| expr.schema_name().to_string())
        .collect()
}

fn lookup_super_multiplicities_table<B: SnarkBackend>(
    aggregate_gadget: &Arc<Node<B>>,
    virtualized_ir: &crate::prover::irs::VirtualizedIr<B>,
) -> Option<TrackedTable<B>> {
    let supp_node = aggregate_gadget.children().into_iter().next()?;
    let lookup_node = supp_node
        .children()
        .into_iter()
        .find(|child| child.name() == "Lookup")?;
    match virtualized_ir.payload_for_node(&lookup_node.id())? {
        PayloadStructure::GadgetPayload(map) => map
            .get(crate::irs::nodes::gadget::utils::lookup::SUPER_MULTIPLICITIES_LABEL)
            .cloned(),
        _ => None,
    }
}

fn lookup_super_multiplicities_oracle<B: SnarkBackend>(
    aggregate_gadget: &Arc<Node<B>>,
    virtualized_ir: &crate::verifier::irs::VirtualizedIr<B>,
) -> Option<TrackedTableOracle<B>> {
    let supp_node = aggregate_gadget.children().into_iter().next()?;
    let lookup_node = supp_node
        .children()
        .into_iter()
        .find(|child| child.name() == "Lookup")?;
    match virtualized_ir.payload_for_node(&lookup_node.id())? {
        PayloadStructure::GadgetPayload(map) => map
            .get(crate::irs::nodes::gadget::utils::lookup::SUPER_MULTIPLICITIES_LABEL)
            .cloned(),
        _ => None,
    }
}
