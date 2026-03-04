use std::{collections::HashSet, sync::Arc};

use arithmetic::{
    ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, ROW_ID_COL_NAME, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::{One, Zero};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{Field, FieldRef, Schema};
use datafusion_common::Column;
use datafusion_expr::{Aggregate, Expr, LogicalPlan};
use either::Either;
use indexmap::IndexMap;

use crate::irs::{
    nodes::{IsLpNode, IsNode, IsPlanNode, Node, ProverNodeOps, VerifierNodeOps},
    payloads::PayloadStructure,
    tree::Tree,
};

mod hints;

pub struct LpNode<B>
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
const QUALIFIER_METADATA_KEY: &str = "tt.qualifier";

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

impl<B: SnarkBackend> IsNode<B> for LpNode<B> {
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

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        let mut children = vec![self.input.clone()];
        // The order of children matters for tree traversal.
        children.push(self.gadget.clone());
        children.extend(self.group_exprs.iter().cloned());
        children.extend(self.aggr_exprs.iter().cloned());
        children
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for LpNode<B> {
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

        // Verifier planning only needs schema-aligned group payloads.
        // Avoid extra row-id sorting work here.
        let input_df = input_hint_df.data_frame().clone();
        let output_df = output_hint_df.data_frame().clone();

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
        let aggregate_output_names: HashSet<String> = self
            .aggregate
            .aggr_expr
            .iter()
            .map(|expr| expr.schema_name().to_string())
            .collect();
        let group_output_names: HashSet<String> = self
            .aggregate
            .group_expr
            .iter()
            .filter_map(|expr| match expr {
                Expr::Column(col) => Some(col.name.clone()),
                _ => None,
            })
            .collect();
        for (field, poly) in input_table.tracked_polys_iter() {
            if field.name() == ACTIVATOR_COL_NAME {
                continue;
            }
            // Keep aggregate outputs materialized by this node. Only group-by
            // columns are sourced virtually from input; other input columns
            // must not leak into the aggregate output when there are no groups.
            if aggregate_output_names.contains(field.name()) {
                continue;
            }
            if !group_output_names.contains(field.name()) {
                continue;
            }
            if let Some(existing_field) = merged_polys
                .keys()
                .find(|existing| existing.name() == field.name())
                .cloned()
            {
                merged_polys.swap_remove(&existing_field);
            }
            merged_polys.insert(field.clone(), poly.clone());
        }

        // COUNT outputs may be sourced from lookup multiplicities when present.
        // Only inject multiplicities if the COUNT column is missing from the
        // materialized aggregate output.
        let count_output_names = count_output_names(&self.aggregate.aggr_expr);
        if !count_output_names.is_empty()
            && lookup_super_multiplicities_table(&self.gadget, virtualized_ir).is_some()
        {
            let missing_count_outputs: Vec<String> = count_output_names
                .iter()
                .filter(|name| merged_polys.keys().all(|field| field.name() != *name))
                .cloned()
                .collect();
            if !missing_count_outputs.is_empty() {
                let multiplicities_table =
                    lookup_super_multiplicities_table(&self.gadget, virtualized_ir)
                        .expect("multiplicities should be available");
                let data_indices = multiplicities_table.data_tracked_polys_indices();
                if data_indices.len() != 1 {
                    panic!("Lookup multiplicities must have exactly one data column");
                }
                let multiplicity_col = multiplicities_table.tracked_col_by_ind(data_indices[0]);
                let multiplicity_field = multiplicity_col
                    .field_ref()
                    .expect("Lookup multiplicity column should have field metadata");
                let multiplicity_poly = multiplicity_col.data_tracked_poly();

                for col_name in missing_count_outputs {
                    let field_ref = Arc::new(Field::new(
                        col_name,
                        multiplicity_field.data_type().clone(),
                        multiplicity_field.is_nullable(),
                    ));
                    merged_polys.insert(field_ref, multiplicity_poly.clone());
                }
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

        // Prefer the aggregate output size from the planned payload even if it is 0
        // (e.g., a single-row aggregate). Only fall back to the input size when the
        // aggregate payload is missing.
        let log_size = if current_table.schema_ref().is_some() {
            current_table.log_size()
        } else {
            input_table.log_size()
        };

        let updated_table = TrackedTable::new(schema, merged_polys, log_size);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
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

impl<B: SnarkBackend> IsPlanNode<B> for LpNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        Some(self.gadget.as_ref().clone())
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsProverPlanNode<B> for LpNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsProverPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Aggregate input cannot be a gadget node"),
        };

        let output = hints::build_output_dataframe(input_hint_df.data_frame(), &self.aggregate);
        let output = crate::irs::nodes::hints::sort_by_row_id_if_present(output)
            .expect("aggregate output sort should succeed");

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

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for LpNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                    plan_node,
                )
            }
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

fn schema_field_for_column(
    schema: &datafusion::arrow::datatypes::Schema,
    column: &Column,
) -> Option<datafusion::arrow::datatypes::FieldRef> {
    let name = column.name();
    if let Some(relation) = column.relation.as_ref() {
        let relation_str = relation.to_string();
        if let Some(field) = schema.fields().iter().find(|field| {
            field.name() == name
                && field
                    .metadata()
                    .get(QUALIFIER_METADATA_KEY)
                    .is_some_and(|q| q == &relation_str)
        }) {
            return Some(field.clone());
        }
    }
    schema
        .fields()
        .iter()
        .find(|field| field.name() == name)
        .cloned()
}

fn aggregate_group_projection_fields(
    schema: &datafusion::arrow::datatypes::Schema,
    group_exprs: &[Expr],
) -> Vec<Field> {
    let mut fields = Vec::new();

    for expr in group_exprs {
        let Expr::Column(col) = expr else {
            continue;
        };
        if let Some(field_ref) = schema_field_for_column(schema, col)
            && fields.iter().all(|f: &Field| {
                f.name() != field_ref.name()
                    || f.metadata().get(QUALIFIER_METADATA_KEY)
                        != field_ref.metadata().get(QUALIFIER_METADATA_KEY)
            })
        {
            fields.push(field_ref.as_ref().clone());
        }
    }

    let row_id_choice = schema
        .fields()
        .iter()
        .filter(|field| field.name() == ROW_ID_COL_NAME)
        .find(|field| field.metadata().contains_key(QUALIFIER_METADATA_KEY))
        .cloned()
        .or_else(|| {
            let mut row_ids = schema
                .fields()
                .iter()
                .filter(|field| field.name() == ROW_ID_COL_NAME);
            let first = row_ids.next().cloned();
            if row_ids.next().is_none() {
                first
            } else {
                None
            }
        });
    if let Some(field_ref) = row_id_choice
        && fields.iter().all(|f| {
            f.name() != field_ref.name()
                || f.metadata().get(QUALIFIER_METADATA_KEY)
                    != field_ref.metadata().get(QUALIFIER_METADATA_KEY)
        })
    {
        fields.push(field_ref.as_ref().clone());
    }

    for field_ref in schema
        .fields()
        .iter()
        .filter(|field| field.name() == ACTIVATOR_COL_NAME)
    {
        if fields.iter().all(|f| {
            f.name() != field_ref.name()
                || f.metadata().get(QUALIFIER_METADATA_KEY)
                    != field_ref.metadata().get(QUALIFIER_METADATA_KEY)
        }) {
            fields.push(field_ref.as_ref().clone());
        }
    }

    fields
}

impl<B: SnarkBackend> VerifierNodeOps<B> for LpNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let (input_fields, output_fields) = {
            let input_hint_df = match planned_ir.payload_for_node(&self.input.id()) {
                Some(PayloadStructure::PlanPayload(hint_df)) => hint_df,
                _ => return Ok(()),
            };
            let output_hint_df = match planned_ir.payload_for_node(&id) {
                Some(PayloadStructure::PlanPayload(hint_df)) => hint_df,
                _ => return Ok(()),
            };
            (
                aggregate_group_projection_fields(
                    input_hint_df.data_frame().schema().as_arrow(),
                    &self.aggregate.group_expr,
                ),
                aggregate_group_projection_fields(
                    output_hint_df.data_frame().schema().as_arrow(),
                    &self.aggregate.group_expr,
                ),
            )
        };
        let input_groups_hint = crate::irs::nodes::hints::HintDF::new_virtual(
            crate::irs::nodes::hints::schema_only_df(input_fields),
        );
        let output_groups_hint = crate::irs::nodes::hints::HintDF::new_virtual(
            crate::irs::nodes::hints::schema_only_df(output_fields),
        );

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

    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table,
            _ => return Ok(()),
        };

        let current_table_opt = virtualized_ir
            .payload_for_node(&id)
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(table),
                _ => None,
            });

        let mut merged_oracles = current_table_opt
            .map(TrackedTableOracle::tracked_oracles)
            .unwrap_or_default();
        let aggregate_output_names: HashSet<String> = self
            .aggregate
            .aggr_expr
            .iter()
            .map(|expr| expr.schema_name().to_string())
            .collect();
        let group_output_names: HashSet<String> = self
            .aggregate
            .group_expr
            .iter()
            .filter_map(|expr| match expr {
                Expr::Column(col) => Some(col.name.clone()),
                _ => None,
            })
            .collect();
        for (field, oracle) in input_table.tracked_oracles_iter() {
            if field.name() == ACTIVATOR_COL_NAME {
                continue;
            }
            // Keep aggregate outputs materialized by this node. Only group-by
            // columns are sourced virtually from input; other input columns
            // must not leak into the aggregate output when there are no groups.
            if aggregate_output_names.contains(field.name()) {
                continue;
            }
            if !group_output_names.contains(field.name()) {
                continue;
            }
            if let Some(existing_field) = merged_oracles
                .keys()
                .find(|existing| existing.name() == field.name())
                .cloned()
            {
                merged_oracles.swap_remove(&existing_field);
            }
            merged_oracles.insert(field.clone(), oracle.clone());
        }

        // COUNT outputs may be sourced from lookup multiplicities when present.
        // Only inject multiplicities if the COUNT column is missing from the
        // materialized aggregate output.
        let count_output_names = count_output_names(&self.aggregate.aggr_expr);
        let lookup_multiplicities = lookup_super_multiplicities_oracle_ref(&self.gadget, virtualized_ir);
        if !count_output_names.is_empty() && lookup_multiplicities.is_some() {
            let missing_count_outputs: Vec<String> = count_output_names
                .iter()
                .filter(|name| merged_oracles.keys().all(|field| field.name() != *name))
                .cloned()
                .collect();
            if !missing_count_outputs.is_empty() {
                let multiplicities_table = lookup_multiplicities.expect("multiplicities should be available");
                let data_indices = multiplicities_table.data_tracked_oracles_indices();
                if data_indices.len() != 1 {
                    panic!("Lookup multiplicities must have exactly one data column");
                }
                let multiplicity_col =
                    multiplicities_table.tracked_col_oracle_by_ind(data_indices[0]);
                let multiplicity_field = multiplicity_col
                    .field_ref()
                    .expect("Lookup multiplicity column should have field metadata");
                let multiplicity_oracle = multiplicity_col.data_tracked_oracle();

                for col_name in missing_count_outputs {
                    let field_ref = Arc::new(Field::new(
                        col_name,
                        multiplicity_field.data_type().clone(),
                        multiplicity_field.is_nullable(),
                    ));
                    merged_oracles.insert(field_ref, multiplicity_oracle.clone());
                }
            }
        }

        let metadata = current_table_opt
            .and_then(TrackedTableOracle::schema_ref)
            .map(|s| s.metadata().clone())
            .or_else(|| input_table.schema_ref().map(|s| s.metadata().clone()))
            .unwrap_or_default();
        let fields = merged_oracles
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        let schema = Some(Schema::new_with_metadata(fields, metadata));

        // Mirror prover: trust the planned aggregate output size even if it is 0.
        let log_size = if current_table_opt.is_some() {
            current_table_opt
                .map(TrackedTableOracle::log_size)
                .expect("current aggregate table should exist when current_table_opt.is_some()")
        } else {
            input_table.log_size()
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
            let mut group_indices = Vec::with_capacity(aggregate.group_expr.len());
            for expr in &aggregate.group_expr {
                let Expr::Column(col) = expr else {
                    panic!("Aggregate group expressions must be column references");
                };
                let idx = find_tracked_oracle_index_by_column(current_table, col);
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

            let count_output_names: std::collections::HashSet<String> =
                count_output_names(&aggregate.aggr_expr)
                    .into_iter()
                    .collect();
            for (expr, expr_node) in aggregate.aggr_expr.iter().zip(aggr_exprs.iter()) {
                let column_name = expr.schema_name().to_string();
                if count_output_names.contains(&column_name) {
                    continue;
                }
                let col_idx = find_tracked_oracle_index_by_name(current_table, &column_name);
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
            let mut input_group_indices = Vec::with_capacity(aggregate.group_expr.len() + 1);
            let mut output_group_indices = Vec::with_capacity(aggregate.group_expr.len() + 1);
            for expr in &aggregate.group_expr {
                let Expr::Column(col) = expr else {
                    panic!("Aggregate group expressions must be column references");
                };
                let input_idx = find_tracked_oracle_index_by_column(input_table, col);
                let output_idx = find_tracked_oracle_index_by_column(output_table, col);
                input_group_indices.push(input_idx);
                output_group_indices.push(output_idx);
            }
            if let Some(input_idx) =
                find_tracked_oracle_index_by_name_optional(input_table, ACTIVATOR_COL_NAME)
                && !input_group_indices.contains(&input_idx)
            {
                input_group_indices.push(input_idx);
            }
            if let Some(output_idx) =
                find_tracked_oracle_index_by_name_optional(output_table, ACTIVATOR_COL_NAME)
                && !output_group_indices.contains(&output_idx)
            {
                output_group_indices.push(output_idx);
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

impl<B: SnarkBackend> IsLpNode<B> for LpNode<B> {
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
                Tree::<B>::from_expr(expr, Some(_self_ref.clone()), vec![Arc::downgrade(&input)])
                    .root()
                    .clone()
            })
            .collect();
        let group_exprs = aggregate
            .group_expr
            .iter()
            .map(|expr| {
                Tree::<B>::from_expr(expr, Some(_self_ref.clone()), vec![Arc::downgrade(&input)])
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
#[allow(unused)]
fn populate_aggregate_function_exprs<B: SnarkBackend>(
    aggregate: &Aggregate,
    aggr_exprs: &[Arc<Node<B>>],
    current_table: &TrackedTable<B>,
    _prover: &mut ark_piop::prover::ArgProver<B>,
    virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let mut group_indices = Vec::with_capacity(aggregate.group_expr.len());
    for expr in &aggregate.group_expr {
        let Expr::Column(col) = expr else {
            panic!("Aggregate group expressions must be column references");
        };
        let idx = find_tracked_index_by_column(current_table, col);
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

    let count_output_names: std::collections::HashSet<String> =
        count_output_names(&aggregate.aggr_expr)
            .into_iter()
            .collect();
    for (expr, expr_node) in aggregate.aggr_expr.iter().zip(aggr_exprs.iter()) {
        let column_name = expr.schema_name().to_string();
        if count_output_names.contains(&column_name) {
            continue;
        }
        let col_idx = find_tracked_index_by_name(current_table, &column_name);
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
    let mut input_group_indices = Vec::with_capacity(aggregate.group_expr.len() + 1);
    let mut output_group_indices = Vec::with_capacity(aggregate.group_expr.len() + 1);
    for expr in &aggregate.group_expr {
        let Expr::Column(col) = expr else {
            panic!("Aggregate group expressions must be column references");
        };
        let input_idx = find_tracked_index_by_column(input_table, col);
        let output_idx = find_tracked_index_by_column(output_table, col);
        input_group_indices.push(input_idx);
        output_group_indices.push(output_idx);
    }
    if let Some(input_idx) = find_tracked_index_by_name_optional(input_table, ACTIVATOR_COL_NAME)
        && !input_group_indices.contains(&input_idx)
    {
        input_group_indices.push(input_idx);
    }
    if let Some(output_idx) = find_tracked_index_by_name_optional(output_table, ACTIVATOR_COL_NAME)
        && !output_group_indices.contains(&output_idx)
    {
        output_group_indices.push(output_idx);
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
    #[cfg(feature = "honest-prover")]
    {
        let sample_keys = |table: &TrackedTable<B>| {
            let row_count = 1usize << table.log_size();
            let activator = table
                .activator_tracked_poly()
                .map(|p| p.evaluations())
                .unwrap_or_else(|| vec![B::F::one(); row_count]);
            let data_indices = table.data_tracked_polys_indices();
            let col_evals = data_indices
                .iter()
                .map(|idx| {
                    table
                        .tracked_col_by_ind(*idx)
                        .data_tracked_poly()
                        .evaluations()
                })
                .collect::<Vec<_>>();
            let mut out = Vec::new();
            for i in 0..row_count {
                if activator[i].is_zero() {
                    continue;
                }
                let key = col_evals
                    .iter()
                    .map(|vals| format!("{}", vals[i]))
                    .collect::<Vec<_>>()
                    .join("|");
                out.push(key);
                if out.len() >= 5 {
                    break;
                }
            }
            out
        };
        let input_group_names = input_group_indices
            .iter()
            .map(|idx| {
                let f = input_table.tracked_col_by_ind(*idx).field_ref();
                f.map(|field| {
                    let qual = field_qualifier(&field).unwrap_or("<none>");
                    format!("#{idx}:{}@{}", field.name(), qual)
                })
                .unwrap_or_else(|| format!("#{idx}:<unknown>"))
            })
            .collect::<Vec<_>>();
        let output_group_names = output_group_indices
            .iter()
            .map(|idx| {
                let f = output_table.tracked_col_by_ind(*idx).field_ref();
                f.map(|field| {
                    let qual = field_qualifier(&field).unwrap_or("<none>");
                    format!("#{idx}:{}@{}", field.name(), qual)
                })
                .unwrap_or_else(|| format!("#{idx}:<unknown>"))
            })
            .collect::<Vec<_>>();
        let output_dupes = {
            let mut names = std::collections::HashMap::<String, usize>::new();
            for (field, _) in output_table.tracked_polys_iter() {
                *names.entry(field.name().to_string()).or_insert(0) += 1;
            }
            names
                .into_iter()
                .filter(|(_, c)| *c > 1)
                .collect::<Vec<_>>()
        };
        tracing::debug!(
            "Aggregate group wiring sample (prover): input_log_size={}, output_log_size={}, input_group_names={:?}, output_group_names={:?}, output_dupes={:?}, input_samples={:?}, output_samples={:?}",
            input_groups_table.log_size(),
            output_groups_table.log_size(),
            input_group_names,
            output_group_names,
            output_dupes,
            sample_keys(&input_groups_table),
            sample_keys(&output_groups_table)
        );
    }
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

fn field_qualifier(field: &FieldRef) -> Option<&str> {
    field
        .metadata()
        .get(QUALIFIER_METADATA_KEY)
        .map(|value| value.as_str())
}

fn find_tracked_index_by_column<B: SnarkBackend>(table: &TrackedTable<B>, col: &Column) -> usize {
    let qualifier = col.relation.as_ref().map(|q| q.to_string());
    find_tracked_index(
        table.tracked_polys().iter(),
        &col.name,
        qualifier.as_deref(),
    )
}

fn find_tracked_index_by_name<B: SnarkBackend>(table: &TrackedTable<B>, name: &str) -> usize {
    find_tracked_index(table.tracked_polys().iter(), name, None)
}

fn find_tracked_index_by_name_optional<B: SnarkBackend>(
    table: &TrackedTable<B>,
    name: &str,
) -> Option<usize> {
    table
        .tracked_polys()
        .iter()
        .position(|(field, _)| field.name() == name)
}

fn find_tracked_oracle_index_by_column<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    col: &Column,
) -> usize {
    let qualifier = col.relation.as_ref().map(|q| q.to_string());
    find_tracked_index(
        table.tracked_oracles().iter(),
        &col.name,
        qualifier.as_deref(),
    )
}

fn find_tracked_oracle_index_by_name<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    name: &str,
) -> usize {
    find_tracked_index(table.tracked_oracles().iter(), name, None)
}

fn find_tracked_oracle_index_by_name_optional<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    name: &str,
) -> Option<usize> {
    table
        .tracked_oracles()
        .iter()
        .position(|(field, _)| field.name() == name)
}

fn find_tracked_index<'a, T: 'a, I>(iter: I, name: &str, qualifier: Option<&str>) -> usize
where
    I: Iterator<Item = (&'a FieldRef, &'a T)>,
{
    let mut name_matches = Vec::new();
    let mut qualifier_matches = Vec::new();

    for (idx, (field, _)) in iter.enumerate() {
        if field.name() != name {
            continue;
        }
        name_matches.push(idx);
        let field_qual = field_qualifier(field);
        match (qualifier, field_qual) {
            (Some(q), Some(fq)) if fq == q => qualifier_matches.push(idx),
            (None, None) => qualifier_matches.push(idx),
            _ => {}
        }
    }

    if let Some(q) = qualifier {
        if qualifier_matches.len() == 1 {
            return qualifier_matches[0];
        }
        if qualifier_matches.is_empty() && name_matches.len() == 1 {
            return name_matches[0];
        }
        panic!(
            "Aggregate column resolution failed for name={name} qualifier={q}: matches={:?}",
            name_matches
        );
    }

    if qualifier_matches.len() == 1 {
        return qualifier_matches[0];
    }
    if qualifier_matches.is_empty() && name_matches.len() == 1 {
        return name_matches[0];
    }
    panic!(
        "Aggregate column resolution failed for name={name}: matches={:?}",
        name_matches
    );
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

fn lookup_super_multiplicities_oracle_ref<'a, B: SnarkBackend>(
    aggregate_gadget: &Arc<Node<B>>,
    virtualized_ir: &'a crate::verifier::irs::VirtualizedIr<B>,
) -> Option<&'a TrackedTableOracle<B>> {
    let supp_node = aggregate_gadget.children().into_iter().next()?;
    let lookup_node = supp_node
        .children()
        .into_iter()
        .find(|child| child.name() == "Lookup")?;
    match virtualized_ir.payload_for_node(&lookup_node.id())? {
        PayloadStructure::GadgetPayload(map) => map
            .get(crate::irs::nodes::gadget::utils::lookup::SUPER_MULTIPLICITIES_LABEL),
        _ => None,
    }
}
