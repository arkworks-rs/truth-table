use std::sync::Arc;

use crate::irs::{
    nodes::{
        IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps,
        gadget::utils::{bool, match_pair_check, nodup, prescr_perm},
    },
    payloads::PayloadStructure,
};
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;
use arithmetic::{
    ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, ROW_ID_COL_NAME, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::{Field as ArkField, PrimeField};
use ark_piop::SnarkBackend;
use ark_piop::arithmetic::mat_poly::mle::MLE;
use ark_piop::prover::structs::polynomial::TrackedPoly;
use ark_piop::verifier::structs::oracle::TrackedOracle;
use datafusion::functions_window::expr_fn::row_number;
use datafusion::{
    arrow::datatypes::{DataType, Field, FieldRef, Schema},
    prelude::DataFrame,
};
use datafusion_common::{Column, DataFusionError, Result as DataFusionResult};
use datafusion_expr::ExprFunctionExt;
use datafusion_expr::{Expr, JoinType, LogicalPlan, col, lit};
use either::Either;
use indexmap::IndexMap;
pub const LEFT_LABEL: &str = "__LEFT__";
pub const RIGHT_LABEL: &str = "__RIGHT__";
pub const OUTPUT_LABEL: &str = "__OUTPUT__";
pub const SRC_LEFT_LABEL: &str = "__SRC_LEFT__";
pub const SRC_RIGHT_LABEL: &str = "__SRC_RIGHT__";
pub const SRC_LEFT_COL_NAME: &str = "src_left";
pub const SRC_RIGHT_COL_NAME: &str = "src_right";
pub struct GadgetNode<B: SnarkBackend> {
    bool_gadget: Arc<Node<B>>,
    nodup_gadget: Arc<Node<B>>,
    match_pair_gadget: Arc<Node<B>>,
}
#[cfg(test)]
mod tests;

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Join".to_string()
    }

    fn display(&self) -> String {
        let name = self.name();
        crate::irs::nodes::display_with_inputs(&name, &self.children())
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
        let mut gadget_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        let left_hint = match gadget_payload.get(LEFT_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };
        let right_hint = match gadget_payload.get(RIGHT_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };
        let output_hint = match gadget_payload.get(OUTPUT_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };

        // Build source-row tables aligned with the (row-id sorted) join output.
        let (left_src_df, right_src_df) = build_source_dfs(
            left_hint.data_frame().clone(),
            right_hint.data_frame().clone(),
            output_hint.data_frame().clone(),
        )
        .expect("join source dataframe derivation should succeed");
        gadget_payload.insert(
            SRC_LEFT_LABEL.to_string(),
            crate::irs::nodes::hints::HintDF::new_materialized(left_src_df),
        );
        gadget_payload.insert(
            SRC_RIGHT_LABEL.to_string(),
            crate::irs::nodes::hints::HintDF::new_materialized(right_src_df),
        );

        let join_lp = planned_ir.tree().arena().iter().find_map(|(_, node)| {
            let is_parent = node.children().iter().any(|child| child.id() == id);
            if !is_parent {
                return None;
            }
            match node.as_ref() {
                Node::Plan(crate::irs::nodes::PlanNode::LpBased(plan_node)) => Some(plan_node.lp()),
                _ => None,
            }
        });
        let join = match join_lp {
            Some(LogicalPlan::Join(join)) => join,
            _ => return Ok(()),
        };
        let (match_left, match_right, match_out) =
            build_match_pair_hints(&join, &left_hint, &right_hint, &output_hint)
                .expect("match-pair hint derivation should succeed");
        gadget_payload.insert(match_pair_check::LEFT_LABEL.to_string(), match_left);
        gadget_payload.insert(match_pair_check::RIGHT_LABEL.to_string(), match_right);
        gadget_payload.insert(match_pair_check::OUT_LABEL.to_string(), match_out);
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));
        Ok(())
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![
            self.bool_gadget.clone(),
            self.nodup_gadget.clone(),
            self.match_pair_gadget.clone(),
        ]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };
        let Some(output) = payload.get(OUTPUT_LABEL) else {
            return Ok(());
        };
        let bool_table = bool_table_from_output_prover(output);
        let mut bool_payload = match virtualized_ir.payload_for_node(&self.bool_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        bool_payload.insert(bool::TABLE_LABEL.to_string(), bool_table);
        virtualized_ir.set_payload_for_node(
            self.bool_gadget.id(),
            Some(PayloadStructure::GadgetPayload(bool_payload)),
        );

        let (Some(left_src), Some(right_src)) =
            (payload.get(SRC_LEFT_LABEL), payload.get(SRC_RIGHT_LABEL))
        else {
            return Ok(());
        };
        let nodup_table = nodup_table_from_output_prover(output, left_src, right_src);
        let mut nodup_payload = match virtualized_ir.payload_for_node(&self.nodup_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        nodup_payload.insert(nodup::INPUT_LABEL.to_string(), nodup_table);
        virtualized_ir.set_payload_for_node(
            self.nodup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(nodup_payload)),
        );

        let Some(join) = find_parent_join_plan(id, virtualized_ir.tree()) else {
            return Ok(());
        };
        let match_tables = build_match_pair_tables_prover(
            &join,
            output,
            payload.get(LEFT_LABEL),
            payload.get(RIGHT_LABEL),
        )
        .unwrap_or_else(|| {
            panic!("Match-pair tables require left/right/output for Join gadget");
        });
        let mut match_payload = match virtualized_ir.payload_for_node(&self.match_pair_gadget.id())
        {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        match_payload.insert(match_pair_check::LEFT_LABEL.to_string(), match_tables.0);
        match_payload.insert(match_pair_check::RIGHT_LABEL.to_string(), match_tables.1);
        match_payload.insert(match_pair_check::OUT_LABEL.to_string(), match_tables.2);
        virtualized_ir.set_payload_for_node(
            self.match_pair_gadget.id(),
            Some(PayloadStructure::GadgetPayload(match_payload)),
        );
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };
        let Some(output) = payload.get(OUTPUT_LABEL) else {
            return Ok(());
        };
        let bool_table = bool_table_from_output_verifier(output);
        let mut bool_payload = match virtualized_ir.payload_for_node(&self.bool_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        bool_payload.insert(bool::TABLE_LABEL.to_string(), bool_table);
        virtualized_ir.set_payload_for_node(
            self.bool_gadget.id(),
            Some(PayloadStructure::GadgetPayload(bool_payload)),
        );

        let (Some(left_src), Some(right_src)) =
            (payload.get(SRC_LEFT_LABEL), payload.get(SRC_RIGHT_LABEL))
        else {
            return Ok(());
        };
        let nodup_table = nodup_table_from_output_verifier(output, left_src, right_src);
        let mut nodup_payload = match virtualized_ir.payload_for_node(&self.nodup_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        nodup_payload.insert(nodup::INPUT_LABEL.to_string(), nodup_table);
        virtualized_ir.set_payload_for_node(
            self.nodup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(nodup_payload)),
        );

        let Some(join) = find_parent_join_plan(id, virtualized_ir.tree()) else {
            return Ok(());
        };
        let match_tables = build_match_pair_tables_verifier(
            &join,
            output,
            payload.get(LEFT_LABEL),
            payload.get(RIGHT_LABEL),
        )
        .unwrap_or_else(|| {
            panic!("Match-pair tables require left/right/output for Join gadget");
        });
        let mut match_payload = match virtualized_ir.payload_for_node(&self.match_pair_gadget.id())
        {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        match_payload.insert(match_pair_check::LEFT_LABEL.to_string(), match_tables.0);
        match_payload.insert(match_pair_check::RIGHT_LABEL.to_string(), match_tables.1);
        match_payload.insert(match_pair_check::OUT_LABEL.to_string(), match_tables.2);
        virtualized_ir.set_payload_for_node(
            self.match_pair_gadget.id(),
            Some(PayloadStructure::GadgetPayload(match_payload)),
        );
        Ok(())
    }
}

fn bool_table_from_output_prover<B: SnarkBackend>(output: &TrackedTable<B>) -> TrackedTable<B> {
    let activator = output
        .activator_tracked_poly()
        .expect("Join output should carry an activator column");
    let field = Arc::new(Field::new("data", DataType::Boolean, false));
    let mut tracked_polys = IndexMap::new();
    tracked_polys.insert(field.clone(), activator);
    let schema = Some(Schema::new(vec![field.as_ref().clone()]));
    TrackedTable::new(schema, tracked_polys, output.log_size())
}

fn bool_table_from_output_verifier<B: SnarkBackend>(
    output: &TrackedTableOracle<B>,
) -> TrackedTableOracle<B> {
    let activator = output
        .activator_tracked_poly()
        .expect("Join output should carry an activator column");
    let field = Arc::new(Field::new("data", DataType::Boolean, false));
    let mut tracked_oracles = IndexMap::new();
    tracked_oracles.insert(field.clone(), activator);
    let schema = Some(Schema::new(vec![field.as_ref().clone()]));
    TrackedTableOracle::new(schema, tracked_oracles, output.log_size())
}

fn nodup_table_from_output_prover<B: SnarkBackend>(
    output: &TrackedTable<B>,
    left_src: &TrackedTable<B>,
    right_src: &TrackedTable<B>,
) -> TrackedTable<B> {
    let activator = output
        .activator_tracked_poly()
        .expect("Join output should carry an activator column");

    let left_indices = left_src.data_tracked_polys_indices();
    assert_eq!(
        left_indices.len(),
        1,
        "Join src-left should have exactly one data column"
    );
    let right_indices = right_src.data_tracked_polys_indices();
    assert_eq!(
        right_indices.len(),
        1,
        "Join src-right should have exactly one data column"
    );

    let left_cols = left_src.tracked_polys();
    let (left_field, left_poly) = left_cols
        .get_index(left_indices[0])
        .expect("Join src-left data column missing");
    let right_cols = right_src.tracked_polys();
    let (_right_field, right_poly) = right_cols
        .get_index(right_indices[0])
        .expect("Join src-right data column missing");

    let base = B::F::from(2u64).pow([output.log_size() as u64]);
    let left_scaled = left_poly.mul_scalar_poly(base);
    let encoded_pair = &left_scaled + right_poly;

    let pair_field = Arc::new(Field::new(
        "src_pair",
        left_field.data_type().clone(),
        left_field.is_nullable(),
    ));

    let mut tracked_polys = IndexMap::new();
    tracked_polys.insert(ACTIVATOR_FIELD.clone(), activator);
    tracked_polys.insert(pair_field.clone(), encoded_pair);

    let schema = Some(Schema::new(vec![
        ACTIVATOR_FIELD.as_ref().clone(),
        pair_field.as_ref().clone(),
    ]));
    TrackedTable::new(schema, tracked_polys, output.log_size())
}

fn nodup_table_from_output_verifier<B: SnarkBackend>(
    output: &TrackedTableOracle<B>,
    left_src: &TrackedTableOracle<B>,
    right_src: &TrackedTableOracle<B>,
) -> TrackedTableOracle<B> {
    let activator = output
        .activator_tracked_poly()
        .expect("Join output should carry an activator column");

    let left_indices = left_src.data_tracked_oracles_indices();
    assert_eq!(
        left_indices.len(),
        1,
        "Join src-left should have exactly one data column"
    );
    let right_indices = right_src.data_tracked_oracles_indices();
    assert_eq!(
        right_indices.len(),
        1,
        "Join src-right should have exactly one data column"
    );

    let left_cols = left_src.tracked_oracles();
    let (left_field, left_oracle) = left_cols
        .get_index(left_indices[0])
        .expect("Join src-left data column missing");
    let right_cols = right_src.tracked_oracles();
    let (_right_field, right_oracle) = right_cols
        .get_index(right_indices[0])
        .expect("Join src-right data column missing");

    let base = B::F::from(2u64).pow([output.log_size() as u64]);
    let left_scaled = left_oracle.mul_scalar_oracle(base);
    let encoded_pair = &left_scaled + right_oracle;

    let pair_field = Arc::new(Field::new(
        "src_pair",
        left_field.data_type().clone(),
        left_field.is_nullable(),
    ));

    let mut tracked_oracles = IndexMap::new();
    tracked_oracles.insert(ACTIVATOR_FIELD.clone(), activator);
    tracked_oracles.insert(pair_field.clone(), encoded_pair);

    let schema = Some(Schema::new(vec![
        ACTIVATOR_FIELD.as_ref().clone(),
        pair_field.as_ref().clone(),
    ]));
    TrackedTableOracle::new(schema, tracked_oracles, output.log_size())
}

fn folding_challenges<F: PrimeField>(count: usize) -> Vec<F> {
    (0..count).map(|i| F::from((i + 1) as u64)).collect()
}

fn single_data_col_from_table<B: SnarkBackend>(
    table: &TrackedTable<B>,
    label: &str,
) -> (FieldRef, TrackedPoly<B>) {
    let data_indices = table.data_tracked_polys_indices();
    if data_indices.len() != 1 {
        panic!("Join {label} table must have exactly one data column");
    }
    let data_cols = table.tracked_polys();
    let (field, poly) = data_cols
        .get_index(data_indices[0])
        .expect("Join src data column missing");
    (field.clone(), poly.clone())
}

fn index_tracked_poly<B: SnarkBackend>(
    prover: &mut ark_piop::prover::ArgProver<B>,
    table: &TrackedTable<B>,
) -> TrackedPoly<B> {
    let log_size = table.log_size();
    let index_mle = MLE::from_evaluations_vec(
        log_size,
        (0..(1 << log_size)).map(|i| B::F::from(i as u64)).collect(),
    );
    prover.track_mat_mv_poly(index_mle)
}

fn append_tracked_col<B: SnarkBackend>(
    table: &TrackedTable<B>,
    field: FieldRef,
    poly: TrackedPoly<B>,
) -> TrackedTable<B> {
    let mut tracked_polys = table.tracked_polys();
    tracked_polys.insert(field.clone(), poly);
    let schema = table.schema_ref().map(|schema| {
        let mut fields = schema
            .fields()
            .iter()
            .map(|f| f.as_ref().clone())
            .collect::<Vec<_>>();
        fields.push(field.as_ref().clone());
        Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    let schema = schema.or_else(|| {
        Some(Schema::new(
            tracked_polys
                .keys()
                .map(|f| f.as_ref().clone())
                .collect::<Vec<_>>(),
        ))
    });
    TrackedTable::new(schema, tracked_polys, table.log_size())
}

fn append_tracked_oracle<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    field: FieldRef,
    oracle: TrackedOracle<B>,
) -> TrackedTableOracle<B> {
    let mut tracked_oracles = table.tracked_oracles();
    tracked_oracles.insert(field.clone(), oracle);
    let schema = table.schema_ref().map(|schema| {
        let mut fields = schema
            .fields()
            .iter()
            .map(|f| f.as_ref().clone())
            .collect::<Vec<_>>();
        fields.push(field.as_ref().clone());
        Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    let schema = schema.or_else(|| {
        Some(Schema::new(
            tracked_oracles
                .keys()
                .map(|f| f.as_ref().clone())
                .collect::<Vec<_>>(),
        ))
    });
    TrackedTableOracle::new(schema, tracked_oracles, table.log_size())
}

fn single_data_col_from_table_oracle<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    label: &str,
) -> (FieldRef, TrackedOracle<B>) {
    let data_indices = table.data_tracked_oracles_indices();
    if data_indices.len() != 1 {
        panic!("Join {label} table must have exactly one data column");
    }
    let data_cols = table.tracked_oracles();
    let (field, oracle) = data_cols
        .get_index(data_indices[0])
        .expect("Join src data column missing");
    (field.clone(), oracle.clone())
}

fn index_tracked_oracle<B: SnarkBackend>(
    verifier: &mut ark_piop::verifier::ArgVerifier<B>,
    table: &TrackedTableOracle<B>,
) -> TrackedOracle<B> {
    let data_col = table
        .data_tracked_oracles_indices()
        .first()
        .copied()
        .map(|idx| table.tracked_col_oracle_by_ind(idx))
        .unwrap_or_else(|| panic!("Join expects data columns on left table"));
    let log_size = data_col.data_tracked_oracle().log_size();
    let index_oracle = prescr_perm::shift_permutation_oracle::<B::F>(log_size, 0, true);
    let tracker = data_col.data_tracked_oracle().tracker();
    let index_id = tracker.borrow_mut().track_oracle(index_oracle);
    TrackedOracle::new(Either::Left(index_id), tracker, log_size)
}

fn output_left_from_output<B: SnarkBackend>(
    output: &TrackedTable<B>,
    left: &TrackedTable<B>,
) -> TrackedTable<B> {
    let output_cols = output.tracked_polys();
    let left_fields: Vec<FieldRef> = match left.schema_ref() {
        Some(schema) => schema
            .fields()
            .iter()
            .map(|field| Arc::new(field.as_ref().clone()))
            .collect(),
        None => left.tracked_polys().keys().cloned().collect(),
    };

    let mut filtered = IndexMap::new();
    for left_field in &left_fields {
        let maybe = output_cols
            .iter()
            .find(|(field, _)| field.name() == left_field.name());
        let Some((out_field, out_poly)) = maybe else {
            if left_field.name() == arithmetic::ROW_ID_COL_NAME {
                continue;
            }
            panic!("Join output missing left column {}", left_field.name());
        };
        filtered.insert(out_field.clone(), out_poly.clone());
    }

    let metadata = left
        .schema_ref()
        .map(|schema| schema.metadata().clone())
        .unwrap_or_default();
    let fields: Vec<Field> = filtered
        .keys()
        .map(|field| field.as_ref().clone())
        .collect();
    let schema = Some(Schema::new_with_metadata(fields, metadata));
    TrackedTable::new(schema, filtered, output.log_size())
}

fn output_left_from_output_oracle<B: SnarkBackend>(
    output: &TrackedTableOracle<B>,
    left: &TrackedTableOracle<B>,
) -> TrackedTableOracle<B> {
    let output_cols = output.tracked_oracles();
    let left_fields: Vec<FieldRef> = match left.schema_ref() {
        Some(schema) => schema
            .fields()
            .iter()
            .map(|field| Arc::new(field.as_ref().clone()))
            .collect(),
        None => left.tracked_oracles().keys().cloned().collect(),
    };

    let mut filtered = IndexMap::new();
    for left_field in &left_fields {
        let maybe = output_cols
            .iter()
            .find(|(field, _)| field.name() == left_field.name());
        let Some((out_field, out_oracle)) = maybe else {
            if left_field.name() == arithmetic::ROW_ID_COL_NAME {
                continue;
            }
            panic!("Join output missing left column {}", left_field.name());
        };
        filtered.insert(out_field.clone(), out_oracle.clone());
    }

    let metadata = left
        .schema_ref()
        .map(|schema| schema.metadata().clone())
        .unwrap_or_default();
    let fields: Vec<Field> = filtered
        .keys()
        .map(|field| field.as_ref().clone())
        .collect();
    let schema = Some(Schema::new_with_metadata(fields, metadata));
    TrackedTableOracle::new(schema, filtered, output.log_size())
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for Join gadget node");
        };

        let Some(output) = payload.get(OUTPUT_LABEL).cloned() else {
            panic!("Expected output table for Join gadget");
        };
        let Some(left_table) = payload.get(LEFT_LABEL).cloned() else {
            panic!("Expected left table for Join gadget");
        };
        let Some(right_table) = payload.get(RIGHT_LABEL).cloned() else {
            panic!("Expected right table for Join gadget");
        };
        let Some(left_src) = payload.get(SRC_LEFT_LABEL).cloned() else {
            panic!("Expected src-left table for Join gadget");
        };
        let Some(right_src) = payload.get(SRC_RIGHT_LABEL).cloned() else {
            panic!("Expected src-right table for Join gadget");
        };

        let (src_field, src_poly) = single_data_col_from_table(&left_src, "src-left");
        let output_left_base = output_left_from_output(&output, &left_table);
        let output_left = append_tracked_col(&output_left_base, src_field.clone(), src_poly);

        let index_poly = index_tracked_poly(prover, &left_table);
        let input_left = append_tracked_col(&left_table, src_field, index_poly);

        let output_challs = folding_challenges::<B::F>(output_left.num_data_tracked_cols());
        let output_folded = output_left.fold_all_data_columns(&output_challs);
        let input_challs = folding_challenges::<B::F>(input_left.num_data_tracked_cols());
        let input_folded = input_left.fold_all_data_columns(&input_challs);

        // output_left is a subtable of input_left after folding, so add lookup claim.
        prover.add_mv_lookup_claim(
            input_folded.data_tracked_poly().id(),
            output_folded.data_tracked_poly().id(),
        )?;

        let (right_src_field, right_src_poly) = single_data_col_from_table(&right_src, "src-right");
        let output_right_base = output_left_from_output(&output, &right_table);
        let output_right =
            append_tracked_col(&output_right_base, right_src_field.clone(), right_src_poly);

        let right_index_poly = index_tracked_poly(prover, &right_table);
        let input_right = append_tracked_col(&right_table, right_src_field, right_index_poly);

        let output_right_challs = folding_challenges::<B::F>(output_right.num_data_tracked_cols());
        let output_right_folded = output_right.fold_all_data_columns(&output_right_challs);
        let input_right_challs = folding_challenges::<B::F>(input_right.num_data_tracked_cols());
        let input_right_folded = input_right.fold_all_data_columns(&input_right_challs);

        // output_right is a subtable of input_right after folding, so add lookup claim.
        prover.add_mv_lookup_claim(
            input_right_folded.data_tracked_poly().id(),
            output_right_folded.data_tracked_poly().id(),
        )?;
        Ok(())
    }

    fn honest_prover_check(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for Join gadget node");
        };

        let Some(output) = payload.get(OUTPUT_LABEL).cloned() else {
            panic!("Expected output table for Join gadget");
        };
        let Some(left_table) = payload.get(LEFT_LABEL).cloned() else {
            panic!("Expected left table for Join gadget");
        };
        let Some(right_table) = payload.get(RIGHT_LABEL).cloned() else {
            panic!("Expected right table for Join gadget");
        };
        let Some(left_src) = payload.get(SRC_LEFT_LABEL).cloned() else {
            panic!("Expected src-left table for Join gadget");
        };
        let Some(right_src) = payload.get(SRC_RIGHT_LABEL).cloned() else {
            panic!("Expected src-right table for Join gadget");
        };

        let (src_field, src_oracle) = single_data_col_from_table_oracle(&left_src, "src-left");
        let output_left_base = output_left_from_output_oracle(&output, &left_table);
        let output_left = append_tracked_oracle(&output_left_base, src_field.clone(), src_oracle);

        let index_oracle = index_tracked_oracle(verifier, &left_table);
        let input_left = append_tracked_oracle(&left_table, src_field, index_oracle);

        let output_challs = folding_challenges::<B::F>(output_left.num_data_tracked_col_oracles());
        let output_folded = output_left.fold_all_data_oracles(&output_challs);
        let input_challs = folding_challenges::<B::F>(input_left.num_data_tracked_col_oracles());
        let input_folded = input_left.fold_all_data_oracles(&input_challs);

        verifier.add_mv_lookup_claim(
            input_folded.data_tracked_oracle().id(),
            output_folded.data_tracked_oracle().id(),
        )?;

        let (right_src_field, right_src_oracle) =
            single_data_col_from_table_oracle(&right_src, "src-right");
        let output_right_base = output_left_from_output_oracle(&output, &right_table);
        let output_right = append_tracked_oracle(
            &output_right_base,
            right_src_field.clone(),
            right_src_oracle,
        );

        let right_index_oracle = index_tracked_oracle(verifier, &right_table);
        let input_right = append_tracked_oracle(&right_table, right_src_field, right_index_oracle);

        let output_right_challs =
            folding_challenges::<B::F>(output_right.num_data_tracked_col_oracles());
        let output_right_folded = output_right.fold_all_data_oracles(&output_right_challs);
        let input_right_challs =
            folding_challenges::<B::F>(input_right.num_data_tracked_col_oracles());
        let input_right_folded = input_right.fold_all_data_oracles(&input_right_challs);

        verifier.add_mv_lookup_claim(
            input_right_folded.data_tracked_oracle().id(),
            output_right_folded.data_tracked_oracle().id(),
        )?;
        Ok(())
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> Default for GadgetNode<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new() -> Self {
        let bool_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::bool::GadgetNode::new(),
        )));
        let nodup_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::nodup::GadgetNode::new(),
        )));
        let match_pair_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::match_pair_check::GadgetNode::new(),
        )));
        Self {
            bool_gadget,
            nodup_gadget,
            match_pair_gadget,
        }
    }
}

fn build_row_index_df(
    df: DataFrame,
    row_id_cols: &[Column],
    row_id_aliases: &[String],
    index_col_name: &str,
) -> DataFusionResult<DataFrame> {
    debug_assert_eq!(
        row_id_cols.len(),
        row_id_aliases.len(),
        "row_id alias count should match row_id column count"
    );
    let row_number_expr = row_number()
        .partition_by(Vec::new())
        .order_by(
            row_id_cols
                .iter()
                .cloned()
                .map(|col| Expr::Column(col).sort(true, true))
                .collect(),
        )
        .build()?
        .alias("__row_number__");
    let mut indexed_exprs: Vec<Expr> = row_id_cols.iter().cloned().map(Expr::Column).collect();
    indexed_exprs.push(row_number_expr);
    let indexed = df.select(indexed_exprs)?;

    let mut final_exprs: Vec<Expr> = row_id_cols
        .iter()
        .zip(row_id_aliases.iter())
        .map(|(col, alias)| Expr::Column(col.clone()).alias(alias))
        .collect();
    final_exprs.push((col("__row_number__") - lit(1_i64)).alias(index_col_name));
    indexed.select(final_exprs)
}

fn row_id_columns(df: &DataFrame, side: &str) -> DataFusionResult<Vec<Column>> {
    let row_id_cols: Vec<Column> = df
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            (field.name() == ROW_ID_COL_NAME)
                .then_some(Column::new(qualifier.cloned(), ROW_ID_COL_NAME))
        })
        .collect();
    if row_id_cols.is_empty() {
        return Err(DataFusionError::Plan(format!(
            "Join {side} input is missing {ROW_ID_COL_NAME}"
        )));
    }
    Ok(row_id_cols)
}

pub(crate) fn build_source_dfs(
    left: DataFrame,
    right: DataFrame,
    output: DataFrame,
) -> DataFusionResult<(DataFrame, DataFrame)> {
    // Use row_id columns to keep output ordering deterministic.
    let output = crate::irs::nodes::hints::sort_by_row_id_if_present(output)?;
    let left_row_ids = row_id_columns(&left, "left")?;
    let right_row_ids = row_id_columns(&right, "right")?;
    let left_aliases: Vec<String> = (0..left_row_ids.len())
        .map(|idx| format!("__left_row_id__{idx}"))
        .collect();
    let right_aliases: Vec<String> = (0..right_row_ids.len())
        .map(|idx| format!("__right_row_id__{idx}"))
        .collect();

    let left_index_df = build_row_index_df(left, &left_row_ids, &left_aliases, SRC_LEFT_COL_NAME)?;
    let right_index_df =
        build_row_index_df(right, &right_row_ids, &right_aliases, SRC_RIGHT_COL_NAME)?;

    // Join the output with index mappings to recover source row indices.
    let left_join_exprs: Vec<Expr> = left_row_ids
        .iter()
        .zip(left_aliases.iter())
        .map(|(col, alias)| {
            Expr::Column(col.clone()).eq(Expr::Column(Column::new_unqualified(alias)))
        })
        .collect();
    let output = output.join_on(left_index_df, JoinType::Inner, left_join_exprs)?;
    let right_join_exprs: Vec<Expr> = right_row_ids
        .iter()
        .zip(right_aliases.iter())
        .map(|(col, alias)| {
            Expr::Column(col.clone()).eq(Expr::Column(Column::new_unqualified(alias)))
        })
        .collect();
    let output = output.join_on(right_index_df, JoinType::Inner, right_join_exprs)?;
    let output = crate::irs::nodes::hints::sort_by_row_id_if_present(output)?;
    let left_src = output
        .clone()
        .select(vec![Expr::Column(Column::new_unqualified(
            SRC_LEFT_COL_NAME,
        ))])?;
    let right_src = output.select(vec![Expr::Column(Column::new_unqualified(
        SRC_RIGHT_COL_NAME,
    ))])?;
    Ok((left_src, right_src))
}

fn find_parent_join_plan<B: SnarkBackend>(
    id: crate::irs::nodes::NodeId,
    tree: &crate::irs::tree::Tree<B>,
) -> Option<datafusion_expr::Join> {
    tree.arena().iter().find_map(|(_, node)| {
        let is_parent = node.children().iter().any(|child| child.id() == id);
        if !is_parent {
            return None;
        }
        match node.as_ref() {
            Node::Plan(crate::irs::nodes::PlanNode::LpBased(plan_node)) => match plan_node.lp() {
                LogicalPlan::Join(join) => Some(join),
                _ => None,
            },
            _ => None,
        }
    })
}

fn build_match_pair_hints(
    join: &datafusion_expr::Join,
    left_hint: &crate::irs::nodes::hints::HintDF,
    right_hint: &crate::irs::nodes::hints::HintDF,
    output_hint: &crate::irs::nodes::hints::HintDF,
) -> DataFusionResult<(
    crate::irs::nodes::hints::HintDF,
    crate::irs::nodes::hints::HintDF,
    crate::irs::nodes::hints::HintDF,
)> {
    let mut left_exprs: Vec<Expr> = join.on.iter().map(|(l, _)| l.clone()).collect();
    let mut right_exprs: Vec<Expr> = join.on.iter().map(|(_, r)| r.clone()).collect();
    crate::irs::nodes::hints::append_row_id_expr_if_present(
        left_hint.data_frame(),
        &mut left_exprs,
    );
    crate::irs::nodes::hints::append_activator_exprs_if_present(
        left_hint.data_frame(),
        &mut left_exprs,
    );
    crate::irs::nodes::hints::append_row_id_expr_if_present(
        right_hint.data_frame(),
        &mut right_exprs,
    );
    crate::irs::nodes::hints::append_activator_exprs_if_present(
        right_hint.data_frame(),
        &mut right_exprs,
    );

    let left_df = left_hint.data_frame().clone().select(left_exprs)?;
    let left_df = crate::irs::nodes::hints::sort_by_row_id_if_present(left_df)?;
    let right_df = right_hint.data_frame().clone().select(right_exprs)?;
    let right_df = crate::irs::nodes::hints::sort_by_row_id_if_present(right_df)?;

    let output_sorted =
        crate::irs::nodes::hints::sort_by_row_id_if_present(output_hint.data_frame().clone())?;
    let mut out_exprs = Vec::new();
    crate::irs::nodes::hints::append_activator_exprs_if_present(&output_sorted, &mut out_exprs);
    if out_exprs.is_empty() {
        return Err(DataFusionError::Plan(
            "Join output is missing an activator column".to_string(),
        ));
    }
    let output_df = output_sorted.select(out_exprs)?;

    Ok((
        crate::irs::nodes::hints::HintDF::new_virtual(left_df),
        crate::irs::nodes::hints::HintDF::new_virtual(right_df),
        crate::irs::nodes::hints::HintDF::new_virtual(output_df),
    ))
}

fn join_key_names(join: &datafusion_expr::Join, use_left: bool) -> Vec<String> {
    join.on
        .iter()
        .map(|(left, right)| {
            let expr = if use_left { left } else { right };
            match expr {
                Expr::Column(col) => col.name.clone(),
                _ => panic!("Join match-pair keys must be column expressions"),
            }
        })
        .collect()
}

fn ordered_column_names(
    mut keys: Vec<String>,
    include_row_id: bool,
    include_activator: bool,
) -> Vec<String> {
    if include_row_id && !keys.iter().any(|name| name == ROW_ID_COL_NAME) {
        keys.push(ROW_ID_COL_NAME.to_string());
    }
    if include_activator && !keys.iter().any(|name| name == ACTIVATOR_COL_NAME) {
        keys.push(ACTIVATOR_COL_NAME.to_string());
    }
    keys
}

fn build_match_pair_tables_prover<B: SnarkBackend>(
    join: &datafusion_expr::Join,
    output: &TrackedTable<B>,
    left: Option<&TrackedTable<B>>,
    right: Option<&TrackedTable<B>>,
) -> Option<(TrackedTable<B>, TrackedTable<B>, TrackedTable<B>)> {
    let left_table = left?;
    let right_table = right?;
    let include_left_row_id = left_table
        .tracked_polys()
        .keys()
        .any(|field| field.name() == ROW_ID_COL_NAME);
    let include_right_row_id = right_table
        .tracked_polys()
        .keys()
        .any(|field| field.name() == ROW_ID_COL_NAME);
    let include_left_activator = left_table
        .tracked_polys()
        .keys()
        .any(|field| field.name() == ACTIVATOR_COL_NAME);
    let include_right_activator = right_table
        .tracked_polys()
        .keys()
        .any(|field| field.name() == ACTIVATOR_COL_NAME);
    if !include_left_activator {
        panic!("Join left table missing column {ACTIVATOR_COL_NAME}");
    }
    if !include_right_activator {
        panic!("Join right table missing column {ACTIVATOR_COL_NAME}");
    }
    let left_keys = ordered_column_names(join_key_names(join, true), include_left_row_id, true);
    let right_keys = ordered_column_names(join_key_names(join, false), include_right_row_id, true);

    let left_selected = select_tracked_columns(left_table, &left_keys, "left");
    let right_selected = select_tracked_columns(right_table, &right_keys, "right");
    let out_selected = output_activator_table(output);

    Some((left_selected, right_selected, out_selected))
}

fn build_match_pair_tables_verifier<B: SnarkBackend>(
    join: &datafusion_expr::Join,
    output: &TrackedTableOracle<B>,
    left: Option<&TrackedTableOracle<B>>,
    right: Option<&TrackedTableOracle<B>>,
) -> Option<(
    TrackedTableOracle<B>,
    TrackedTableOracle<B>,
    TrackedTableOracle<B>,
)> {
    let left_table = left?;
    let right_table = right?;
    let include_left_row_id = left_table
        .tracked_oracles()
        .keys()
        .any(|field| field.name() == ROW_ID_COL_NAME);
    let include_right_row_id = right_table
        .tracked_oracles()
        .keys()
        .any(|field| field.name() == ROW_ID_COL_NAME);
    let include_left_activator = left_table
        .tracked_oracles()
        .keys()
        .any(|field| field.name() == ACTIVATOR_COL_NAME);
    let include_right_activator = right_table
        .tracked_oracles()
        .keys()
        .any(|field| field.name() == ACTIVATOR_COL_NAME);
    if !include_left_activator {
        panic!("Join left table missing column {ACTIVATOR_COL_NAME}");
    }
    if !include_right_activator {
        panic!("Join right table missing column {ACTIVATOR_COL_NAME}");
    }
    let left_keys = ordered_column_names(join_key_names(join, true), include_left_row_id, true);
    let right_keys = ordered_column_names(join_key_names(join, false), include_right_row_id, true);

    let left_selected = select_tracked_oracles(left_table, &left_keys, "left");
    let right_selected = select_tracked_oracles(right_table, &right_keys, "right");
    let out_selected = output_activator_table_oracle(output);

    Some((left_selected, right_selected, out_selected))
}

fn select_tracked_columns<B: SnarkBackend>(
    table: &TrackedTable<B>,
    column_names: &[String],
    side: &str,
) -> TrackedTable<B> {
    let cols = table.tracked_polys();
    let mut selected = IndexMap::new();
    for name in column_names {
        let (field, poly) = cols
            .iter()
            .find(|(field, _)| field.name() == name)
            .unwrap_or_else(|| panic!("Join {side} table missing column {name}"));
        selected.insert(field.clone(), poly.clone());
    }
    let schema = table.schema_ref().map(|schema| {
        let fields: Vec<Field> = selected
            .keys()
            .map(|field| field.as_ref().clone())
            .collect();
        Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    let schema = schema.or_else(|| {
        let fields: Vec<Field> = selected
            .keys()
            .map(|field| field.as_ref().clone())
            .collect();
        Some(Schema::new(fields))
    });
    TrackedTable::new(schema, selected, table.log_size())
}

fn select_tracked_oracles<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    column_names: &[String],
    side: &str,
) -> TrackedTableOracle<B> {
    let cols = table.tracked_oracles();
    let mut selected = IndexMap::new();
    for name in column_names {
        let (field, oracle) = cols
            .iter()
            .find(|(field, _)| field.name() == name)
            .unwrap_or_else(|| panic!("Join {side} table missing column {name}"));
        selected.insert(field.clone(), oracle.clone());
    }
    let schema = table.schema_ref().map(|schema| {
        let fields: Vec<Field> = selected
            .keys()
            .map(|field| field.as_ref().clone())
            .collect();
        Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    let schema = schema.or_else(|| {
        let fields: Vec<Field> = selected
            .keys()
            .map(|field| field.as_ref().clone())
            .collect();
        Some(Schema::new(fields))
    });
    TrackedTableOracle::new(schema, selected, table.log_size())
}

fn output_activator_table<B: SnarkBackend>(output: &TrackedTable<B>) -> TrackedTable<B> {
    let activator = output
        .tracked_polys()
        .iter()
        .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
        .map(|(field, poly)| (field.clone(), poly.clone()))
        .unwrap_or_else(|| panic!("Join output missing activator column"));
    let mut selected = IndexMap::new();
    selected.insert(activator.0.clone(), activator.1);
    let schema = Some(Schema::new(vec![activator.0.as_ref().clone()]));
    TrackedTable::new(schema, selected, output.log_size())
}

fn output_activator_table_oracle<B: SnarkBackend>(
    output: &TrackedTableOracle<B>,
) -> TrackedTableOracle<B> {
    let activator = output
        .tracked_oracles()
        .iter()
        .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
        .map(|(field, oracle)| (field.clone(), oracle.clone()))
        .unwrap_or_else(|| panic!("Join output missing activator column"));
    let mut selected = IndexMap::new();
    selected.insert(activator.0.clone(), activator.1);
    let schema = Some(Schema::new(vec![activator.0.as_ref().clone()]));
    TrackedTableOracle::new(schema, selected, output.log_size())
}
