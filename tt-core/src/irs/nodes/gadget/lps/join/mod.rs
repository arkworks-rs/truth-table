use std::sync::Arc;

use crate::irs::{
    nodes::{
        IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps,
        gadget::utils::{match_pair_check, prescr_perm},
    },
    payloads::PayloadStructure,
};
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;
use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::SnarkBackend;
use ark_piop::arithmetic::mat_poly::mle::MLE;
use ark_piop::prover::structs::polynomial::TrackedPoly;
use ark_piop::verifier::structs::oracle::TrackedOracle;
use datafusion::arrow::datatypes::{Field, FieldRef, Schema};
use datafusion_common::{DataFusionError, Result as DataFusionResult};
use datafusion_expr::{Expr, Join};
use either::Either;
use indexmap::IndexMap;
mod hints;
mod wiring;
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
    join: Join,
}

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
        let gadget_payload = match planned_ir.payload_for_node(&id) {
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

        // Build source-row tables aligned with the join output.
        let (left_src_df, right_src_df) = hints::build_source_dfs(
            left_hint.data_frame().clone(),
            right_hint.data_frame().clone(),
            output_hint.data_frame().clone(),
            &self.join,
        )
        .expect("join source dataframe derivation should succeed");
        let mut gadget_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(
            SRC_LEFT_LABEL.to_string(),
            crate::irs::nodes::hints::HintDF::new_materialized(left_src_df),
        );
        gadget_payload.insert(
            SRC_RIGHT_LABEL.to_string(),
            crate::irs::nodes::hints::HintDF::new_materialized(right_src_df),
        );
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));

        let (match_left, match_right, match_out) =
            build_match_pair_hints(&self.join, &left_hint, &right_hint, &output_hint)
                .expect("match-pair hint derivation should succeed");
        let mut match_payload = match planned_ir.payload_for_node(&self.match_pair_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        match_payload.insert(match_pair_check::LEFT_LABEL.to_string(), match_left);
        match_payload.insert(match_pair_check::RIGHT_LABEL.to_string(), match_right);
        match_payload.insert(match_pair_check::OUT_LABEL.to_string(), match_out);
        planned_ir.set_payload_for_node(
            self.match_pair_gadget.id(),
            Some(PayloadStructure::GadgetPayload(match_payload)),
        );
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
        // First fetch the payload for the current node, prepared by the parent
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            panic!("Expected gadget payload for Join gadget node")
        };
        // Among the payload, we expect left, right, and output tables
        let current_output = payload
            .get(OUTPUT_LABEL)
            .unwrap_or_else(|| panic!("Join gadget payload missing {OUTPUT_LABEL}"));
        let current_left = payload
            .get(LEFT_LABEL)
            .unwrap_or_else(|| panic!("Join gadget payload missing {LEFT_LABEL}"));
        let current_right = payload
            .get(RIGHT_LABEL)
            .unwrap_or_else(|| panic!("Join gadget payload missing {RIGHT_LABEL}"));
        let current_left_src = payload
            .get(SRC_LEFT_LABEL)
            .unwrap_or_else(|| panic!("Join gadget payload missing {SRC_LEFT_LABEL}"));
        let current_right_src = payload
            .get(SRC_RIGHT_LABEL)
            .unwrap_or_else(|| panic!("Join gadget payload missing {SRC_RIGHT_LABEL}"));
        self.wire_prover_bool_payload(current_output, virtualized_ir);

        self.wire_prover_nodup_payload(
            current_output,
            current_left_src,
            current_right_src,
            virtualized_ir,
        );

        self.wire_prover_match_pair_payload(
            current_output,
            current_left,
            current_right,
            virtualized_ir,
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
            panic!("expected gadget payload for Join gadget node")
        };
        let current_output = payload
            .get(OUTPUT_LABEL)
            .unwrap_or_else(|| panic!("Join gadget payload missing {OUTPUT_LABEL}"));
        let current_left = payload
            .get(LEFT_LABEL)
            .unwrap_or_else(|| panic!("Join gadget payload missing {LEFT_LABEL}"));
        let current_right = payload
            .get(RIGHT_LABEL)
            .unwrap_or_else(|| panic!("Join gadget payload missing {RIGHT_LABEL}"));
        let current_left_src = payload
            .get(SRC_LEFT_LABEL)
            .unwrap_or_else(|| panic!("Join gadget payload missing {SRC_LEFT_LABEL}"));
        let current_right_src = payload
            .get(SRC_RIGHT_LABEL)
            .unwrap_or_else(|| panic!("Join gadget payload missing {SRC_RIGHT_LABEL}"));
        self.wire_verifier_bool_payload(current_output, virtualized_ir);

        self.wire_verifier_nodup_payload(
            current_output,
            current_left_src,
            current_right_src,
            virtualized_ir,
        );

        self.wire_verifier_match_pair_payload(
            current_output,
            current_left,
            current_right,
            virtualized_ir,
        );
        Ok(())
    }
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
        let Some(PayloadStructure::GadgetPayload(nodup_payload)) =
            gadget_ready_ir.payload_for_node(&self.nodup_gadget.id())
        else {
            panic!("Expected nodup gadget payload for Join gadget");
        };
        let Some(left_src) = nodup_payload.get(SRC_LEFT_LABEL).cloned() else {
            panic!("Expected src-left table for Join gadget");
        };
        let Some(right_src) = nodup_payload.get(SRC_RIGHT_LABEL).cloned() else {
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
        let Some(PayloadStructure::GadgetPayload(nodup_payload)) =
            gadget_ready_ir.payload_for_node(&self.nodup_gadget.id())
        else {
            panic!("Expected nodup gadget payload for Join gadget");
        };
        let Some(left_src) = nodup_payload.get(SRC_LEFT_LABEL).cloned() else {
            panic!("Expected src-left table for Join gadget");
        };
        let Some(right_src) = nodup_payload.get(SRC_RIGHT_LABEL).cloned() else {
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

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(join: Join) -> Self {
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
            join,
        }
    }
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
