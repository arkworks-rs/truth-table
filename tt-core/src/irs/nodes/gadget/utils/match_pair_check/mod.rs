use std::sync::Arc;

use ark_ff::{One, Zero};
use ark_piop::{
    SnarkBackend, prover::structs::polynomial::TrackedPoly,
    verifier::structs::oracle::TrackedOracle,
};
use datafusion::{
    arrow::{
        array::{ArrayRef, BooleanArray, new_null_array},
        compute::concat,
        compute::concat_batches,
        datatypes::{Field, Schema},
        record_batch::RecordBatch,
    },
    functions_window::expr_fn::row_number,
    prelude::{DataFrame, SessionContext},
};
use datafusion_common::{Column, DataFusionError, Result as DataFusionResult};
use datafusion_expr::{Expr, ExprFunctionExt, Join, LogicalPlan, col, lit};
use indexmap::IndexMap;
use tokio::runtime::RuntimeFlavor;
use tracing::error;

use crate::irs::nodes::gadget::lps::join as join_gadget;
use crate::irs::nodes::gadget::utils::{lookup, nodup};
use crate::irs::nodes::hints::sort_by_row_id_if_present;
use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub const LEFT_LABEL: &str = "__left__";
pub const RIGHT_LABEL: &str = "__right__";
pub const OUT_LABEL: &str = "__out__";
pub const UNION_LABEL: &str = "__union__";

pub struct GadgetNode<B: SnarkBackend> {
    nodup_gadget: Arc<Node<B>>,
    left_lookup_gadget: Arc<Node<B>>,
    right_lookup_gadget: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Match-Pair Check".to_string()
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

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![
            self.nodup_gadget.clone(),
            self.left_lookup_gadget.clone(),
            self.right_lookup_gadget.clone(),
        ]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::prover::irs::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(join_gadget_id) = find_parent_id(id, planned_ir.tree()) else {
            return Ok(());
        };
        let join_payload = match planned_ir.payload_for_node(&join_gadget_id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        let left_hint = match join_payload.get(join_gadget::LEFT_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };
        let right_hint = match join_payload.get(join_gadget::RIGHT_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };
        let Some(join) = find_parent_join_plan(join_gadget_id, planned_ir.tree()) else {
            return Ok(());
        };

        let (key_union, key_names) =
            build_key_union_df(&join, left_hint.data_frame(), right_hint.data_frame())
                .expect("match-pair key union should succeed");
        let key_union =
            pad_key_union_df(key_union, &key_names).expect("match-pair padding should succeed");
        let key_hint = crate::irs::nodes::hints::HintDF::new_materialized(key_union);
        let (left_cols, right_cols, _) =
            join_key_columns(&join).expect("match-pair join keys should be columns");

        let left_keys_df =
            build_lookup_keys_df(left_hint.data_frame(), &left_cols, &key_names, "left")
                .expect("match-pair left key projection should succeed");
        let right_keys_df =
            build_lookup_keys_df(right_hint.data_frame(), &right_cols, &key_names, "right")
                .expect("match-pair right key projection should succeed");
        let union_df = sort_by_row_id_if_present(key_hint.data_frame().clone())
            .expect("match-pair union sort should succeed");
        let union_hint = crate::irs::nodes::hints::HintDF::new_virtual(union_df);

        let mut gadget_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(UNION_LABEL.to_string(), key_hint);
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));

        let mut nodup_payload = match planned_ir.payload_for_node(&self.nodup_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        nodup_payload.insert(nodup::INPUT_LABEL.to_string(), union_hint.clone());
        planned_ir.set_payload_for_node(
            self.nodup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(nodup_payload)),
        );

        let left_lookup_hint = crate::irs::nodes::hints::HintDF::new_virtual(left_keys_df);
        let left_lookup_hint = crate::irs::nodes::hints::strip_row_id_from_hint(&left_lookup_hint);
        let mut left_lookup_payload =
            match planned_ir.payload_for_node(&self.left_lookup_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
        left_lookup_payload.insert(lookup::INCLUDED_LABEL.to_string(), left_lookup_hint);
        left_lookup_payload.insert(lookup::SUPER_LABEL.to_string(), union_hint.clone());
        planned_ir.set_payload_for_node(
            self.left_lookup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(left_lookup_payload)),
        );

        let right_lookup_hint = crate::irs::nodes::hints::HintDF::new_virtual(right_keys_df);
        let right_lookup_hint =
            crate::irs::nodes::hints::strip_row_id_from_hint(&right_lookup_hint);
        let mut right_lookup_payload =
            match planned_ir.payload_for_node(&self.right_lookup_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
        right_lookup_payload.insert(lookup::INCLUDED_LABEL.to_string(), right_lookup_hint);
        right_lookup_payload.insert(lookup::SUPER_LABEL.to_string(), union_hint);
        planned_ir.set_payload_for_node(
            self.right_lookup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(right_lookup_payload)),
        );
        Ok(())
    }

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
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };
        let union = payload
            .get(UNION_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Match-Pair gadget missing {}", UNION_LABEL));
        let left_keys = payload
            .get(LEFT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Match-Pair gadget missing {}", LEFT_LABEL));
        let right_keys = payload
            .get(RIGHT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Match-Pair gadget missing {}", RIGHT_LABEL));

        let mut nodup_payload = match virtualized_ir.payload_for_node(&self.nodup_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        nodup_payload.insert(nodup::INPUT_LABEL.to_string(), union.clone());
        virtualized_ir.set_payload_for_node(
            self.nodup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(nodup_payload)),
        );

        let mut left_lookup_payload =
            match virtualized_ir.payload_for_node(&self.left_lookup_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
        left_lookup_payload.insert(
            lookup::INCLUDED_LABEL.to_string(),
            drop_row_id_keep_activator_prover(&left_keys),
        );
        left_lookup_payload.insert(
            lookup::SUPER_LABEL.to_string(),
            drop_row_id_keep_activator_prover(&union),
        );
        virtualized_ir.set_payload_for_node(
            self.left_lookup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(left_lookup_payload)),
        );

        let mut right_lookup_payload =
            match virtualized_ir.payload_for_node(&self.right_lookup_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
        right_lookup_payload.insert(
            lookup::INCLUDED_LABEL.to_string(),
            drop_row_id_keep_activator_prover(&right_keys),
        );
        right_lookup_payload.insert(
            lookup::SUPER_LABEL.to_string(),
            drop_row_id_keep_activator_prover(&union),
        );
        virtualized_ir.set_payload_for_node(
            self.right_lookup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(right_lookup_payload)),
        );
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::prover::irs::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(join_gadget_id) = find_parent_id(id, planned_ir.tree()) else {
            return Ok(());
        };
        let join_payload = match planned_ir.payload_for_node(&join_gadget_id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        let left_hint = match join_payload.get(join_gadget::LEFT_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };
        let right_hint = match join_payload.get(join_gadget::RIGHT_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };
        let Some(join) = find_parent_join_plan(join_gadget_id, planned_ir.tree()) else {
            return Ok(());
        };

        let (key_union, key_names) =
            build_key_union_df(&join, left_hint.data_frame(), right_hint.data_frame())
                .expect("match-pair key union should succeed");
        let key_union =
            pad_key_union_df(key_union, &key_names).expect("match-pair padding should succeed");
        let key_hint = crate::irs::nodes::hints::HintDF::new_materialized(key_union);
        let (left_cols, right_cols, _) =
            join_key_columns(&join).expect("match-pair join keys should be columns");

        let left_keys_df =
            build_lookup_keys_df(left_hint.data_frame(), &left_cols, &key_names, "left")
                .expect("match-pair left key projection should succeed");
        let right_keys_df =
            build_lookup_keys_df(right_hint.data_frame(), &right_cols, &key_names, "right")
                .expect("match-pair right key projection should succeed");
        let union_df = sort_by_row_id_if_present(key_hint.data_frame().clone())
            .expect("match-pair union sort should succeed");
        let union_hint = crate::irs::nodes::hints::HintDF::new_virtual(union_df);

        let mut gadget_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(UNION_LABEL.to_string(), key_hint);
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));

        let mut nodup_payload = match planned_ir.payload_for_node(&self.nodup_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        nodup_payload.insert(nodup::INPUT_LABEL.to_string(), union_hint.clone());
        planned_ir.set_payload_for_node(
            self.nodup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(nodup_payload)),
        );

        let left_lookup_hint = crate::irs::nodes::hints::HintDF::new_virtual(left_keys_df);
        let left_lookup_hint = crate::irs::nodes::hints::strip_row_id_from_hint(&left_lookup_hint);
        let mut left_lookup_payload =
            match planned_ir.payload_for_node(&self.left_lookup_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
        left_lookup_payload.insert(lookup::INCLUDED_LABEL.to_string(), left_lookup_hint);
        left_lookup_payload.insert(lookup::SUPER_LABEL.to_string(), union_hint.clone());
        planned_ir.set_payload_for_node(
            self.left_lookup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(left_lookup_payload)),
        );

        let right_lookup_hint = crate::irs::nodes::hints::HintDF::new_virtual(right_keys_df);
        let right_lookup_hint =
            crate::irs::nodes::hints::strip_row_id_from_hint(&right_lookup_hint);
        let mut right_lookup_payload =
            match planned_ir.payload_for_node(&self.right_lookup_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
        right_lookup_payload.insert(lookup::INCLUDED_LABEL.to_string(), right_lookup_hint);
        right_lookup_payload.insert(lookup::SUPER_LABEL.to_string(), union_hint);
        planned_ir.set_payload_for_node(
            self.right_lookup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(right_lookup_payload)),
        );
        Ok(())
    }

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
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };
        let union = payload
            .get(UNION_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Match-Pair gadget missing {}", UNION_LABEL));
        let left_keys = payload
            .get(LEFT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Match-Pair gadget missing {}", LEFT_LABEL));
        let right_keys = payload
            .get(RIGHT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Match-Pair gadget missing {}", RIGHT_LABEL));

        let mut nodup_payload = match virtualized_ir.payload_for_node(&self.nodup_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        nodup_payload.insert(nodup::INPUT_LABEL.to_string(), union.clone());
        virtualized_ir.set_payload_for_node(
            self.nodup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(nodup_payload)),
        );

        let mut left_lookup_payload =
            match virtualized_ir.payload_for_node(&self.left_lookup_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
        left_lookup_payload.insert(
            lookup::INCLUDED_LABEL.to_string(),
            drop_row_id_keep_activator_verifier(&left_keys),
        );
        left_lookup_payload.insert(
            lookup::SUPER_LABEL.to_string(),
            drop_row_id_keep_activator_verifier(&union),
        );
        virtualized_ir.set_payload_for_node(
            self.left_lookup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(left_lookup_payload)),
        );

        let mut right_lookup_payload =
            match virtualized_ir.payload_for_node(&self.right_lookup_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
        right_lookup_payload.insert(
            lookup::INCLUDED_LABEL.to_string(),
            drop_row_id_keep_activator_verifier(&right_keys),
        );
        right_lookup_payload.insert(
            lookup::SUPER_LABEL.to_string(),
            drop_row_id_keep_activator_verifier(&union),
        );
        virtualized_ir.set_payload_for_node(
            self.right_lookup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(right_lookup_payload)),
        );
        Ok(())
    }
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
            panic!("Expected gadget payload for Match-Pair gadget node");
        };
        let Some(union_table) = payload.get(UNION_LABEL).cloned() else {
            panic!("Expected union table for Match-Pair gadget");
        };
        let Some(output_table) = payload.get(OUT_LABEL).cloned() else {
            panic!("Expected output activator table for Match-Pair gadget");
        };

        let left_multiplicities =
            lookup_multiplicities_table_prover(gadget_ready_ir, &self.left_lookup_gadget);
        let right_multiplicities =
            lookup_multiplicities_table_prover(gadget_ready_ir, &self.right_lookup_gadget);
        let union_activator = union_table
            .activator_tracked_poly()
            .expect("Match-Pair union table missing activator");
        let output_activator = output_table
            .activator_tracked_poly()
            .expect("Match-Pair output table missing activator");
        let left_mult = single_data_poly_from_table(&left_multiplicities, "left multiplicity");
        let right_mult = single_data_poly_from_table(&right_multiplicities, "right multiplicity");
        let union_left = &union_activator * &(&left_mult * &right_mult);

        let output_sum = output_activator
            .evaluations()
            .into_iter()
            .fold(B::F::zero(), |acc, val| acc + val);
        let challenge = prover.get_and_append_challenge(b"match_pair_output_sum_key")?;
        let output_sum_key = format!("match_pair_output_sum_{challenge}");
        prover.add_miscellaneous_field_element(output_sum_key.clone(), output_sum)?;
        prover.add_mv_sumcheck_claim(union_left.id(), output_sum)?;
        Ok(())
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let left_keys = payload
            .get(LEFT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Match-Pair gadget missing {}", LEFT_LABEL));
        let right_keys = payload
            .get(RIGHT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Match-Pair gadget missing {}", RIGHT_LABEL));
        let _union_keys = payload
            .get(UNION_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Match-Pair gadget missing {}", UNION_LABEL));
        let output_table = payload
            .get(OUT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Match-Pair gadget missing {}", OUT_LABEL));

        // Honest check: sum of pair multiplicities equals output active count.
        let left_counts = active_row_multiset::<B>(&left_keys);
        let right_counts = active_row_multiset::<B>(&right_keys);
        let output_active = active_row_count::<B>(&output_table);
        let mut match_count = 0usize;
        for (key, left_count) in &left_counts {
            let right_count = right_counts.get(key).copied().unwrap_or(0);
            match_count += left_count * right_count;
        }

        if match_count == output_active {
            Ok(())
        } else {
            error!(
                "Match-Pair honest check failed: match_count={}, output_active={}",
                match_count, output_active
            );
            Err(ark_piop::errors::SnarkError::ProverError(
                ark_piop::prover::errors::ProverError::HonestProverError(
                    ark_piop::prover::errors::HonestProverError::FalseClaim,
                ),
            ))
        }
    }

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for Match-Pair gadget node");
        };
        let Some(union_table) = payload.get(UNION_LABEL).cloned() else {
            panic!("Expected union table for Match-Pair gadget");
        };
        let Some(output_table) = payload.get(OUT_LABEL).cloned() else {
            panic!("Expected output activator table for Match-Pair gadget");
        };

        let left_multiplicities =
            lookup_multiplicities_table_verifier(gadget_ready_ir, &self.left_lookup_gadget);
        let right_multiplicities =
            lookup_multiplicities_table_verifier(gadget_ready_ir, &self.right_lookup_gadget);

        let union_activator = union_table
            .activator_tracked_poly()
            .expect("Match-Pair union table missing activator");
        let output_activator = output_table
            .activator_tracked_poly()
            .expect("Match-Pair output table missing activator");
        let left_mult = single_data_oracle_from_table(&left_multiplicities, "left multiplicity");
        let right_mult = single_data_oracle_from_table(&right_multiplicities, "right multiplicity");

        let union_left = &union_activator * &(&left_mult * &right_mult);

        let challenge = verifier.get_and_append_challenge(b"match_pair_output_sum_key")?;
        let output_sum_key = format!("match_pair_output_sum_{challenge}");
        let output_sum = verifier.miscellaneous_field_element(&output_sum_key)?;

        verifier.add_sumcheck_claim(union_left.id(), output_sum);
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
        let nodup_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::nodup::GadgetNode::default(),
        )));
        let left_lookup_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::lookup::GadgetNode::new(),
        )));
        let right_lookup_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::lookup::GadgetNode::new(),
        )));
        Self {
            nodup_gadget,
            left_lookup_gadget,
            right_lookup_gadget,
        }
    }
}

fn drop_row_id_keep_activator_prover<B: SnarkBackend>(
    table: &arithmetic::table::TrackedTable<B>,
) -> arithmetic::table::TrackedTable<B> {
    let cols = table.tracked_polys();
    if !cols
        .keys()
        .any(|field| field.name() == arithmetic::ACTIVATOR_COL_NAME)
    {
        panic!(
            "Match-Pair lookup tables must include {}",
            arithmetic::ACTIVATOR_COL_NAME
        );
    }
    let mut filtered = IndexMap::new();
    for (field, poly) in cols.iter() {
        if field.name() == arithmetic::ROW_ID_COL_NAME {
            continue;
        }
        filtered.insert(field.clone(), poly.clone());
    }
    let schema = table.schema_ref().map(|schema| {
        let fields: Vec<Field> = filtered
            .keys()
            .map(|field| field.as_ref().clone())
            .collect();
        Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    arithmetic::table::TrackedTable::new(schema, filtered, table.log_size())
}

fn drop_row_id_keep_activator_verifier<B: SnarkBackend>(
    table: &arithmetic::table_oracle::TrackedTableOracle<B>,
) -> arithmetic::table_oracle::TrackedTableOracle<B> {
    let cols = table.tracked_oracles();
    if !cols
        .keys()
        .any(|field| field.name() == arithmetic::ACTIVATOR_COL_NAME)
    {
        panic!(
            "Match-Pair lookup tables must include {}",
            arithmetic::ACTIVATOR_COL_NAME
        );
    }
    let mut filtered = IndexMap::new();
    for (field, oracle) in cols.iter() {
        if field.name() == arithmetic::ROW_ID_COL_NAME {
            continue;
        }
        filtered.insert(field.clone(), oracle.clone());
    }
    let schema = table.schema_ref().map(|schema| {
        let fields: Vec<Field> = filtered
            .keys()
            .map(|field| field.as_ref().clone())
            .collect();
        Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    arithmetic::table_oracle::TrackedTableOracle::new(schema, filtered, table.log_size())
}

fn lookup_multiplicities_table_prover<B: SnarkBackend>(
    gadget_ready_ir: &mut GadgetReadyIr<B>,
    lookup_node: &Arc<Node<B>>,
) -> arithmetic::table::TrackedTable<B> {
    let Some(PayloadStructure::GadgetPayload(payload)) =
        gadget_ready_ir.payload_for_node(&lookup_node.id())
    else {
        panic!("Expected payload for lookup gadget");
    };
    payload
        .get(lookup::SUPER_MULTIPLICITIES_LABEL)
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "Expected {} for lookup gadget",
                lookup::SUPER_MULTIPLICITIES_LABEL
            )
        })
}

fn lookup_multiplicities_table_verifier<B: SnarkBackend>(
    gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
    lookup_node: &Arc<Node<B>>,
) -> arithmetic::table_oracle::TrackedTableOracle<B> {
    let Some(PayloadStructure::GadgetPayload(payload)) =
        gadget_ready_ir.payload_for_node(&lookup_node.id())
    else {
        panic!("Expected payload for lookup gadget");
    };
    payload
        .get(lookup::SUPER_MULTIPLICITIES_LABEL)
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "Expected {} for lookup gadget",
                lookup::SUPER_MULTIPLICITIES_LABEL
            )
        })
}

fn single_data_poly_from_table<B: SnarkBackend>(
    table: &arithmetic::table::TrackedTable<B>,
    label: &str,
) -> TrackedPoly<B> {
    let data_indices = table.data_tracked_polys_indices();
    if data_indices.len() != 1 {
        panic!("Match-Pair {label} table must have exactly one data column");
    }
    let data_cols = table.tracked_polys();
    let (_, poly) = data_cols
        .get_index(data_indices[0])
        .expect("Match-Pair multiplicity column missing");
    poly.clone()
}
fn single_data_oracle_from_table<B: SnarkBackend>(
    table: &arithmetic::table_oracle::TrackedTableOracle<B>,
    label: &str,
) -> TrackedOracle<B> {
    let data_indices = table.data_tracked_oracles_indices();
    if data_indices.len() != 1 {
        panic!("Match-Pair {label} table must have exactly one data column");
    }
    let data_cols = table.tracked_oracles();
    let (_, oracle) = data_cols
        .get_index(data_indices[0])
        .expect("Match-Pair multiplicity column missing");
    oracle.clone()
}

fn active_row_multiset<B: SnarkBackend>(
    table: &arithmetic::table::TrackedTable<B>,
) -> std::collections::HashMap<String, usize> {
    let data_indices = table.data_tracked_polys_indices();
    let data_evals: Vec<Vec<B::F>> = data_indices
        .iter()
        .copied()
        .map(|idx| {
            table
                .tracked_col_by_ind(idx)
                .data_tracked_poly()
                .evaluations()
        })
        .collect();
    let activator = table
        .activator_tracked_poly()
        .map(|poly| poly.evaluations());
    let size = table.size();

    let mut counts = std::collections::HashMap::new();
    for row in 0..size {
        if let Some(act) = activator.as_ref()
            && act[row] != B::F::one()
        {
            continue;
        }
        let key = if data_evals.is_empty() {
            String::new()
        } else {
            let mut parts = Vec::with_capacity(data_evals.len());
            for col in &data_evals {
                parts.push(format!("{:?}", col[row]));
            }
            parts.join("|")
        };
        *counts.entry(key).or_insert(0) += 1;
    }
    counts
}

fn active_row_count<B: SnarkBackend>(table: &arithmetic::table::TrackedTable<B>) -> usize {
    let activator = table
        .activator_tracked_poly()
        .map(|poly| poly.evaluations());
    let size = table.size();
    match activator {
        Some(act) => act
            .iter()
            .take(size)
            .filter(|val| **val == B::F::one())
            .count(),
        None => size,
    }
}

fn find_parent_id<B: SnarkBackend>(
    id: crate::irs::nodes::NodeId,
    tree: &crate::irs::tree::Tree<B>,
) -> Option<crate::irs::nodes::NodeId> {
    tree.arena().iter().find_map(|(node_id, node)| {
        let is_parent = node.children().iter().any(|child| child.id() == id);
        is_parent.then_some(*node_id)
    })
}

fn find_parent_join_plan<B: SnarkBackend>(
    gadget_id: crate::irs::nodes::NodeId,
    tree: &crate::irs::tree::Tree<B>,
) -> Option<Join> {
    tree.arena().iter().find_map(|(_, node)| {
        let is_parent = node.children().iter().any(|child| child.id() == gadget_id);
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

fn join_key_columns(join: &Join) -> DataFusionResult<(Vec<Column>, Vec<Column>, Vec<String>)> {
    let mut left_cols = Vec::with_capacity(join.on.len());
    let mut right_cols = Vec::with_capacity(join.on.len());
    let mut key_names = Vec::with_capacity(join.on.len());

    for (idx, (left_expr, right_expr)) in join.on.iter().enumerate() {
        let (left_col, right_col) = match (left_expr, right_expr) {
            (Expr::Column(left_col), Expr::Column(right_col)) => (left_col, right_col),
            _ => {
                return Err(DataFusionError::Plan(
                    "match-pair keys must be column expressions".to_string(),
                ));
            }
        };
        left_cols.push(left_col.clone());
        right_cols.push(right_col.clone());
        // Use a deterministic, unambiguous alias for each join key.
        key_names.push(format!("__mp_key_{idx}"));
    }

    Ok((left_cols, right_cols, key_names))
}

fn build_lookup_keys_df(
    df: &DataFrame,
    cols: &[Column],
    key_names: &[String],
    side: &str,
) -> DataFusionResult<DataFrame> {
    let sorted_input = sort_by_row_id_if_present(df.clone())?;
    let mut exprs: Vec<Expr> = cols
        .iter()
        .zip(key_names)
        .map(|(col_ref, name)| Expr::Column(col_ref.clone()).alias(name))
        .collect();
    crate::irs::nodes::hints::append_activator_exprs_if_present(&sorted_input, &mut exprs);
    let sorted = sorted_input.select(exprs)?;

    let mut final_exprs: Vec<Expr> = key_names.iter().map(col).collect();
    crate::irs::nodes::hints::append_activator_exprs_if_present(&sorted, &mut final_exprs);
    let final_df = sorted.select(final_exprs)?;
    if final_df.schema().fields().len() == key_names.len() {
        return Err(DataFusionError::Plan(format!(
            "match-pair {side} lookup keys missing activator column"
        )));
    }
    Ok(final_df)
}

fn row_id_columns(df: &DataFrame, side: &str) -> DataFusionResult<Vec<Column>> {
    let row_id_cols: Vec<Column> = df
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            (field.name() == arithmetic::ROW_ID_COL_NAME)
                .then_some(Column::new(qualifier.cloned(), arithmetic::ROW_ID_COL_NAME))
        })
        .collect();
    if row_id_cols.is_empty() {
        return Err(DataFusionError::Plan(format!(
            "match-pair {side} input is missing {}",
            arithmetic::ROW_ID_COL_NAME
        )));
    }
    Ok(row_id_cols)
}

fn build_key_union_df(
    join: &Join,
    left: &DataFrame,
    right: &DataFrame,
) -> DataFusionResult<(DataFrame, Vec<String>)> {
    let (left_cols, right_cols, key_names) = join_key_columns(join)?;
    let left_row_ids = row_id_columns(left, "left")?;
    let right_row_ids = row_id_columns(right, "right")?;

    let left_keys = build_key_df(left, &left_cols, &key_names, &left_row_ids)?;
    let right_keys = build_key_df(right, &right_cols, &key_names, &right_row_ids)?;

    let unioned = left_keys.union(right_keys)?;
    let key_exprs: Vec<Expr> = key_names.iter().map(col).collect();
    // Deduplicate the union strictly by key values so downstream NoDup sees a true set.
    let deduped_keys = unioned.select(key_exprs.clone())?.distinct()?;
    let with_row_number = deduped_keys.select(
        key_exprs
            .iter()
            .cloned()
            .chain(std::iter::once(
                row_number()
                    .partition_by(Vec::new())
                    .order_by(
                        key_exprs
                            .iter()
                            .cloned()
                            .map(|expr| expr.sort(true, true))
                            .collect(),
                    )
                    .build()?
                    .alias("__row_number__"),
            ))
            .collect(),
    )?;
    let with_row_id = with_row_number.select(
        key_exprs
            .into_iter()
            .chain(std::iter::once(
                (col("__row_number__") - lit(1_i64)).alias(arithmetic::ROW_ID_COL_NAME),
            ))
            .collect(),
    )?;
    Ok((with_row_id, key_names))
}

fn build_key_df(
    df: &DataFrame,
    cols: &[Column],
    key_names: &[String],
    row_id_cols: &[Column],
) -> DataFusionResult<DataFrame> {
    let sorted_df = sort_by_row_id_if_present(df.clone())?;
    let active_df = if sorted_df
        .schema()
        .iter()
        .any(|(_, field)| field.name() == arithmetic::ACTIVATOR_COL_NAME)
    {
        sorted_df.filter(col(arithmetic::ACTIVATOR_COL_NAME).eq(lit(true)))?
    } else {
        sorted_df
    };

    let mut exprs: Vec<Expr> = cols
        .iter()
        .zip(key_names)
        .map(|(col_ref, name)| Expr::Column(col_ref.clone()).alias(name))
        .collect();

    if row_id_cols.len() == 1 {
        exprs.push(Expr::Column(row_id_cols[0].clone()).alias(arithmetic::ROW_ID_COL_NAME));
        return sort_by_row_id_if_present(active_df.select(exprs)?);
    }

    let row_number_expr = row_number()
        .partition_by(Vec::new())
        .order_by(
            row_id_cols
                .iter()
                .cloned()
                .map(|col_ref| Expr::Column(col_ref).sort(true, true))
                .collect(),
        )
        .build()?
        .alias("__row_number__");
    exprs.push(row_number_expr);
    let with_row_number = active_df.select(exprs)?;

    let mut final_exprs: Vec<Expr> = key_names.iter().map(col).collect();
    final_exprs.push((col("__row_number__") - lit(1_i64)).alias(arithmetic::ROW_ID_COL_NAME));
    sort_by_row_id_if_present(with_row_number.select(final_exprs)?)
}

fn pad_key_union_df(df: DataFrame, key_names: &[String]) -> DataFusionResult<DataFrame> {
    let batches = collect_blocking(df.clone())?;
    let schema_ref = if batches.is_empty() {
        Arc::new(df.schema().as_arrow().clone())
    } else {
        batches[0].schema()
    };
    let combined = if batches.is_empty() {
        RecordBatch::new_empty(schema_ref.clone())
    } else {
        let batch_refs: Vec<&RecordBatch> = batches.iter().collect();
        concat_batches(&schema_ref, batch_refs)?
    };
    let row_count = combined.num_rows();
    let target = if row_count == 0 {
        2
    } else {
        row_count.next_power_of_two()
    };
    let pad = target.saturating_sub(row_count);

    let mut output_fields = Vec::with_capacity(key_names.len() + 1);
    let mut output_arrays = Vec::with_capacity(key_names.len() + 1);

    for key in key_names {
        let (idx, field) = combined
            .schema()
            .fields()
            .iter()
            .enumerate()
            .find(|(_, field)| field.name() == key)
            .map(|(idx, field)| (idx, field.clone()))
            .ok_or_else(|| {
                DataFusionError::Plan(format!("match-pair key column missing: {key}"))
            })?;
        let base = combined.column(idx).clone();
        output_fields.push(field.as_ref().clone());
        let out = if pad == 0 {
            base
        } else {
            let pad_arr: ArrayRef = new_null_array(field.data_type(), pad);
            concat(&[base.as_ref(), pad_arr.as_ref()])?
        };
        output_arrays.push(out);
    }

    let mut activator_vals = Vec::with_capacity(target);
    activator_vals.extend(std::iter::repeat_n(true, row_count));
    activator_vals.extend(std::iter::repeat_n(false, pad));
    output_fields.push((**arithmetic::ACTIVATOR_FIELD).clone());
    output_arrays.push(Arc::new(BooleanArray::from(activator_vals)) as _);

    let out_schema = Arc::new(Schema::new(output_fields));
    let out_batch = RecordBatch::try_new(out_schema, output_arrays)?;
    let ctx = SessionContext::new();
    ctx.read_batch(out_batch)
}

fn collect_blocking(df: DataFrame) -> DataFusionResult<Vec<RecordBatch>> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => match handle.runtime_flavor() {
            RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(df.collect()))
            }
            RuntimeFlavor::CurrentThread => {
                let df_clone = df.clone();
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| DataFusionError::Execution(e.to_string()))?;
                    rt.block_on(df_clone.collect())
                })
                .join()
                .map_err(|_| {
                    DataFusionError::Execution("dataframe collection thread panicked".to_string())
                })?
            }
            _ => tokio::task::block_in_place(|| handle.block_on(df.collect())),
        },
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| DataFusionError::Execution(e.to_string()))?;
            rt.block_on(df.collect())
        }
    }
}
