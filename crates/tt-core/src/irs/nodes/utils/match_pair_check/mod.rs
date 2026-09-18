use std::sync::Arc;

mod hints;
#[cfg(test)]
mod tests;

use ark_ff::{One, PrimeField, Zero};
use ark_piop::{
    SnarkBackend, arithmetic::mat_poly::mle::MLE, prover::structs::polynomial::TrackedPoly,
    verifier::structs::oracle::TrackedOracle,
};
use datafusion::{
    arrow::datatypes::{DataType, Field, Schema},
    prelude::DataFrame,
};
use datafusion_common::{Column, DataFusionError, Result as DataFusionResult};
use datafusion_expr::{Expr, Join, LogicalPlan, col};
use indexmap::IndexMap;
use tracing::error;

use self::hints::build_union_hint_df;
use crate::irs::nodes::hints::sort_by_row_id_if_present;
use crate::irs::nodes::utils::{
    bool as bool_check, lookup, nodup, validate_tracked_oracle_table_row_domain,
    validate_tracked_table_row_domain,
};
use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

fn add_match_count_claims_prover<B: SnarkBackend>(
    prover: &mut ark_piop::prover::ArgProver<B>,
    pair_count: &TrackedPoly<B>,
    output_activator: &TrackedPoly<B>,
    claimed_count: B::F,
) -> ark_piop::errors::SnarkResult<()> {
    // A miscellaneous proof field is not transcript-bound before Sumcheck
    // batching.  Instead commit the claimed count as an nv=0 constant, which
    // ark-piop appends to the transcript before it samples batching weights.
    let count =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(0, vec![claimed_count]))?;
    let pair_difference = count_difference_prover(pair_count, &count)?;
    let output_difference = count_difference_prover(output_activator, &count)?;
    prover.add_mv_sumcheck_claim(pair_difference.id(), B::F::zero())?;
    prover.add_mv_sumcheck_claim(output_difference.id(), B::F::zero())?;
    Ok(())
}

fn add_match_count_claims_verifier<B: SnarkBackend>(
    verifier: &mut ark_piop::verifier::ArgVerifier<B>,
    pair_count: &TrackedOracle<B>,
    output_activator: &TrackedOracle<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let count = verifier.track_next_mv_com()?;
    let pair_difference = count_difference_verifier(pair_count, &count)?;
    let output_difference = count_difference_verifier(output_activator, &count)?;
    verifier.add_mv_sumcheck_claim(pair_difference.id(), B::F::zero());
    verifier.add_mv_sumcheck_claim(output_difference.id(), B::F::zero());
    Ok(())
}

fn inverse_domain_size<F: PrimeField>(log_size: usize) -> ark_piop::errors::SnarkResult<F> {
    F::from(2u64)
        .pow([log_size as u64])
        .inverse()
        .ok_or_else(|| match_pair_check_error("Boolean-hypercube size is not invertible"))
}

/// Build a polynomial whose hypercube sum is `sum(values) - count`.
///
/// The committed count has zero variables, so it can be combined with either
/// input domain. Dividing it by that domain's size makes its hypercube sum
/// exactly `count`, even when the pair and output polynomials have different
/// numbers of variables.
fn count_difference_prover<B: SnarkBackend>(
    values: &TrackedPoly<B>,
    count: &TrackedPoly<B>,
) -> ark_piop::errors::SnarkResult<TrackedPoly<B>> {
    let density = count.mul_scalar_poly(inverse_domain_size::<B::F>(values.log_size())?);
    Ok(values - &density)
}

fn count_difference_verifier<B: SnarkBackend>(
    values: &TrackedOracle<B>,
    count: &TrackedOracle<B>,
) -> ark_piop::errors::SnarkResult<TrackedOracle<B>> {
    let density = count.mul_scalar_oracle(inverse_domain_size::<B::F>(values.log_size())?);
    Ok(values - &density)
}

/// Ensure field sums represent the natural join-pair and output-row counts.
///
/// With Boolean activators, the largest possible number of matching pairs is
/// `2^left_log_size * 2^right_log_size`.  Both that count and the output's
/// active-row count must fit below the field characteristic; otherwise equality
/// of the two Sumcheck targets would establish only equality modulo the field.
fn ensure_match_count_no_wrap<F: PrimeField>(
    left_log_size: usize,
    right_log_size: usize,
    output_log_size: usize,
) -> ark_piop::errors::SnarkResult<()> {
    let pair_log_size = left_log_size
        .checked_add(right_log_size)
        .ok_or_else(|| match_pair_check_error("input capacities overflow usize"))?;
    let modulus_bits = F::MODULUS_BIT_SIZE as usize;
    if pair_log_size >= modulus_bits || output_log_size >= modulus_bits {
        return Err(match_pair_check_error(
            "join pair and output capacities must be below the field modulus",
        ));
    }
    Ok(())
}

fn match_pair_check_error(message: &str) -> ark_piop::errors::SnarkError {
    ark_piop::errors::SnarkError::VerifierError(
        ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(format!(
            "Match-Pair check: {message}"
        )),
    )
}

fn ensure_table_tracker_prover<B: SnarkBackend>(
    reference: &TrackedPoly<B>,
    table: &arithmetic::table::TrackedTable<B>,
    label: &str,
) -> ark_piop::errors::SnarkResult<()> {
    let columns = table.tracked_polys();
    let Some((_, first)) = columns.first() else {
        return Err(match_pair_check_error(&format!(
            "{label} has no row-domain columns"
        )));
    };
    if !reference.same_tracker(first) {
        return Err(match_pair_check_error(&format!(
            "{label} belongs to a different proof tracker"
        )));
    }
    Ok(())
}

fn ensure_table_tracker_verifier<B: SnarkBackend>(
    reference: &TrackedOracle<B>,
    table: &arithmetic::table_oracle::TrackedTableOracle<B>,
    label: &str,
) -> ark_piop::errors::SnarkResult<()> {
    let columns = table.tracked_oracles();
    let Some((_, first)) = columns.first() else {
        return Err(match_pair_check_error(&format!(
            "{label} has no row-domain oracles"
        )));
    };
    if !reference.same_tracker(first) {
        return Err(match_pair_check_error(&format!(
            "{label} belongs to a different proof tracker"
        )));
    }
    Ok(())
}

/// Enforce equality of every row-domain encoding segment for each output key.
///
/// The relation is gated by the committed output activator, so inactive
/// padding remains unconstrained. We register one exact Zerocheck per segment:
/// for every active output row `i`, key position `j`, and encoding segment
/// `s`, the verifier checks
///
/// `a_out(i) * (left_key[j][s](i) - right_key[j][s](i)) = 0`.
///
/// All operands come from the already committed join-output table; there is no
/// prover-supplied equality witness.
fn add_output_key_equality_claims_prover<B: SnarkBackend>(
    prover: &mut ark_piop::prover::ArgProver<B>,
    output_activator: &TrackedPoly<B>,
    output_log_size: usize,
    left_keys: &arithmetic::table::TrackedTable<B>,
    right_keys: &arithmetic::table::TrackedTable<B>,
) -> ark_piop::errors::SnarkResult<()> {
    if left_keys.log_size() != output_log_size || right_keys.log_size() != output_log_size {
        return Err(match_pair_check_error(
            "output left/right key tables must share the declared output row domain",
        ));
    }
    if !output_activator.is_constant() && output_activator.log_size() != output_log_size {
        return Err(match_pair_check_error(
            "output activator and output key tables must share one row domain",
        ));
    }

    let left_cols = left_keys
        .tracked_cols_iter()
        .filter(|(field, _)| !arithmetic::is_system_column(field.name()))
        .collect::<Vec<_>>();
    let right_cols = right_keys
        .tracked_cols_iter()
        .filter(|(field, _)| !arithmetic::is_system_column(field.name()))
        .collect::<Vec<_>>();
    if left_cols.is_empty() || left_cols.len() != right_cols.len() {
        return Err(match_pair_check_error(
            "output left/right key tables must contain the same nonzero number of keys",
        ));
    }

    for (key_index, ((left_field, left_col), (right_field, right_col))) in
        left_cols.into_iter().zip(right_cols).enumerate()
    {
        if left_field.data_type() != right_field.data_type() {
            return Err(match_pair_check_error(&format!(
                "output key {key_index} has different left/right encoding types"
            )));
        }
        let left_segments = left_col.segments_iter().collect::<Vec<_>>();
        let right_segments = right_col.segments_iter().collect::<Vec<_>>();
        if left_segments.len() != right_segments.len() {
            return Err(match_pair_check_error(&format!(
                "output key {key_index} has different left/right encoding widths"
            )));
        }

        for (segment_index, (left_segment, right_segment)) in
            left_segments.into_iter().zip(right_segments).enumerate()
        {
            let (left_suffix, left_poly, _) = left_segment;
            let (right_suffix, right_poly, _) = right_segment;
            if left_suffix != right_suffix {
                return Err(match_pair_check_error(&format!(
                    "output key {key_index} segment {segment_index} has incompatible left/right encodings"
                )));
            }
            if (!left_poly.is_constant() && left_poly.log_size() != output_log_size)
                || (!right_poly.is_constant() && right_poly.log_size() != output_log_size)
            {
                return Err(match_pair_check_error(&format!(
                    "output key {key_index} segment {segment_index} is on the wrong row domain"
                )));
            }
            if !left_poly.same_tracker(right_poly) || !left_poly.same_tracker(output_activator) {
                return Err(match_pair_check_error(
                    "output key equality operands must share the proof tracker",
                ));
            }

            let residual = &(left_poly - right_poly) * output_activator;
            prover.add_mv_zerocheck_claim(residual.id())?;
        }
    }
    Ok(())
}

/// Verifier-side mirror of [`add_output_key_equality_claims_prover`].
fn add_output_key_equality_claims_verifier<B: SnarkBackend>(
    verifier: &mut ark_piop::verifier::ArgVerifier<B>,
    output_activator: &TrackedOracle<B>,
    output_log_size: usize,
    left_keys: &arithmetic::table_oracle::TrackedTableOracle<B>,
    right_keys: &arithmetic::table_oracle::TrackedTableOracle<B>,
) -> ark_piop::errors::SnarkResult<()> {
    if left_keys.log_size() != output_log_size || right_keys.log_size() != output_log_size {
        return Err(match_pair_check_error(
            "output left/right key tables must share the declared output row domain",
        ));
    }
    if !output_activator.is_constant() && output_activator.log_size() != output_log_size {
        return Err(match_pair_check_error(
            "output activator and output key tables must share one row domain",
        ));
    }

    let left_cols = left_keys
        .tracked_col_oracles_iter()
        .filter(|(field, _)| !arithmetic::is_system_column(field.name()))
        .collect::<Vec<_>>();
    let right_cols = right_keys
        .tracked_col_oracles_iter()
        .filter(|(field, _)| !arithmetic::is_system_column(field.name()))
        .collect::<Vec<_>>();
    if left_cols.is_empty() || left_cols.len() != right_cols.len() {
        return Err(match_pair_check_error(
            "output left/right key tables must contain the same nonzero number of keys",
        ));
    }

    for (key_index, ((left_field, left_col), (right_field, right_col))) in
        left_cols.into_iter().zip(right_cols).enumerate()
    {
        if left_field.data_type() != right_field.data_type() {
            return Err(match_pair_check_error(&format!(
                "output key {key_index} has different left/right encoding types"
            )));
        }
        let left_segments = left_col.segments_iter().collect::<Vec<_>>();
        let right_segments = right_col.segments_iter().collect::<Vec<_>>();
        if left_segments.len() != right_segments.len() {
            return Err(match_pair_check_error(&format!(
                "output key {key_index} has different left/right encoding widths"
            )));
        }

        for (segment_index, (left_segment, right_segment)) in
            left_segments.into_iter().zip(right_segments).enumerate()
        {
            let (left_suffix, left_oracle, _) = left_segment;
            let (right_suffix, right_oracle, _) = right_segment;
            if left_suffix != right_suffix {
                return Err(match_pair_check_error(&format!(
                    "output key {key_index} segment {segment_index} has incompatible left/right encodings"
                )));
            }
            if (!left_oracle.is_constant() && left_oracle.log_size() != output_log_size)
                || (!right_oracle.is_constant() && right_oracle.log_size() != output_log_size)
            {
                return Err(match_pair_check_error(&format!(
                    "output key {key_index} segment {segment_index} is on the wrong row domain"
                )));
            }
            if !left_oracle.same_tracker(right_oracle)
                || !left_oracle.same_tracker(output_activator)
            {
                return Err(match_pair_check_error(
                    "output key equality operands must share the proof tracker",
                ));
            }

            let residual = &(left_oracle - right_oracle) * output_activator;
            verifier.add_mv_zerocheck_claim(residual.id());
        }
    }
    Ok(())
}

/// The left join keys (either a single key or a composite key)
pub const LEFT_LABEL: &str = "__left__";
/// The right join keys (either a single key or a composite key)
pub const RIGHT_LABEL: &str = "__right__";
/// The join-key columns contributed by the left input to each output row.
pub const OUTPUT_LEFT_KEYS_LABEL: &str = "__output_left_keys__";
/// The join-key columns contributed by the right input to each output row.
pub const OUTPUT_RIGHT_KEYS_LABEL: &str = "__output_right_keys__";
/// The output of the join gadget
/// TODO: This is not in the paper, but we use it here to extract the number of matches; i.e. `s` in the paper's notation. We should remove it in the future
pub const OUT_LABEL: &str = "__out__";
/// The union of left and right keys
pub const UNION_LABEL: &str = "__union__";

thread_local! {
    static MATCH_PAIR_PLANNING_CACHE: std::cell::RefCell<Option<IndexMap<crate::irs::nodes::NodeId, MatchPairPlanningContext>>> =
        const { std::cell::RefCell::new(None) };
}

#[derive(Clone)]
struct MatchPairPlanningContext {
    left_hint: crate::irs::nodes::hints::HintDF,
    right_hint: crate::irs::nodes::hints::HintDF,
    join: Join,
}

struct MatchPairPlannedHints {
    key_hint: crate::irs::nodes::hints::HintDF,
    union_hint: crate::irs::nodes::hints::HintDF,
    left_lookup_hint: crate::irs::nodes::hints::HintDF,
    right_lookup_hint: crate::irs::nodes::hints::HintDF,
}

fn union_runtime_hint(df: DataFrame) -> crate::irs::nodes::hints::HintDF {
    let should_materialize = df
        .schema()
        .fields()
        .iter()
        .map(|field| {
            let materialize = field.name() != arithmetic::ROW_ID_COL_NAME;
            (field.clone(), materialize)
        })
        .collect();
    crate::irs::nodes::hints::HintDF::new(df, should_materialize)
}

pub struct GadgetNode<B: SnarkBackend> {
    union_activator_bool_gadget: Arc<Node<B>>,
    left_activator_bool_gadget: Arc<Node<B>>,
    right_activator_bool_gadget: Arc<Node<B>>,
    nodup_gadget: Arc<Node<B>>,
    left_lookup_gadget: Arc<Node<B>>,
    right_lookup_gadget: Arc<Node<B>>,
}

pub fn begin_match_pair_planning_cache_scope() {
    MATCH_PAIR_PLANNING_CACHE.with(|cache| {
        *cache.borrow_mut() = Some(IndexMap::new());
    });
}

pub fn end_match_pair_planning_cache_scope() {
    MATCH_PAIR_PLANNING_CACHE.with(|cache| {
        *cache.borrow_mut() = None;
    });
}

pub fn cache_match_pair_planning_context(
    id: crate::irs::nodes::NodeId,
    left_hint: crate::irs::nodes::hints::HintDF,
    right_hint: crate::irs::nodes::hints::HintDF,
    join: Join,
) {
    MATCH_PAIR_PLANNING_CACHE.with(|cache| {
        if let Some(scope_cache) = cache.borrow_mut().as_mut() {
            scope_cache.insert(
                id,
                MatchPairPlanningContext {
                    left_hint,
                    right_hint,
                    join,
                },
            );
        }
    });
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Match-Pair Check".to_string()
    }

    fn display(&self) -> String {
        self.name()
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
            self.union_activator_bool_gadget.clone(),
            self.left_activator_bool_gadget.clone(),
            self.right_activator_bool_gadget.clone(),
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
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Get the context plans for this node
        let Some(ctx) = load_match_pair_planning_context(id, planned_ir) else {
            panic!(
                "Match-Pair gadget planning payload should have been populated by the parent Join gadget"
            );
        };
        let (left_cols, right_cols, key_names) =
            join_key_columns(&ctx.join).expect("match-pair join keys should be columns");

        let left_keys_df =
            build_lookup_keys_df(ctx.left_hint.data_frame(), &left_cols, &key_names, "left")
                .expect("match-pair left key projection should succeed");
        let right_keys_df = build_lookup_keys_df(
            ctx.right_hint.data_frame(),
            &right_cols,
            &key_names,
            "right",
        )
        .expect("match-pair right key projection should succeed");
        let key_union = build_union_hint_df(left_keys_df.clone(), right_keys_df.clone())
            .expect("match-pair union hint should succeed");
        let key_hint = union_runtime_hint(key_union);
        let union_df = sort_by_row_id_if_present(key_hint.data_frame().clone())
            .expect("match-pair union sort should succeed");
        let union_hint = crate::irs::nodes::hints::HintDF::new_virtual(union_df);

        let left_lookup_hint = crate::irs::nodes::hints::HintDF::new_virtual(left_keys_df);
        let left_lookup_hint = crate::irs::nodes::hints::strip_row_id_from_hint(&left_lookup_hint);

        let right_lookup_hint = crate::irs::nodes::hints::HintDF::new_virtual(right_keys_df);
        let right_lookup_hint =
            crate::irs::nodes::hints::strip_row_id_from_hint(&right_lookup_hint);
        apply_match_pair_planned_hints(
            self,
            id,
            planned_ir,
            MatchPairPlannedHints {
                key_hint,
                union_hint,
                left_lookup_hint,
                right_lookup_hint,
            },
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
            panic!("Expected gadget payload for Match-Pair gadget node");
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
        validate_tracked_table_row_domain(&union, "Match-Pair union")?;
        validate_tracked_table_row_domain(&left_keys, "Match-Pair left keys")?;
        validate_tracked_table_row_domain(&right_keys, "Match-Pair right keys")?;
        let union_activator = union
            .activator_tracked_poly()
            .ok_or_else(|| match_pair_check_error("union table is missing its activator"))?;
        ensure_table_tracker_prover(&union_activator, &left_keys, "left-key table")?;
        ensure_table_tracker_prover(&union_activator, &right_keys, "right-key table")?;

        // The multiplicity and count equations below interpret all three
        // activators as ordinary set-membership bits.  Check each exact
        // runtime commitment independently: checking only the union would
        // leave fractional input weights available to satisfy the weighted
        // lookup and pair-count equations without representing SQL rows.
        populate_activator_bool_payload_prover(
            &self.union_activator_bool_gadget,
            &union,
            "union_activator",
            virtualized_ir,
        )?;
        populate_activator_bool_payload_prover(
            &self.left_activator_bool_gadget,
            &left_keys,
            "left_activator",
            virtualized_ir,
        )?;
        populate_activator_bool_payload_prover(
            &self.right_activator_bool_gadget,
            &right_keys,
            "right_activator",
            virtualized_ir,
        )?;

        let mut nodup_payload = match virtualized_ir.payload_for_node(&self.nodup_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        // Planning provides a materialization hint for NoDup, but the proved
        // relation must use the exact union table whose multiplicities and
        // activator are constrained below. Retaining an independently
        // committed hint would let a duplicated runtime union pass NoDup by
        // supplying a separate, duplicate-free table to that child gadget.
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
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Get the ctx plans for this node
        let Some(ctx) = load_match_pair_planning_context(id, planned_ir) else {
            panic!(
                "Match-Pair gadget planning payload should have been populated by the parent Join gadget"
            );
        };

        let (left_cols, right_cols, key_names) =
            join_key_columns(&ctx.join).expect("match-pair join keys should be columns");
        let left_keys_df = build_lookup_keys_schema_only(
            ctx.left_hint.data_frame(),
            &left_cols,
            &key_names,
            "left",
        )
        .expect("match-pair verifier left key schema should succeed");
        let right_keys_df = build_lookup_keys_schema_only(
            ctx.right_hint.data_frame(),
            &right_cols,
            &key_names,
            "right",
        )
        .expect("match-pair verifier right key schema should succeed");
        let key_union = build_union_schema_only(&key_names, &left_keys_df)
            .expect("match-pair verifier union schema should succeed");
        let key_hint = union_runtime_hint(key_union);
        let union_hint =
            crate::irs::nodes::hints::HintDF::new_virtual(key_hint.data_frame().clone());
        let left_lookup_hint = strip_row_id_keep_activator_schema_only(
            &crate::irs::nodes::hints::HintDF::new_virtual(left_keys_df),
        );
        let right_lookup_hint = strip_row_id_keep_activator_schema_only(
            &crate::irs::nodes::hints::HintDF::new_virtual(right_keys_df),
        );

        apply_match_pair_planned_hints(
            self,
            id,
            planned_ir,
            MatchPairPlannedHints {
                key_hint,
                union_hint,
                left_lookup_hint,
                right_lookup_hint,
            },
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
        let (union, left_keys, right_keys) = {
            let Some(PayloadStructure::GadgetPayload(payload)) =
                virtualized_ir.payload_for_node(&id)
            else {
                return Ok(());
            };
            (
                payload
                    .get(UNION_LABEL)
                    .cloned()
                    .unwrap_or_else(|| panic!("Match-Pair gadget missing {}", UNION_LABEL)),
                payload
                    .get(LEFT_LABEL)
                    .cloned()
                    .unwrap_or_else(|| panic!("Match-Pair gadget missing {}", LEFT_LABEL)),
                payload
                    .get(RIGHT_LABEL)
                    .cloned()
                    .unwrap_or_else(|| panic!("Match-Pair gadget missing {}", RIGHT_LABEL)),
            )
        };
        validate_tracked_oracle_table_row_domain(&union, "Match-Pair union")?;
        validate_tracked_oracle_table_row_domain(&left_keys, "Match-Pair left keys")?;
        validate_tracked_oracle_table_row_domain(&right_keys, "Match-Pair right keys")?;
        let union_activator = union
            .activator_tracked_poly()
            .ok_or_else(|| match_pair_check_error("union table is missing its activator"))?;
        ensure_table_tracker_verifier(&union_activator, &left_keys, "left-key table")?;
        ensure_table_tracker_verifier(&union_activator, &right_keys, "right-key table")?;
        let union_no_row_id = drop_row_id_keep_activator_verifier(&union);
        let left_keys_no_row_id = drop_row_id_keep_activator_verifier(&left_keys);
        let right_keys_no_row_id = drop_row_id_keep_activator_verifier(&right_keys);

        populate_activator_bool_payload_verifier(
            &self.union_activator_bool_gadget,
            &union,
            "union_activator",
            virtualized_ir,
        )?;
        populate_activator_bool_payload_verifier(
            &self.left_activator_bool_gadget,
            &left_keys,
            "left_activator",
            virtualized_ir,
        )?;
        populate_activator_bool_payload_verifier(
            &self.right_activator_bool_gadget,
            &right_keys,
            "right_activator",
            virtualized_ir,
        )?;

        let mut nodup_payload = match virtualized_ir.payload_for_node(&self.nodup_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        // Mirror the prover: bind NoDup to the runtime union oracles rather
        // than to the independent planning materialization.
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
        left_lookup_payload.insert(lookup::INCLUDED_LABEL.to_string(), left_keys_no_row_id);
        left_lookup_payload.insert(lookup::SUPER_LABEL.to_string(), union_no_row_id.clone());
        virtualized_ir.set_payload_for_node(
            self.left_lookup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(left_lookup_payload)),
        );

        let mut right_lookup_payload =
            match virtualized_ir.payload_for_node(&self.right_lookup_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
        right_lookup_payload.insert(lookup::INCLUDED_LABEL.to_string(), right_keys_no_row_id);
        right_lookup_payload.insert(lookup::SUPER_LABEL.to_string(), union_no_row_id);
        virtualized_ir.set_payload_for_node(
            self.right_lookup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(right_lookup_payload)),
        );
        Ok(())
    }
}

fn strip_row_id_keep_activator_schema_only(
    hint: &crate::irs::nodes::hints::HintDF,
) -> crate::irs::nodes::hints::HintDF {
    let fields = hint
        .data_frame()
        .schema()
        .fields()
        .iter()
        .filter(|field| field.name() != arithmetic::ROW_ID_COL_NAME)
        .map(|field| field.as_ref().clone())
        .collect();
    crate::irs::nodes::hints::HintDF::new_virtual(crate::irs::nodes::hints::schema_only_df(fields))
}

fn build_lookup_keys_schema_only(
    df: &DataFrame,
    cols: &[Column],
    key_names: &[String],
    side: &str,
) -> DataFusionResult<DataFrame> {
    let mut fields = Vec::with_capacity(key_names.len() + 2);
    for (col_ref, key_name) in cols.iter().zip(key_names) {
        let key_field = resolve_field_for_column(df, col_ref, side)?;
        fields.push(Field::new(
            key_name,
            key_field.data_type().clone(),
            key_field.is_nullable(),
        ));
    }
    fields.push((**arithmetic::ROW_ID_FIELD).clone());
    fields.push((**arithmetic::ACTIVATOR_FIELD).clone());
    Ok(crate::irs::nodes::hints::schema_only_df(fields))
}

fn build_union_schema_only(
    key_names: &[String],
    keys_df: &DataFrame,
) -> DataFusionResult<DataFrame> {
    let mut fields = Vec::with_capacity(key_names.len() + 2);
    for key_name in key_names {
        let field = keys_df
            .schema()
            .fields()
            .iter()
            .find(|f| f.name() == key_name)
            .ok_or_else(|| {
                DataFusionError::Plan(format!("match-pair key column missing: {key_name}"))
            })?;
        fields.push(field.as_ref().clone());
    }
    fields.push((**arithmetic::ROW_ID_FIELD).clone());
    fields.push((**arithmetic::ACTIVATOR_FIELD).clone());
    Ok(crate::irs::nodes::hints::schema_only_df(fields))
}

fn resolve_field_for_column<'a>(
    df: &'a DataFrame,
    col: &Column,
    side: &str,
) -> DataFusionResult<&'a Field> {
    if let Some(relation) = &col.relation
        && let Some((_, field)) = df.schema().iter().find(|(qualifier, field)| {
            qualifier.as_ref().is_some_and(|q| *q == relation) && field.name() == &col.name
        })
    {
        return Ok(field);
    }

    let mut by_name = df
        .schema()
        .iter()
        .filter(|(_, field)| field.name() == &col.name)
        .map(|(_, field)| field);
    let Some(first) = by_name.next() else {
        return Err(DataFusionError::Plan(format!(
            "match-pair {side} key column not found: {}",
            col.flat_name()
        )));
    };
    if by_name.next().is_some() {
        return Err(DataFusionError::Plan(format!(
            "match-pair {side} key column is ambiguous: {}",
            col.flat_name()
        )));
    }
    Ok(first)
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
        let Some(left_table) = payload.get(LEFT_LABEL).cloned() else {
            panic!("Expected left table for Match-Pair gadget");
        };
        let Some(right_table) = payload.get(RIGHT_LABEL).cloned() else {
            panic!("Expected right table for Match-Pair gadget");
        };
        let Some(output_left_keys) = payload.get(OUTPUT_LEFT_KEYS_LABEL).cloned() else {
            panic!("Expected output-left key table for Match-Pair gadget");
        };
        let Some(output_right_keys) = payload.get(OUTPUT_RIGHT_KEYS_LABEL).cloned() else {
            panic!("Expected output-right key table for Match-Pair gadget");
        };
        validate_tracked_table_row_domain(&union_table, "Match-Pair union")?;
        validate_tracked_table_row_domain(&output_table, "Match-Pair output")?;
        validate_tracked_table_row_domain(&left_table, "Match-Pair left keys")?;
        validate_tracked_table_row_domain(&right_table, "Match-Pair right keys")?;
        validate_tracked_table_row_domain(&output_left_keys, "Match-Pair output-left keys")?;
        validate_tracked_table_row_domain(&output_right_keys, "Match-Pair output-right keys")?;
        ensure_match_count_no_wrap::<B::F>(
            left_table.log_size(),
            right_table.log_size(),
            output_table.log_size(),
        )?;

        let left_multiplicities =
            lookup_multiplicities_table_prover(gadget_ready_ir, &self.left_lookup_gadget);
        let right_multiplicities =
            lookup_multiplicities_table_prover(gadget_ready_ir, &self.right_lookup_gadget);
        validate_tracked_table_row_domain(&left_multiplicities, "Match-Pair left multiplicities")?;
        validate_tracked_table_row_domain(
            &right_multiplicities,
            "Match-Pair right multiplicities",
        )?;
        if left_multiplicities.log_size() != union_table.log_size()
            || right_multiplicities.log_size() != union_table.log_size()
        {
            return Err(match_pair_check_error(
                "union and lookup multiplicities must share one row domain",
            ));
        }
        let union_activator = union_table
            .activator_tracked_poly()
            .ok_or_else(|| match_pair_check_error("union table is missing its activator"))?;
        let output_activator = output_table
            .activator_tracked_poly()
            .ok_or_else(|| match_pair_check_error("output table is missing its activator"))?;
        for (table, label) in [
            (&output_table, "output table"),
            (&left_table, "left-key table"),
            (&right_table, "right-key table"),
            (&output_left_keys, "output-left-key table"),
            (&output_right_keys, "output-right-key table"),
            (&left_multiplicities, "left-multiplicity table"),
            (&right_multiplicities, "right-multiplicity table"),
        ] {
            ensure_table_tracker_prover(&union_activator, table, label)?;
        }
        add_output_key_equality_claims_prover(
            prover,
            &output_activator,
            output_table.log_size(),
            &output_left_keys,
            &output_right_keys,
        )?;
        let left_mult = single_data_poly_from_table(&left_multiplicities, "left multiplicity")?;
        let right_mult = single_data_poly_from_table(&right_multiplicities, "right multiplicity")?;
        let union_left = &union_activator * &(&left_mult * &right_mult);

        let output_sum = output_activator
            .evaluations()
            .into_iter()
            .fold(B::F::zero(), |acc, val| acc + val);
        // Both zero-sum claims share one transcript-bound count constant. The
        // first establishes the number of matching input pairs; the second
        // binds that number to the materialized join output's activator.
        add_match_count_claims_prover(prover, &union_left, &output_activator, output_sum)?;
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
        let union_keys = payload
            .get(UNION_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Match-Pair gadget missing {}", UNION_LABEL));
        let output_table = payload
            .get(OUT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Match-Pair gadget missing {}", OUT_LABEL));
        // The optional host-side honest check must apply the same structural
        // preconditions as the proof path before it iterates evaluations.
        // This keeps malformed row-domain metadata fail-closed instead of
        // letting debug/release indexing behavior decide the result.
        validate_tracked_table_row_domain(&union_keys, "Match-Pair honest-check union")?;
        validate_tracked_table_row_domain(&left_keys, "Match-Pair honest-check left keys")?;
        validate_tracked_table_row_domain(&right_keys, "Match-Pair honest-check right keys")?;
        validate_tracked_table_row_domain(&output_table, "Match-Pair honest-check output")?;
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
        let Some(left_table) = payload.get(LEFT_LABEL).cloned() else {
            panic!("Expected left table for Match-Pair gadget");
        };
        let Some(right_table) = payload.get(RIGHT_LABEL).cloned() else {
            panic!("Expected right table for Match-Pair gadget");
        };
        let Some(output_left_keys) = payload.get(OUTPUT_LEFT_KEYS_LABEL).cloned() else {
            panic!("Expected output-left key table for Match-Pair gadget");
        };
        let Some(output_right_keys) = payload.get(OUTPUT_RIGHT_KEYS_LABEL).cloned() else {
            panic!("Expected output-right key table for Match-Pair gadget");
        };
        validate_tracked_oracle_table_row_domain(&union_table, "Match-Pair union")?;
        validate_tracked_oracle_table_row_domain(&output_table, "Match-Pair output")?;
        validate_tracked_oracle_table_row_domain(&left_table, "Match-Pair left keys")?;
        validate_tracked_oracle_table_row_domain(&right_table, "Match-Pair right keys")?;
        validate_tracked_oracle_table_row_domain(&output_left_keys, "Match-Pair output-left keys")?;
        validate_tracked_oracle_table_row_domain(
            &output_right_keys,
            "Match-Pair output-right keys",
        )?;
        ensure_match_count_no_wrap::<B::F>(
            left_table.log_size(),
            right_table.log_size(),
            output_table.log_size(),
        )?;

        let left_multiplicities =
            lookup_multiplicities_table_verifier(gadget_ready_ir, &self.left_lookup_gadget);
        let right_multiplicities =
            lookup_multiplicities_table_verifier(gadget_ready_ir, &self.right_lookup_gadget);
        validate_tracked_oracle_table_row_domain(
            &left_multiplicities,
            "Match-Pair left multiplicities",
        )?;
        validate_tracked_oracle_table_row_domain(
            &right_multiplicities,
            "Match-Pair right multiplicities",
        )?;
        if left_multiplicities.log_size() != union_table.log_size()
            || right_multiplicities.log_size() != union_table.log_size()
        {
            return Err(match_pair_check_error(
                "union and lookup multiplicities must share one row domain",
            ));
        }

        let union_activator = union_table
            .activator_tracked_poly()
            .ok_or_else(|| match_pair_check_error("union table is missing its activator"))?;
        let output_activator = output_table
            .activator_tracked_poly()
            .ok_or_else(|| match_pair_check_error("output table is missing its activator"))?;
        for (table, label) in [
            (&output_table, "output table"),
            (&left_table, "left-key table"),
            (&right_table, "right-key table"),
            (&output_left_keys, "output-left-key table"),
            (&output_right_keys, "output-right-key table"),
            (&left_multiplicities, "left-multiplicity table"),
            (&right_multiplicities, "right-multiplicity table"),
        ] {
            ensure_table_tracker_verifier(&union_activator, table, label)?;
        }
        add_output_key_equality_claims_verifier(
            verifier,
            &output_activator,
            output_table.log_size(),
            &output_left_keys,
            &output_right_keys,
        )?;

        let left_mult = single_data_oracle_from_table(&left_multiplicities, "left multiplicity")?;
        let right_mult =
            single_data_oracle_from_table(&right_multiplicities, "right multiplicity")?;

        let union_left = &union_activator * &(&left_mult * &right_mult);

        // Mirror the prover's transcript-bound count constant and the two
        // zero-sum differences. This remains sound when ark-piop batches the
        // claims because the shared count precedes the batching challenges.
        add_match_count_claims_verifier(verifier, &union_left, &output_activator)?;
        Ok(())
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
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
        let union_activator_bool_gadget =
            Arc::new(Node::<B>::Gadget(Arc::new(bool_check::GadgetNode::new())));
        let left_activator_bool_gadget =
            Arc::new(Node::<B>::Gadget(Arc::new(bool_check::GadgetNode::new())));
        let right_activator_bool_gadget =
            Arc::new(Node::<B>::Gadget(Arc::new(bool_check::GadgetNode::new())));
        let nodup_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::utils::nodup::GadgetNode::default(),
        )));
        let left_lookup_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::utils::lookup::GadgetNode::new(),
        )));
        let right_lookup_gadget = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::utils::lookup::GadgetNode::new(),
        )));
        Self {
            union_activator_bool_gadget,
            left_activator_bool_gadget,
            right_activator_bool_gadget,
            nodup_gadget,
            left_lookup_gadget,
            right_lookup_gadget,
        }
    }
}

/// Reinterpret a table activator as ordinary data with no gating activator.
///
/// BoolCheck gates a data column when its table carries an activator.  Here the
/// value being checked *is* the activator, so attaching it again as a gate would
/// accept arbitrary values at zero-weight slots.  The synthetic one-column
/// table deliberately has no system activator and therefore checks every slot.
fn activator_bool_table_prover<B: SnarkBackend>(
    table: &arithmetic::table::TrackedTable<B>,
    field_name: &str,
) -> ark_piop::errors::SnarkResult<arithmetic::table::TrackedTable<B>> {
    let activator = table
        .activator_tracked_poly()
        .ok_or_else(|| match_pair_check_error("Booleanity input is missing its activator"))?;
    let field = Arc::new(Field::new(field_name, DataType::Boolean, false));
    let mut tracked_polys = IndexMap::new();
    tracked_polys.insert(field.clone(), activator);
    Ok(arithmetic::table::TrackedTable::new(
        Some(Schema::new(vec![field.as_ref().clone()])),
        tracked_polys,
        table.log_size(),
    ))
}

fn activator_bool_table_verifier<B: SnarkBackend>(
    table: &arithmetic::table_oracle::TrackedTableOracle<B>,
    field_name: &str,
) -> ark_piop::errors::SnarkResult<arithmetic::table_oracle::TrackedTableOracle<B>> {
    let activator = table
        .activator_tracked_poly()
        .ok_or_else(|| match_pair_check_error("Booleanity input is missing its activator"))?;
    let field = Arc::new(Field::new(field_name, DataType::Boolean, false));
    let mut tracked_oracles = IndexMap::new();
    tracked_oracles.insert(field.clone(), activator);
    Ok(arithmetic::table_oracle::TrackedTableOracle::new(
        Some(Schema::new(vec![field.as_ref().clone()])),
        tracked_oracles,
        table.log_size(),
    ))
}

fn populate_activator_bool_payload_prover<B: SnarkBackend>(
    bool_gadget: &Arc<Node<B>>,
    table: &arithmetic::table::TrackedTable<B>,
    field_name: &str,
    virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let mut bool_payload = match virtualized_ir.payload_for_node(&bool_gadget.id()) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    bool_payload.insert(
        bool_check::TABLE_LABEL.to_string(),
        activator_bool_table_prover(table, field_name)?,
    );
    virtualized_ir.set_payload_for_node(
        bool_gadget.id(),
        Some(PayloadStructure::GadgetPayload(bool_payload)),
    );
    Ok(())
}

fn populate_activator_bool_payload_verifier<B: SnarkBackend>(
    bool_gadget: &Arc<Node<B>>,
    table: &arithmetic::table_oracle::TrackedTableOracle<B>,
    field_name: &str,
    virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let mut bool_payload = match virtualized_ir.payload_for_node(&bool_gadget.id()) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    bool_payload.insert(
        bool_check::TABLE_LABEL.to_string(),
        activator_bool_table_verifier(table, field_name)?,
    );
    virtualized_ir.set_payload_for_node(
        bool_gadget.id(),
        Some(PayloadStructure::GadgetPayload(bool_payload)),
    );
    Ok(())
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
) -> ark_piop::errors::SnarkResult<TrackedPoly<B>> {
    validate_tracked_table_row_domain(table, &format!("Match-Pair {label}"))?;
    let data_indices = table.data_tracked_polys_indices();
    if data_indices.len() != 1 {
        return Err(match_pair_check_error(&format!(
            "{label} table must have exactly one data column"
        )));
    }
    let data_cols = table.tracked_polys();
    let (_, poly) = data_cols
        .get_index(data_indices[0])
        .ok_or_else(|| match_pair_check_error("multiplicity column is missing"))?;
    Ok(poly.clone())
}
fn single_data_oracle_from_table<B: SnarkBackend>(
    table: &arithmetic::table_oracle::TrackedTableOracle<B>,
    label: &str,
) -> ark_piop::errors::SnarkResult<TrackedOracle<B>> {
    validate_tracked_oracle_table_row_domain(table, &format!("Match-Pair {label}"))?;
    let data_indices = table.data_tracked_oracles_indices();
    if data_indices.len() != 1 {
        return Err(match_pair_check_error(&format!(
            "{label} table must have exactly one data column"
        )));
    }
    let data_cols = table.tracked_oracles();
    let (_, oracle) = data_cols
        .get_index(data_indices[0])
        .ok_or_else(|| match_pair_check_error("multiplicity oracle is missing"))?;
    Ok(oracle.clone())
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

fn load_match_pair_planning_context<B: SnarkBackend>(
    id: crate::irs::nodes::NodeId,
    planned_ir: &crate::irs::shared_ir::OutputPlannedIr<B>,
) -> Option<MatchPairPlanningContext> {
    if let Some(cached) = MATCH_PAIR_PLANNING_CACHE.with(|cache| {
        cache
            .borrow()
            .as_ref()
            .and_then(|scope_cache| scope_cache.get(&id).cloned())
    }) {
        return Some(cached);
    }
    let payload = match planned_ir.payload_for_node(&id) {
        Some(PayloadStructure::GadgetPayload(map)) => map,
        _ => return None,
    };
    let left_hint = payload.get(LEFT_LABEL)?.clone();
    let right_hint = payload.get(RIGHT_LABEL)?.clone();
    let parent_id = find_parent_id(id, planned_ir.tree())?;
    let join = find_parent_join_plan(parent_id, planned_ir.tree())?;
    Some(MatchPairPlanningContext {
        left_hint,
        right_hint,
        join,
    })
}

fn apply_match_pair_planned_hints<B: SnarkBackend>(
    node: &GadgetNode<B>,
    id: crate::irs::nodes::NodeId,
    planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    hints: MatchPairPlannedHints,
) {
    let mut gadget_payload = match planned_ir.payload_for_node(&id) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    gadget_payload.insert(UNION_LABEL.to_string(), hints.key_hint);
    planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));

    let mut nodup_payload = match planned_ir.payload_for_node(&node.nodup_gadget.id()) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    nodup_payload
        .entry(nodup::INPUT_LABEL.to_string())
        .or_insert_with(|| hints.union_hint.clone());
    planned_ir.set_payload_for_node(
        node.nodup_gadget.id(),
        Some(PayloadStructure::GadgetPayload(nodup_payload)),
    );

    let mut left_lookup_payload = match planned_ir.payload_for_node(&node.left_lookup_gadget.id()) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    left_lookup_payload.insert(lookup::INCLUDED_LABEL.to_string(), hints.left_lookup_hint);
    left_lookup_payload.insert(lookup::SUPER_LABEL.to_string(), hints.union_hint.clone());
    planned_ir.set_payload_for_node(
        node.left_lookup_gadget.id(),
        Some(PayloadStructure::GadgetPayload(left_lookup_payload)),
    );

    let mut right_lookup_payload = match planned_ir.payload_for_node(&node.right_lookup_gadget.id())
    {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    right_lookup_payload.insert(lookup::INCLUDED_LABEL.to_string(), hints.right_lookup_hint);
    right_lookup_payload.insert(lookup::SUPER_LABEL.to_string(), hints.union_hint);
    planned_ir.set_payload_for_node(
        node.right_lookup_gadget.id(),
        Some(PayloadStructure::GadgetPayload(right_lookup_payload)),
    );
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
    crate::irs::nodes::hints::append_row_id_expr_if_present(&sorted_input, &mut exprs);
    crate::irs::nodes::hints::append_activator_exprs_if_present(&sorted_input, &mut exprs);
    let sorted = sorted_input.select(exprs)?;

    let mut final_exprs: Vec<Expr> = key_names.iter().map(col).collect();
    crate::irs::nodes::hints::append_row_id_expr_if_present(&sorted, &mut final_exprs);
    crate::irs::nodes::hints::append_activator_exprs_if_present(&sorted, &mut final_exprs);
    let final_df = sorted.select(final_exprs)?;
    if !final_df
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == arithmetic::ROW_ID_COL_NAME)
    {
        return Err(DataFusionError::Plan(format!(
            "match-pair {side} lookup keys missing row id column"
        )));
    }
    if final_df
        .schema()
        .fields()
        .iter()
        .all(|field| field.name() != arithmetic::ACTIVATOR_COL_NAME)
    {
        return Err(DataFusionError::Plan(format!(
            "match-pair {side} lookup keys missing activator column"
        )));
    }
    Ok(final_df)
}
