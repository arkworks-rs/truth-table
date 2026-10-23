//! MatchPaircheck, the paper's matching pair check that the inner join
//! (PIOP 18) invokes: `s` is the number of matching pairs between the left
//! and right keys.
//!
//! 1. The prover sends `t` and the union `û` of the distinct keys, sorted;
//!    `û.act := C_{µ,t}` is public.
//! 2. A StrictSortcheck (the sort check's distinct mode) on `û` proves its
//!    keys distinct.
//! 3. Lookups prove both sides' keys in `û` and give the multiplicities
//!    `m_L`, `m_R`.
//! 4. A sumcheck proves `Σ û.act · m_L · m_R = s`.
use std::sync::{Arc, Mutex};

mod hints;

use ark_ff::{One, Zero};
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::SnarkError,
    prover::structs::polynomial::TrackedPoly,
    verifier::{errors::VerifierError, structs::oracle::TrackedOracle},
};
use datafusion::{
    arrow::datatypes::{Field, Schema},
    prelude::DataFrame,
};
use datafusion_common::{Column, DataFusionError, Result as DataFusionResult};
use datafusion_expr::{Expr, Join, LogicalPlan, col};
use either::Either;
use indexmap::IndexMap;
use tracing::error;

use self::hints::build_union_hint_df;
use crate::irs::nodes::hints::{HintDF, sort_by_row_id_if_present};
use crate::irs::nodes::utils::contig_sort::{ACTIVE_ROWS_LABEL, active_rows_field};
use crate::irs::nodes::utils::{
    commit_with_tracker, contig_sort, field_to_usize, lookup, track_next_committed,
};
use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

/// The left join keys (a single key or a composite key).
pub const LEFT_LABEL: &str = "__left__";
/// The right join keys (a single key or a composite key).
pub const RIGHT_LABEL: &str = "__right__";
/// The join output. The pair count is claimed as the sum of its activator,
/// which is the number of active output rows only for a Boolean activator;
/// the join passes the public `C_{µ,s}`, so the count is `s` (paper PIOP 18,
/// step 2).
pub const OUT_LABEL: &str = "__out__";
/// The sorted union `û` of the left and right keys.
pub const UNION_LABEL: &str = "__union__";

thread_local! {
    static MATCH_PAIR_PLANNING_CACHE: std::cell::RefCell<Option<IndexMap<crate::irs::nodes::NodeId, MatchPairPlanningContext>>> =
        const { std::cell::RefCell::new(None) };
}

#[derive(Clone)]
struct MatchPairPlanningContext {
    left_hint: HintDF,
    right_hint: HintDF,
    join: Join,
}

/// `û` with every column but the row id and the activator committed: the
/// activator is the public `C_{µ,t}`.
fn union_runtime_hint(df: DataFrame) -> HintDF {
    let should_materialize = df
        .schema()
        .fields()
        .iter()
        .map(|field| (field.clone(), !arithmetic::is_system_column(field.name())))
        .collect();
    HintDF::new(df, should_materialize)
}

pub struct GadgetNode<B: SnarkBackend> {
    sort_gadget: Arc<Node<B>>,
    left_lookup_gadget: Arc<Node<B>>,
    right_lookup_gadget: Arc<Node<B>>,
    /// The prover's `t`, counted in planning.
    active_rows: Mutex<Option<usize>>,
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
            self.sort_gadget.clone(),
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
        let (union_df, active_rows) =
            build_union_hint_df::<B::F>(left_keys_df.clone(), right_keys_df.clone())
                .map_err(|e| SnarkError::Artifact(format!("match-pair union hint: {e}")))?;
        *self.active_rows.lock().expect("lock poisoned") = Some(active_rows);

        let left_lookup_hint =
            crate::irs::nodes::hints::strip_row_id_from_hint(&HintDF::new_virtual(left_keys_df));
        let right_lookup_hint =
            crate::irs::nodes::hints::strip_row_id_from_hint(&HintDF::new_virtual(right_keys_df));
        apply_match_pair_planned_hints(
            self,
            id,
            planned_ir,
            union_runtime_hint(union_df),
            left_lookup_hint,
            right_lookup_hint,
        )
    }

    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(mut payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            panic!("Expected gadget payload for Match-Pair gadget node");
        };
        let union = payload
            .get(UNION_LABEL)
            .unwrap_or_else(|| panic!("Match-Pair gadget missing {}", UNION_LABEL));
        let t = self
            .active_rows
            .lock()
            .expect("lock poisoned")
            .expect("the union's active rows are counted in planning");
        let tracker_rc = union
            .tracked_polys_iter()
            .next()
            .map(|(_, poly)| poly.tracker())
            .expect("the union has committed key columns");
        commit_with_tracker(&tracker_rc, 0, vec![B::F::from(t as u64)])?;
        let activator = tracker_rc
            .borrow_mut()
            .get_or_build_contig_one_poly(union.log_size(), t)?;
        let mut polys = union.tracked_polys();
        polys.insert(arithmetic::ACTIVATOR_FIELD.clone(), activator);
        let union = arithmetic::table::TrackedTable::new_with_side_cols(
            union.schema_ref().cloned(),
            polys,
            union.log_size(),
            union.side_cols(),
        );
        let count = TrackedPoly::new(Either::Right(B::F::from(t as u64)), 0, tracker_rc);
        payload.insert(UNION_LABEL.to_string(), union);
        payload.insert(
            ACTIVE_ROWS_LABEL.to_string(),
            arithmetic::table::TrackedTable::single_column_with_activator(
                active_rows_field(),
                count,
                None,
            ),
        );
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(payload)));
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
        let get = |label: &str| {
            payload
                .get(label)
                .cloned()
                .unwrap_or_else(|| panic!("Match-Pair gadget missing {label}"))
        };
        let (union, left_keys, right_keys) = (get(UNION_LABEL), get(LEFT_LABEL), get(RIGHT_LABEL));
        let key_columns = select_columns_prover(&union, |_| true);
        let mut payloads = vec![(
            &self.sort_gadget,
            vec![
                (contig_sort::TABLE_LABEL, key_columns.clone()),
                (ACTIVE_ROWS_LABEL, get(ACTIVE_ROWS_LABEL)),
            ],
        )];
        payloads.push((
            &self.left_lookup_gadget,
            vec![
                (
                    lookup::INCLUDED_LABEL,
                    select_columns_prover(&left_keys, |_| true),
                ),
                (lookup::SUPER_LABEL, key_columns.clone()),
            ],
        ));
        payloads.push((
            &self.right_lookup_gadget,
            vec![
                (
                    lookup::INCLUDED_LABEL,
                    select_columns_prover(&right_keys, |_| true),
                ),
                (lookup::SUPER_LABEL, key_columns),
            ],
        ));
        for (gadget, tables) in payloads {
            let mut child_payload = match virtualized_ir.payload_for_node(&gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            for (label, table) in tables {
                child_payload.insert(label.to_string(), table);
            }
            virtualized_ir.set_payload_for_node(
                gadget.id(),
                Some(PayloadStructure::GadgetPayload(child_payload)),
            );
        }
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
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
        let mut union_fields = key_fields(&left_keys_df, &key_names);
        union_fields.push((**arithmetic::ROW_ID_FIELD).clone());
        union_fields.push((**arithmetic::ACTIVATOR_FIELD).clone());
        let union_df = crate::irs::nodes::hints::schema_only_df(union_fields);
        let left_lookup_hint =
            strip_row_id_keep_activator_schema_only(&HintDF::new_virtual(left_keys_df));
        let right_lookup_hint =
            strip_row_id_keep_activator_schema_only(&HintDF::new_virtual(right_keys_df));

        apply_match_pair_planned_hints(
            self,
            id,
            planned_ir,
            union_runtime_hint(union_df),
            left_lookup_hint,
            right_lookup_hint,
        )
    }

    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(mut payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };
        let union = payload
            .get(UNION_LABEL)
            .unwrap_or_else(|| panic!("Match-Pair gadget missing {}", UNION_LABEL));
        let tracker_rc = union
            .tracked_oracles_iter()
            .next()
            .map(|(_, oracle)| oracle.tracker())
            .expect("the union has committed key columns");
        let count = track_next_committed(&tracker_rc)?;
        let t = match count.as_constant() {
            Some(value) if count.log_size() == 0 => {
                field_to_usize(value, "the match-pair union's active rows")?
            }
            _ => {
                return Err(SnarkError::VerifierError(
                    VerifierError::VerifierCheckFailed(
                        "the match-pair union's active-row count is not a committed scalar"
                            .to_string(),
                    ),
                ));
            }
        };
        let activator = tracker_rc
            .borrow_mut()
            .get_or_build_contig_one_poly(union.log_size(), t)?;
        let mut oracles = union.tracked_oracles();
        oracles.insert(arithmetic::ACTIVATOR_FIELD.clone(), activator);
        let union = arithmetic::table_oracle::TrackedTableOracle::new_with_side_cols(
            union.schema_ref().cloned(),
            oracles,
            union.log_size(),
            union.side_cols(),
        );
        payload.insert(UNION_LABEL.to_string(), union);
        payload.insert(
            ACTIVE_ROWS_LABEL.to_string(),
            arithmetic::table_oracle::TrackedTableOracle::single_column_with_activator(
                active_rows_field(),
                count,
                None,
            ),
        );
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(payload)));
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
        let get = |label: &str| {
            payload
                .get(label)
                .cloned()
                .unwrap_or_else(|| panic!("Match-Pair gadget missing {label}"))
        };
        let (union, left_keys, right_keys) = (get(UNION_LABEL), get(LEFT_LABEL), get(RIGHT_LABEL));
        let key_columns = select_columns_verifier(&union, |_| true);
        let mut payloads = vec![(
            &self.sort_gadget,
            vec![
                (contig_sort::TABLE_LABEL, key_columns.clone()),
                (ACTIVE_ROWS_LABEL, get(ACTIVE_ROWS_LABEL)),
            ],
        )];
        payloads.push((
            &self.left_lookup_gadget,
            vec![
                (
                    lookup::INCLUDED_LABEL,
                    select_columns_verifier(&left_keys, |_| true),
                ),
                (lookup::SUPER_LABEL, key_columns.clone()),
            ],
        ));
        payloads.push((
            &self.right_lookup_gadget,
            vec![
                (
                    lookup::INCLUDED_LABEL,
                    select_columns_verifier(&right_keys, |_| true),
                ),
                (lookup::SUPER_LABEL, key_columns),
            ],
        ));
        for (gadget, tables) in payloads {
            let mut child_payload = match virtualized_ir.payload_for_node(&gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            for (label, table) in tables {
                child_payload.insert(label.to_string(), table);
            }
            virtualized_ir.set_payload_for_node(
                gadget.id(),
                Some(PayloadStructure::GadgetPayload(child_payload)),
            );
        }
        Ok(())
    }
}

/// The key fields named `key_names`, in that order.
fn key_fields(keys_df: &DataFrame, key_names: &[String]) -> Vec<Field> {
    key_names
        .iter()
        .filter_map(|name| {
            keys_df
                .schema()
                .fields()
                .iter()
                .find(|field| field.name() == name)
                .map(|field| field.as_ref().clone())
        })
        .collect()
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

        let union_activator = union_table
            .activator_tracked_poly()
            .expect("Match-Pair union table missing activator");
        let left_multiplicities =
            lookup_multiplicities_table_prover(gadget_ready_ir, &self.left_lookup_gadget);
        let right_multiplicities =
            lookup_multiplicities_table_prover(gadget_ready_ir, &self.right_lookup_gadget);
        let output_activator = output_table
            .activator_tracked_poly()
            .expect("Match-Pair output table missing activator");
        let left_mult = single_data_poly_from_table(&left_multiplicities, "left multiplicity");
        let right_mult = single_data_poly_from_table(&right_multiplicities, "right multiplicity");
        let union_left = &union_activator * &(&left_mult * &right_mult);

        // The pair count is committed, so it is in the transcript, and claimed
        // for both sums: over the output it can only be `s`.
        let pairs = output_activator
            .evaluations()
            .into_iter()
            .fold(B::F::zero(), |acc, val| acc + val);
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(0, vec![pairs]))?;
        prover.add_mv_sumcheck_claim(union_left.id(), pairs)?;
        prover.add_mv_sumcheck_claim(output_activator.id(), pairs)?;
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
        // Σ over keys of (left count · right count) must equal the number of
        // active output rows.
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

        let union_activator = union_table
            .activator_tracked_poly()
            .expect("Match-Pair union table missing activator");
        let left_multiplicities =
            lookup_multiplicities_table_verifier(gadget_ready_ir, &self.left_lookup_gadget);
        let right_multiplicities =
            lookup_multiplicities_table_verifier(gadget_ready_ir, &self.right_lookup_gadget);

        let left_mult = single_data_oracle_from_table(&left_multiplicities, "left multiplicity");
        let right_mult = single_data_oracle_from_table(&right_multiplicities, "right multiplicity");

        let union_left = &union_activator * &(&left_mult * &right_mult);

        let output_activator = output_table
            .activator_tracked_poly()
            .expect("Match-Pair output table missing activator");
        let count = verifier.track_next_mv_com()?;
        let pairs = match count.as_constant() {
            Some(value) if count.log_size() == 0 => value,
            _ => {
                return Err(SnarkError::VerifierError(
                    VerifierError::VerifierCheckFailed(
                        "the Match-Pair count is not a committed scalar".to_string(),
                    ),
                ));
            }
        };
        verifier.add_mv_sumcheck_claim(union_left.id(), pairs);
        verifier.add_mv_sumcheck_claim(output_activator.id(), pairs);
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
        let sort_gadget = Arc::new(Node::<B>::Gadget(Arc::new(contig_sort::GadgetNode::new(
            contig_sort::SortConfig::Distinct,
        ))));
        let left_lookup_gadget = Arc::new(Node::<B>::Gadget(Arc::new(lookup::GadgetNode::new())));
        let right_lookup_gadget = Arc::new(Node::<B>::Gadget(Arc::new(lookup::GadgetNode::new())));
        Self {
            sort_gadget,
            left_lookup_gadget,
            right_lookup_gadget,
            active_rows: Mutex::new(None),
        }
    }
}

/// `table`'s columns that `keep` selects, without the row id, with the
/// activator.
fn select_columns_prover<B: SnarkBackend>(
    table: &arithmetic::table::TrackedTable<B>,
    keep: impl Fn(&str) -> bool,
) -> arithmetic::table::TrackedTable<B> {
    let polys: IndexMap<_, _> = table
        .tracked_polys()
        .into_iter()
        .filter(|(field, _)| {
            field.name() == arithmetic::ACTIVATOR_COL_NAME
                || (field.name() != arithmetic::ROW_ID_COL_NAME && keep(field.name()))
        })
        .collect();
    let schema = table.schema_ref().map(|schema| {
        let fields: Vec<Field> = polys.keys().map(|field| field.as_ref().clone()).collect();
        Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    arithmetic::table::TrackedTable::new(schema, polys, table.log_size())
}

fn select_columns_verifier<B: SnarkBackend>(
    table: &arithmetic::table_oracle::TrackedTableOracle<B>,
    keep: impl Fn(&str) -> bool,
) -> arithmetic::table_oracle::TrackedTableOracle<B> {
    let oracles: IndexMap<_, _> = table
        .tracked_oracles()
        .into_iter()
        .filter(|(field, _)| {
            field.name() == arithmetic::ACTIVATOR_COL_NAME
                || (field.name() != arithmetic::ROW_ID_COL_NAME && keep(field.name()))
        })
        .collect();
    let schema = table.schema_ref().map(|schema| {
        let fields: Vec<Field> = oracles.keys().map(|field| field.as_ref().clone()).collect();
        Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    arithmetic::table_oracle::TrackedTableOracle::new(schema, oracles, table.log_size())
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
    union_hint: HintDF,
    left_lookup_hint: HintDF,
    right_lookup_hint: HintDF,
) -> ark_piop::errors::SnarkResult<()> {
    // The lookups count multiplicities against `û` in its row-id order.
    let super_hint = HintDF::new_virtual(
        sort_by_row_id_if_present(union_hint.data_frame().clone())
            .map_err(|e| SnarkError::Artifact(format!("match-pair hints: {e}")))?,
    );
    let mut set = |gadget_id, entries: Vec<(&str, HintDF)>| {
        let mut payload = match planned_ir.payload_for_node(&gadget_id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        for (label, hint) in entries {
            payload.insert(label.to_string(), hint);
        }
        planned_ir.set_payload_for_node(gadget_id, Some(PayloadStructure::GadgetPayload(payload)));
    };
    set(
        node.sort_gadget.id(),
        vec![(contig_sort::TABLE_LABEL, union_hint.as_virtual_view())],
    );
    set(id, vec![(UNION_LABEL, union_hint)]);
    set(
        node.left_lookup_gadget.id(),
        vec![
            (lookup::INCLUDED_LABEL, left_lookup_hint),
            (lookup::SUPER_LABEL, super_hint.clone()),
        ],
    );
    set(
        node.right_lookup_gadget.id(),
        vec![
            (lookup::INCLUDED_LABEL, right_lookup_hint),
            (lookup::SUPER_LABEL, super_hint),
        ],
    );
    Ok(())
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
        // A deterministic alias that cannot clash between the two sides.
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
