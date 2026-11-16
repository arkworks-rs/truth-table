//! Membership gadget for `x [NOT] IN (v1, .., vk)` over a long list of
//! literals, at a cost that does not grow with `k`. `S` is the list without
//! repeats, which the verifier holds.
//!
//! 1. The prover sends `û`, the distinct values of `S` and of `x` on the
//!    active rows, sorted (`û.act := C_{µ,t}` public, `t` committed), and a
//!    flag `e` on `û`.
//! 2. A StrictSortcheck (the sort check's distinct mode) proves `û` distinct.
//! 3. `e·(e − û.act) = 0`: `e` is boolean and 0 off the active rows of `û`.
//! 4. `Σ e/(û − γ) = Σ_{s∈S} 1/(s − γ)`, the right side summed by the
//!    verifier: the rows `e` flags are `S`, and `û` is distinct, so `e` is
//!    `û ∈ S`.
//! 5. A lookup of `(x, m)` on the active rows into `(û, e)` on the active
//!    rows of `û`, with `m` the rows where `x` is in the list (`b`, or
//!    `act − b` for `NOT IN`): `û` is distinct, so `m` is `x ∈ S`, and `b` is
//!    boolean.
//! 6. `(act − 1)·b = 0`: `b` is 0 on inactive rows.
//!
//! A value of several segments (a string's hash and length) is folded with
//! challenges drawn after `û` is committed.

use std::sync::{Arc, Mutex};

use arithmetic::{
    ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, ROW_ID_COL_NAME, encoding::is_rank_segment,
    is_system_column, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_ff::{One, Zero};
use ark_piop::{
    SnarkBackend,
    errors::{SnarkError, SnarkResult},
    piop::keyed_sumcheck::{KeyedSumcheckProverInput, KeyedSumcheckVerifierInput},
    prover::{
        ArgProver,
        errors::{HonestProverError, ProverError},
        structs::polynomial::TrackedPoly,
    },
    verifier::{ArgVerifier, errors::VerifierError, structs::oracle::TrackedOracle},
};
use datafusion::arrow::{
    array::{ArrayRef, BooleanArray, Int64Array},
    compute::cast,
    datatypes::{DataType, Field, FieldRef, Schema},
    record_batch::RecordBatch,
};
use datafusion::prelude::DataFrame;
use datafusion_common::ScalarValue;
use datafusion_expr::{col, lit};
use either::Either;
use indexmap::IndexMap;

use crate::irs::nodes::hints::{HintDF, schema_only_df, sort_by_row_id_if_present};
use crate::irs::nodes::utils::contig_sort::{self, ACTIVE_ROWS_LABEL, active_rows_field};
use crate::irs::nodes::utils::match_pair_check::{build_union_hint_df, union_runtime_hint};
use crate::irs::nodes::utils::{commit_with_tracker, field_to_usize, lookup, track_next_committed};
use crate::irs::nodes::{IsGadgetNode, IsNode, Node, NodeId, ProverNodeOps, VerifierNodeOps};
use crate::irs::payloads::PayloadStructure;
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;

use super::gadget::{INPUT_LABEL, OUTPUT_LABEL, check_result};

#[cfg(test)]
mod tests;

/// The plan-time values of `x` and whether each is in `S`: [`KEY_COL`],
/// [`MEMBER_COL`], the row id and the activator.
pub const KEYS_LABEL: &str = "__in_list_keys__";
/// `û` and `e`: [`KEY_COL`], [`FLAG_COL`], the row id and the activator.
pub const UNION_LABEL: &str = "__in_list_union__";
pub const KEY_COL: &str = "__in_list_key__";
pub const MEMBER_COL: &str = "__in_list_member__";
pub const FLAG_COL: &str = "__in_list_flag__";
const LIST_STATEMENT: &[u8] = b"in_list_values";

pub struct LongListNode<B: SnarkBackend> {
    list: Vec<ScalarValue>,
    /// The row-domain segments of each value of `S`.
    values: Vec<Vec<B::F>>,
    negated: bool,
    sort_gadget: Arc<Node<B>>,
    lookup_gadget: Arc<Node<B>>,
    /// The prover's `t`, counted in planning.
    active_rows: Mutex<Option<usize>>,
}

impl<B: SnarkBackend> LongListNode<B> {
    /// `list` holds no value twice.
    pub fn new(list: Vec<ScalarValue>, negated: bool) -> Self {
        assert!(!list.is_empty(), "an IN list needs at least one value");
        Self {
            values: super::gadget::value_segments(&list),
            list,
            negated,
            sort_gadget: Arc::new(Node::Gadget(Arc::new(contig_sort::GadgetNode::new(
                contig_sort::SortConfig::Distinct,
            )))),
            lookup_gadget: Arc::new(Node::Gadget(Arc::new(lookup::GadgetNode::new()))),
            active_rows: Mutex::new(None),
        }
    }

    /// `S` as a table of [`KEY_COL`] of `key_type`, every row active.
    fn list_df(&self, key_type: &DataType) -> datafusion_common::Result<DataFrame> {
        let values = ScalarValue::iter_to_array(self.list.iter().cloned())?;
        let values: ArrayRef = cast(&values, key_type)?;
        let rows = self.list.len();
        let schema = Arc::new(Schema::new(vec![
            Field::new(KEY_COL, key_type.clone(), true),
            Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
            ACTIVATOR_FIELD.as_ref().clone(),
        ]));
        let batch = RecordBatch::try_new(
            schema,
            vec![
                values,
                Arc::new(Int64Array::from_iter_values(0..rows as i64)),
                Arc::new(BooleanArray::from(vec![true; rows])),
            ],
        )?;
        crate::session::session_context().read_batch(batch)
    }

    /// Each value of `S` folded as `û` is: `segments[0] + Σ c_i·segments[i + 1]`.
    fn list_keys(&self, challenges: &[B::F]) -> Arc<[B::F]> {
        self.values
            .iter()
            .map(|segments| {
                segments[1..]
                    .iter()
                    .zip(challenges)
                    .fold(segments[0], |acc, (value, c)| acc + *value * c)
            })
            .collect()
    }

    fn list_digest(&self) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        for segments in &self.values {
            for value in segments {
                hasher.update(value.to_string().as_bytes());
                hasher.update(b",");
            }
            hasher.update(b";");
        }
        hasher.update(&[u8::from(self.negated)]);
        hasher.finalize().as_bytes().to_vec()
    }

    /// The gadget payloads of the sort and the lookup, from the plan-time
    /// `û` and `x`.
    fn set_planned_hints(
        &self,
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
        union_df: DataFrame,
        keys_df: DataFrame,
    ) -> SnarkResult<()> {
        let hint_err = |e: datafusion_common::DataFusionError| {
            SnarkError::Artifact(format!("IN list union hints: {e}"))
        };
        let union_keys = union_df
            .clone()
            .select(vec![
                col(KEY_COL),
                col(ROW_ID_COL_NAME),
                col(ACTIVATOR_COL_NAME),
            ])
            .map_err(hint_err)?;
        let super_df = sort_by_row_id_if_present(union_df.clone()).map_err(hint_err)?;
        let mut set = |gadget_id, entries: Vec<(&str, HintDF)>| {
            let mut payload = match planned_ir.payload_for_node(&gadget_id) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            for (label, hint) in entries {
                payload.insert(label.to_string(), hint);
            }
            planned_ir
                .set_payload_for_node(gadget_id, Some(PayloadStructure::GadgetPayload(payload)));
        };
        set(
            self.sort_gadget.id(),
            vec![(contig_sort::TABLE_LABEL, HintDF::new_virtual(union_keys))],
        );
        set(
            self.lookup_gadget.id(),
            vec![
                (
                    lookup::INCLUDED_LABEL,
                    crate::irs::nodes::hints::strip_row_id_from_hint(&HintDF::new_virtual(keys_df)),
                ),
                (lookup::SUPER_LABEL, HintDF::new_virtual(super_df)),
            ],
        );
        set(id, vec![(UNION_LABEL, union_runtime_hint(union_df))]);
        Ok(())
    }

    fn take_keys_hint(
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> HintDF {
        let Some(PayloadStructure::GadgetPayload(mut payload)) =
            planned_ir.payload_for_node(&id).cloned()
        else {
            panic!("the IN list hands its keys to the long-list gadget");
        };
        let keys = payload
            .shift_remove(KEYS_LABEL)
            .expect("the IN list hands its keys to the long-list gadget");
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(payload)));
        keys
    }

    fn key_type(keys: &HintDF) -> DataType {
        keys.data_frame()
            .schema()
            .field_with_unqualified_name(KEY_COL)
            .expect("the keys hint has the key column")
            .data_type()
            .clone()
    }
}

fn is_key_segment(name: &str) -> bool {
    !is_system_column(name) && !is_rank_segment(name) && name != FLAG_COL
}

impl<B: SnarkBackend> IsNode<B> for LongListNode<B> {
    fn name(&self) -> String {
        "InList Union Membership".to_string()
    }

    fn display(&self) -> String {
        let name = format!("{}\nValues: {}", self.name(), self.list.len());
        crate::irs::nodes::display_with_inputs(&name, &self.children())
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        vec![self.sort_gadget.clone(), self.lookup_gadget.clone()]
    }
}

/// The tables of the sort and the lookup, from the gadget's payload:
/// `(û, t)` for the sort, `(x, m)` and `(û, e)` for the lookup.
struct ChildTables<T> {
    union_keys: T,
    active_rows: T,
    included: T,
    super_table: T,
}

impl<B: SnarkBackend> LongListNode<B> {
    fn prover_child_tables(
        &self,
        payload: &IndexMap<String, TrackedTable<B>>,
    ) -> SnarkResult<ChildTables<TrackedTable<B>>> {
        let get = |label: &str| {
            payload
                .get(label)
                .cloned()
                .unwrap_or_else(|| panic!("the long-list gadget expects {label}"))
        };
        let (input, output, union) = (get(INPUT_LABEL), get(OUTPUT_LABEL), get(UNION_LABEL));
        let act = input.activator_tracked_poly();
        let b = output
            .tracked_col_by_ind(output.data_tracked_polys_indices()[0])
            .data_tracked_poly();
        let member = match (self.negated, &act) {
            (false, _) => b,
            (true, Some(act)) => act - &b,
            (true, None) => b.mul_scalar_poly(-B::F::one()).add_scalar_poly(B::F::one()),
        };
        let mut included: IndexMap<FieldRef, TrackedPoly<B>> = input
            .tracked_polys_iter()
            .filter(|(field, _)| is_key_segment(field.name()))
            .map(|(field, poly)| (field.clone(), poly.clone()))
            .collect();
        included.insert(member_field(), member);
        if let Some(act) = act {
            included.insert(ACTIVATOR_FIELD.clone(), act);
        }
        let mut union_keys = select(&union.tracked_polys(), is_key_segment);
        let mut super_polys = union_keys.clone();
        super_polys.extend(select(&union.tracked_polys(), |name| name == FLAG_COL));
        let union_act = union
            .activator_tracked_poly()
            .expect("û has its public activator");
        union_keys.insert(ACTIVATOR_FIELD.clone(), union_act.clone());
        super_polys.insert(ACTIVATOR_FIELD.clone(), union_act);
        if included.len() != super_polys.len() {
            return Err(column_count_mismatch());
        }
        let table = |polys: IndexMap<FieldRef, TrackedPoly<B>>, log_size| {
            let fields: Vec<Field> = polys.keys().map(|f| f.as_ref().clone()).collect();
            TrackedTable::new(Some(Schema::new(fields)), polys, log_size)
        };
        Ok(ChildTables {
            union_keys: table(union_keys, union.log_size()),
            active_rows: get(ACTIVE_ROWS_LABEL),
            included: table(included, input.log_size()),
            super_table: table(super_polys, union.log_size()),
        })
    }

    fn verifier_child_tables(
        &self,
        payload: &IndexMap<String, TrackedTableOracle<B>>,
    ) -> SnarkResult<ChildTables<TrackedTableOracle<B>>> {
        let get = |label: &str| {
            payload
                .get(label)
                .cloned()
                .unwrap_or_else(|| panic!("the long-list gadget expects {label}"))
        };
        let (input, output, union) = (get(INPUT_LABEL), get(OUTPUT_LABEL), get(UNION_LABEL));
        let act = input.activator_tracked_poly();
        let b = output
            .tracked_col_oracle_by_ind(output.data_tracked_oracles_indices()[0])
            .data_tracked_oracle();
        let member = match (self.negated, &act) {
            (false, _) => b,
            (true, Some(act)) => act - &b,
            (true, None) => b
                .mul_scalar_oracle(-B::F::one())
                .add_scalar_oracle(B::F::one()),
        };
        let mut included: IndexMap<FieldRef, TrackedOracle<B>> = input
            .tracked_oracles_iter()
            .filter(|(field, _)| is_key_segment(field.name()))
            .map(|(field, oracle)| (field.clone(), oracle.clone()))
            .collect();
        included.insert(member_field(), member);
        if let Some(act) = act {
            included.insert(ACTIVATOR_FIELD.clone(), act);
        }
        let mut union_keys = select(&union.tracked_oracles(), is_key_segment);
        let mut super_oracles = union_keys.clone();
        super_oracles.extend(select(&union.tracked_oracles(), |name| name == FLAG_COL));
        let union_act = union
            .activator_tracked_poly()
            .expect("û has its public activator");
        union_keys.insert(ACTIVATOR_FIELD.clone(), union_act.clone());
        super_oracles.insert(ACTIVATOR_FIELD.clone(), union_act);
        if included.len() != super_oracles.len() {
            return Err(column_count_mismatch());
        }
        let table = |oracles: IndexMap<FieldRef, TrackedOracle<B>>, log_size| {
            let fields: Vec<Field> = oracles.keys().map(|f| f.as_ref().clone()).collect();
            TrackedTableOracle::new(Some(Schema::new(fields)), oracles, log_size)
        };
        Ok(ChildTables {
            union_keys: table(union_keys, union.log_size()),
            active_rows: get(ACTIVE_ROWS_LABEL),
            included: table(included, input.log_size()),
            super_table: table(super_oracles, union.log_size()),
        })
    }
}

fn member_field() -> FieldRef {
    Arc::new(Field::new(MEMBER_COL, DataType::Boolean, false))
}

fn select<T: Clone>(
    columns: &IndexMap<FieldRef, T>,
    keep: impl Fn(&str) -> bool,
) -> IndexMap<FieldRef, T> {
    columns
        .iter()
        .filter(|(field, _)| keep(field.name()))
        .map(|(field, column)| (field.clone(), column.clone()))
        .collect()
}

fn column_count_mismatch() -> SnarkError {
    SnarkError::VerifierError(VerifierError::VerifierCheckFailed(
        "IN list values and the tested expression encode to different column counts".to_string(),
    ))
}

impl<B: SnarkBackend> ProverNodeOps<B> for LongListNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        let keys = Self::take_keys_hint(id, planned_ir);
        let hint_err = |e: datafusion_common::DataFusionError| {
            SnarkError::Artifact(format!("IN list union hint: {e}"))
        };
        let keys_df = sort_by_row_id_if_present(keys.data_frame().clone()).map_err(hint_err)?;
        let list_df = self.list_df(&Self::key_type(&keys)).map_err(hint_err)?;
        let x_df = keys_df
            .clone()
            .select(vec![
                col(KEY_COL),
                col(ROW_ID_COL_NAME),
                col(ACTIVATOR_COL_NAME),
            ])
            .map_err(hint_err)?;
        let (union_df, active_rows) =
            build_union_hint_df::<B::F>(list_df, x_df).map_err(hint_err)?;
        *self.active_rows.lock().expect("lock poisoned") = Some(active_rows);
        let in_list = col(KEY_COL).in_list(self.list.iter().cloned().map(lit).collect(), false);
        let union_df = union_df
            .select(vec![
                col(KEY_COL),
                in_list.and(col(ACTIVATOR_COL_NAME)).alias(FLAG_COL),
                col(ROW_ID_COL_NAME),
                col(ACTIVATOR_COL_NAME),
            ])
            .map_err(hint_err)?;
        self.set_planned_hints(id, planned_ir, union_df, keys_df)
    }

    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(mut payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            panic!("Expected gadget payload for the long-list gadget");
        };
        let union = payload
            .get(UNION_LABEL)
            .expect("the long-list gadget has û");
        let t = self
            .active_rows
            .lock()
            .expect("lock poisoned")
            .expect("û's active rows are counted in planning");
        let tracker_rc = union
            .tracked_polys_iter()
            .next()
            .map(|(_, poly)| poly.tracker())
            .expect("û has committed columns");
        commit_with_tracker(&tracker_rc, 0, vec![B::F::from(t as u64)])?;
        let activator = tracker_rc
            .borrow_mut()
            .get_or_build_contig_one_poly(union.log_size(), t)?;
        let mut polys = union.tracked_polys();
        polys.insert(ACTIVATOR_FIELD.clone(), activator);
        let union = TrackedTable::new_with_side_cols(
            union.schema_ref().cloned(),
            polys,
            union.log_size(),
            union.side_cols(),
        );
        let count = TrackedPoly::new(Either::Right(B::F::from(t as u64)), 0, tracker_rc);
        payload.insert(UNION_LABEL.to_string(), union);
        payload.insert(
            ACTIVE_ROWS_LABEL.to_string(),
            TrackedTable::single_column_with_activator(active_rows_field(), count, None),
        );
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(payload)));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        _prover: &mut ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };
        let tables = self.prover_child_tables(&payload)?;
        let children = [
            (
                &self.sort_gadget,
                vec![
                    (contig_sort::TABLE_LABEL, tables.union_keys),
                    (ACTIVE_ROWS_LABEL, tables.active_rows),
                ],
            ),
            (
                &self.lookup_gadget,
                vec![
                    (lookup::INCLUDED_LABEL, tables.included),
                    (lookup::SUPER_LABEL, tables.super_table),
                ],
            ),
        ];
        for (gadget, tables) in children {
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

impl<B: SnarkBackend> VerifierNodeOps<B> for LongListNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        let keys = Self::take_keys_hint(id, planned_ir);
        let union_df = schema_only_df(vec![
            Field::new(KEY_COL, Self::key_type(&keys), true),
            Field::new(FLAG_COL, DataType::Boolean, true),
            Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
            ACTIVATOR_FIELD.as_ref().clone(),
        ]);
        self.set_planned_hints(id, planned_ir, union_df, keys.data_frame().clone())
    }

    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(mut payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };
        let union = payload
            .get(UNION_LABEL)
            .expect("the long-list gadget has û");
        let tracker_rc = union
            .tracked_oracles_iter()
            .next()
            .map(|(_, oracle)| oracle.tracker())
            .expect("û has committed columns");
        let count = track_next_committed(&tracker_rc)?;
        let t = match count.as_constant() {
            Some(value) if count.log_size() == 0 => {
                field_to_usize(value, "the IN list union's active rows")?
            }
            _ => {
                return Err(SnarkError::VerifierError(
                    VerifierError::VerifierCheckFailed(
                        "the IN list union's active-row count is not a committed scalar"
                            .to_string(),
                    ),
                ));
            }
        };
        let activator = tracker_rc
            .borrow_mut()
            .get_or_build_contig_one_poly(union.log_size(), t)?;
        let mut oracles = union.tracked_oracles();
        oracles.insert(ACTIVATOR_FIELD.clone(), activator);
        let union = TrackedTableOracle::new_with_side_cols(
            union.schema_ref().cloned(),
            oracles,
            union.log_size(),
            union.side_cols(),
        );
        payload.insert(UNION_LABEL.to_string(), union);
        payload.insert(
            ACTIVE_ROWS_LABEL.to_string(),
            TrackedTableOracle::single_column_with_activator(active_rows_field(), count, None),
        );
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(payload)));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        _verifier: &mut ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };
        let tables = self.verifier_child_tables(&payload)?;
        let children = [
            (
                &self.sort_gadget,
                vec![
                    (contig_sort::TABLE_LABEL, tables.union_keys),
                    (ACTIVE_ROWS_LABEL, tables.active_rows),
                ],
            ),
            (
                &self.lookup_gadget,
                vec![
                    (lookup::INCLUDED_LABEL, tables.included),
                    (lookup::SUPER_LABEL, tables.super_table),
                ],
            ),
        ];
        for (gadget, tables) in children {
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

impl<B: SnarkBackend> IsGadgetNode<B> for LongListNode<B> {
    fn prove(
        &self,
        prover: &mut ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let get = |label: &str| {
            payload
                .get(label)
                .unwrap_or_else(|| panic!("the long-list gadget expects {label}"))
        };
        let (input, output, union) = (get(INPUT_LABEL), get(OUTPUT_LABEL), get(UNION_LABEL));
        let keys: Vec<TrackedPoly<B>> = union
            .tracked_polys_iter()
            .filter(|(field, _)| is_key_segment(field.name()))
            .map(|(_, poly)| poly.clone())
            .collect();
        let flag = union
            .tracked_polys_iter()
            .find(|(field, _)| field.name() == FLAG_COL)
            .map(|(_, poly)| poly.clone())
            .expect("û carries its flag");
        let union_act = union
            .activator_tracked_poly()
            .expect("û has its public activator");
        let b = output
            .tracked_col_by_ind(output.data_tracked_polys_indices()[0])
            .data_tracked_poly();

        prover.append_statement(LIST_STATEMENT, &self.list_digest())?;
        prover.add_mv_zerocheck_claim((&flag * &(&flag - &union_act)).id())?;

        let mut challenges = Vec::with_capacity(keys.len() - 1);
        for _ in 1..keys.len() {
            challenges.push(prover.get_and_append_challenge(b"in_list_union_fold")?);
        }
        let mut folded = keys[0].clone();
        for (key, c) in keys[1..].iter().zip(&challenges) {
            folded += &key.mul_scalar_poly(*c);
        }
        prover.add_mv_keyed_sum_claim_with_public(
            KeyedSumcheckProverInput {
                fxs: vec![folded],
                mfxs: vec![Some(flag)],
                gxs: Vec::new(),
                mgxs: Vec::new(),
            },
            [Vec::new(), vec![self.list_keys(&challenges)]],
        )?;

        if let Some(act) = input.activator_tracked_poly() {
            let claim = &act.sub_scalar_poly(B::F::one()) * &b;
            match claim.as_constant() {
                None => prover.add_mv_zerocheck_claim(claim.id())?,
                Some(c) if c.is_zero() => {}
                Some(_) => {
                    return Err(SnarkError::ProverError(ProverError::HonestProverError(
                        HonestProverError::FalseClaim,
                    )));
                }
            }
        }
        Ok(())
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let (Some(input), Some(output)) = (payload.get(INPUT_LABEL), payload.get(OUTPUT_LABEL))
        else {
            return Ok(());
        };
        check_result(&self.values, self.negated, input, output)
    }

    fn verify(
        &self,
        verifier: &mut ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let get = |label: &str| {
            payload
                .get(label)
                .unwrap_or_else(|| panic!("the long-list gadget expects {label}"))
        };
        let (input, output, union) = (get(INPUT_LABEL), get(OUTPUT_LABEL), get(UNION_LABEL));
        let keys: Vec<TrackedOracle<B>> = union
            .tracked_oracles_iter()
            .filter(|(field, _)| is_key_segment(field.name()))
            .map(|(_, oracle)| oracle.clone())
            .collect();
        if keys.len() != self.values[0].len() {
            return Err(column_count_mismatch());
        }
        let Some(flag) = union
            .tracked_oracles_iter()
            .find(|(field, _)| field.name() == FLAG_COL)
            .map(|(_, oracle)| oracle.clone())
        else {
            return Err(SnarkError::VerifierError(
                VerifierError::VerifierCheckFailed("the IN list union has no flag".to_string()),
            ));
        };
        let union_act = union
            .activator_tracked_poly()
            .expect("û has its public activator");
        let b = output
            .tracked_col_oracle_by_ind(output.data_tracked_oracles_indices()[0])
            .data_tracked_oracle();

        verifier.append_statement(LIST_STATEMENT, &self.list_digest())?;
        verifier.add_mv_zerocheck_claim((&flag * &(&flag - &union_act)).id());

        let mut challenges = Vec::with_capacity(keys.len() - 1);
        for _ in 1..keys.len() {
            challenges.push(verifier.get_and_append_challenge(b"in_list_union_fold")?);
        }
        let mut folded = keys[0].clone();
        for (key, c) in keys[1..].iter().zip(&challenges) {
            folded += &key.mul_scalar_oracle(*c);
        }
        verifier.add_mv_keyed_sum_claim_with_public(
            KeyedSumcheckVerifierInput {
                fxs: vec![folded],
                mfxs: vec![Some(flag)],
                gxs: Vec::new(),
                mgxs: Vec::new(),
            },
            [Vec::new(), vec![self.list_keys(&challenges)]],
        )?;

        if let Some(act) = input.activator_tracked_poly() {
            let claim = &act.sub_scalar_oracle(B::F::one()) * &b;
            match claim.as_constant() {
                None => verifier.add_mv_zerocheck_claim(claim.id()),
                Some(c) if c.is_zero() => {}
                Some(_) => {
                    return Err(SnarkError::VerifierError(
                        VerifierError::VerifierCheckFailed(
                            "InList: a constant zerocheck is nonzero".to_string(),
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    fn prover_hints(&self) -> IndexMap<String, HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, HintDF> {
        IndexMap::new()
    }
}
