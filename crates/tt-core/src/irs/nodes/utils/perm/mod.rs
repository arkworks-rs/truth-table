use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_FIELD, is_system_column, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_ff::One;
use ark_piop::{
    SnarkBackend, prover::structs::polynomial::TrackedPoly,
    verifier::structs::oracle::TrackedOracle,
};
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use either::Either;
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{
            IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps, utils::keyed_sumcheck,
        },
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};
#[cfg(test)]
mod tests;

pub const LEFT_LABEL: &str = "__left__";
pub const RIGHT_LABEL: &str = "__right__";
pub struct GadgetNode<B: SnarkBackend> {
    keyed_sumcheck: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Permutation".to_string()
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
        vec![self.keyed_sumcheck.clone()]
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
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = virtualized_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for Permutation gadget");
        };

        let left = payload
            .get(LEFT_LABEL)
            .unwrap_or_else(|| panic!("Permutation gadget missing {}", LEFT_LABEL));
        let right = payload
            .get(RIGHT_LABEL)
            .unwrap_or_else(|| panic!("Permutation gadget missing {}", RIGHT_LABEL));

        let shared_names = shared_data_field_names(left, right);
        let (fxs, gxs) = if should_fold_by_names(
            left.num_data_tracked_cols(),
            right.num_data_tracked_cols(),
            &shared_names,
        ) {
            assert!(
                !shared_names.is_empty(),
                "Permutation perm: divergent column counts (LEFT={}, RIGHT={}) with no shared column names — nothing to fold",
                left.num_data_tracked_cols(),
                right.num_data_tracked_cols(),
            );
            (
                fold_table_by_names::<B>(left, &shared_names, keyed_sumcheck::FXS_LABEL),
                fold_table_by_names::<B>(right, &shared_names, keyed_sumcheck::GXS_LABEL),
            )
        } else {
            (
                fold_table_to_single_col::<B>(left, keyed_sumcheck::FXS_LABEL),
                fold_table_to_single_col::<B>(right, keyed_sumcheck::GXS_LABEL),
            )
        };
        let mfxs = constant_one_table::<B>(&fxs, keyed_sumcheck::MFXS_LABEL);
        let mgxs = constant_one_table::<B>(&gxs, keyed_sumcheck::MGXS_LABEL);

        let mut keyed_payload = match virtualized_ir.payload_for_node(&self.keyed_sumcheck.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        keyed_payload.insert(keyed_sumcheck::FXS_LABEL.to_string(), fxs);
        keyed_payload.insert(keyed_sumcheck::GXS_LABEL.to_string(), gxs);
        keyed_payload.insert(keyed_sumcheck::MFXS_LABEL.to_string(), mfxs);
        keyed_payload.insert(keyed_sumcheck::MGXS_LABEL.to_string(), mgxs);
        virtualized_ir.set_payload_for_node(
            self.keyed_sumcheck.id(),
            Some(PayloadStructure::GadgetPayload(keyed_payload)),
        );
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
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
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = virtualized_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for Permutation gadget");
        };

        let left = payload
            .get(LEFT_LABEL)
            .unwrap_or_else(|| panic!("Permutation gadget missing {}", LEFT_LABEL));
        let right = payload
            .get(RIGHT_LABEL)
            .unwrap_or_else(|| panic!("Permutation gadget missing {}", RIGHT_LABEL));

        let shared_names = shared_oracle_data_field_names(left, right);
        let (fxs, gxs) = if should_fold_by_names(
            left.num_data_tracked_col_oracles(),
            right.num_data_tracked_col_oracles(),
            &shared_names,
        ) {
            assert!(
                !shared_names.is_empty(),
                "Permutation perm: divergent column counts (LEFT={}, RIGHT={}) with no shared column names — nothing to fold",
                left.num_data_tracked_col_oracles(),
                right.num_data_tracked_col_oracles(),
            );
            (
                fold_table_oracle_by_names::<B>(left, &shared_names, keyed_sumcheck::FXS_LABEL),
                fold_table_oracle_by_names::<B>(right, &shared_names, keyed_sumcheck::GXS_LABEL),
            )
        } else {
            (
                fold_table_oracle_to_single_col::<B>(left, keyed_sumcheck::FXS_LABEL),
                fold_table_oracle_to_single_col::<B>(right, keyed_sumcheck::GXS_LABEL),
            )
        };
        let mfxs = constant_one_table_oracle::<B>(&fxs, keyed_sumcheck::MFXS_LABEL);
        let mgxs = constant_one_table_oracle::<B>(&gxs, keyed_sumcheck::MGXS_LABEL);

        let mut keyed_payload = match virtualized_ir.payload_for_node(&self.keyed_sumcheck.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        keyed_payload.insert(keyed_sumcheck::FXS_LABEL.to_string(), fxs);
        keyed_payload.insert(keyed_sumcheck::GXS_LABEL.to_string(), gxs);
        keyed_payload.insert(keyed_sumcheck::MFXS_LABEL.to_string(), mfxs);
        keyed_payload.insert(keyed_sumcheck::MGXS_LABEL.to_string(), mgxs);
        virtualized_ir.set_payload_for_node(
            self.keyed_sumcheck.id(),
            Some(PayloadStructure::GadgetPayload(keyed_payload)),
        );
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
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
        let left = payload
            .get(LEFT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Permutation gadget missing {}", LEFT_LABEL));
        let right = payload
            .get(RIGHT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Permutation gadget missing {}", RIGHT_LABEL));

        // Key rows in whichever column order the fold will use, else a
        // legitimately-reordered side reads as a different multiset.
        let shared_names = shared_data_field_names(&left, &right);
        let names = should_fold_by_names(
            left.num_data_tracked_cols(),
            right.num_data_tracked_cols(),
            &shared_names,
        )
        .then_some(shared_names.as_slice());
        let left_counts = active_row_multiset::<B>(&left, names);
        let right_counts = active_row_multiset::<B>(&right, names);
        if left_counts == right_counts {
            return Ok(());
        }
        Err(ark_piop::errors::SnarkError::ProverError(
            ark_piop::prover::errors::ProverError::HonestProverError(
                ark_piop::prover::errors::HonestProverError::FalseClaim,
            ),
        ))
    }

    fn verify(
        &self,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
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
    pub fn new() -> Self
    where
        Self: Sized,
    {
        let keyed_sumcheck = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::utils::keyed_sumcheck::GadgetNode::new(),
        )));
        Self { keyed_sumcheck }
    }
}

/// Whether the two perm sides must be folded over `shared_names`
/// instead of positionally.
///
/// Positional folding pairs challenge `k` with each side's `k`-th data
/// column, so it is only valid when the sides agree column-for-column
/// by position. Two situations break that:
///
/// - divergent column counts — one side carries arithmetization
///   segments the other dropped;
/// - equal counts but different flat orders — e.g. a group-by output
///   lists its key columns first while its input lists them after the
///   aggregates. `align_table_to_reference_order` is meant to reconcile
///   this, but `tracked_subtable_by_indices` rebuilds the table in its
///   own `tracked_cols` order, so the reordering does not survive.
///
/// Both are handled by folding each side over the same *names*.
/// Positional folding is kept for equal counts whose names do not
/// correspond — the LIKE path, where the sides use different labels for
/// positionally-equivalent columns and a name intersection would be
/// empty or partial. Duplicate names also fall back, since
/// `fold_table_by_names` resolves a name to its first match and would
/// otherwise fold one column twice.
fn should_fold_by_names(left_count: usize, right_count: usize, shared_names: &[String]) -> bool {
    if left_count != right_count {
        return true;
    }
    let mut seen = std::collections::HashSet::with_capacity(shared_names.len());
    shared_names.len() == left_count && shared_names.iter().all(|n| seen.insert(n))
}

fn folding_challenges<F: ark_ff::PrimeField>(count: usize) -> Vec<F> {
    (0..count).map(|i| F::from((i + 1) as u64)).collect()
}

fn folded_field_from_schema(schema: Option<&Schema>, label: &str) -> FieldRef {
    if let Some(schema) = schema
        && let Some(field) = schema.fields().iter().find(|f| !is_system_column(f.name()))
    {
        return Arc::new(Field::new(
            label,
            field.data_type().clone(),
            field.is_nullable(),
        ));
    }
    Arc::new(Field::new(label, DataType::UInt64, false))
}

/// Original positional per-side fold — folds `table`'s data columns
/// with `[1..num_data_self]`. Preserved for the equal-count branch of
/// `initialize_gadgets` where both sides carry the same number of data
/// columns and positional alignment already yields comparable folds.
fn fold_table_to_single_col<B: SnarkBackend>(
    table: &TrackedTable<B>,
    label: &str,
) -> TrackedTable<B> {
    let num_data = table.num_data_tracked_cols();
    let challenges = folding_challenges::<B::F>(num_data);
    let folded_col = table.fold_all_data_columns(&challenges);

    let data_field = folded_field_from_schema(table.schema_ref(), label);
    let mut fields = vec![data_field.as_ref().clone()];
    let mut tracked_polys = IndexMap::new();
    tracked_polys.insert(data_field, folded_col.data_tracked_poly());

    if let Some(activator) = table.activator_tracked_poly() {
        fields.push(ACTIVATOR_FIELD.as_ref().clone());
        tracked_polys.insert(ACTIVATOR_FIELD.clone(), activator);
    }

    TrackedTable::new(Some(Schema::new(fields)), tracked_polys, table.log_size())
}

/// Verifier mirror of `fold_table_to_single_col`.
fn fold_table_oracle_to_single_col<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    label: &str,
) -> TrackedTableOracle<B> {
    let num_data = table.num_data_tracked_col_oracles();
    let challenges = folding_challenges::<B::F>(num_data);
    let folded_col = table.fold_all_data_oracles(&challenges);

    let data_field = folded_field_from_schema(table.schema_ref(), label);
    let mut fields = vec![data_field.as_ref().clone()];
    let mut tracked_oracles = IndexMap::new();
    tracked_oracles.insert(data_field, folded_col.data_tracked_oracle());

    if let Some(activator) = table.activator_tracked_poly() {
        fields.push(ACTIVATOR_FIELD.as_ref().clone());
        tracked_oracles.insert(ACTIVATOR_FIELD.clone(), activator);
    }

    TrackedTableOracle::new(Some(Schema::new(fields)), tracked_oracles, table.log_size())
}

/// Compute the intersection of data-column names between LEFT and
/// RIGHT, ordered by RIGHT's tracked_polys flat-view order. RIGHT is
/// treated as the reference because for the rematerialize permutation
/// it is always a (non-strict) subset of LEFT — the compacted output's
/// tracked columns are a subset of the filter's input's tracked columns.
///
/// Returns an empty vector when RIGHT has no data columns (would be a
/// degenerate perm anyway). If RIGHT names a column that LEFT does not
/// carry (defensive, shouldn't happen for rematerialize), that name is
/// silently dropped — the resulting fold still gives comparable
/// multisets over the columns both sides do share.
fn shared_data_field_names<B: SnarkBackend>(
    left: &TrackedTable<B>,
    right: &TrackedTable<B>,
) -> Vec<String> {
    let left_names: std::collections::HashSet<String> = left
        .tracked_polys()
        .keys()
        .filter(|f| !is_system_column(f.name()))
        .map(|f| f.name().to_string())
        .collect();
    right
        .tracked_polys()
        .keys()
        .filter(|f| !is_system_column(f.name()))
        .filter(|f| left_names.contains(f.name()))
        .map(|f| f.name().to_string())
        .collect()
}

fn shared_oracle_data_field_names<B: SnarkBackend>(
    left: &TrackedTableOracle<B>,
    right: &TrackedTableOracle<B>,
) -> Vec<String> {
    let left_names: std::collections::HashSet<String> = left
        .tracked_oracles()
        .keys()
        .filter(|f| !is_system_column(f.name()))
        .map(|f| f.name().to_string())
        .collect();
    right
        .tracked_oracles()
        .keys()
        .filter(|f| !is_system_column(f.name()))
        .filter(|f| left_names.contains(f.name()))
        .map(|f| f.name().to_string())
        .collect()
}

/// Fold `table`'s data columns whose names appear in `names` (in
/// `names` order) with challenges `[1..=names.len()]`. Both LEFT and
/// RIGHT sides of the permutation use the same `names` slice so the
/// resulting folded polys are structurally comparable.
fn fold_table_by_names<B: SnarkBackend>(
    table: &TrackedTable<B>,
    names: &[String],
    label: &str,
) -> TrackedTable<B> {
    // Resolve `names` → flat-view indices in this side's tracked_polys.
    let flat = table.tracked_polys();
    let indices: Vec<usize> = names
        .iter()
        .filter_map(|n| {
            flat.keys()
                .enumerate()
                .find(|(_, f)| f.name() == n)
                .map(|(i, _)| i)
        })
        .collect();
    assert_eq!(
        indices.len(),
        names.len(),
        "fold_table_by_names: perm side missing shared column(s) — LEFT/RIGHT diverged unexpectedly"
    );
    let challenges = folding_challenges::<B::F>(indices.len());
    let folded_col = table.fold(&indices, &challenges);

    let data_field = folded_field_from_schema(table.schema_ref(), label);
    let mut fields = vec![data_field.as_ref().clone()];
    let mut tracked_polys = IndexMap::new();
    tracked_polys.insert(data_field, folded_col.data_tracked_poly());

    if let Some(activator) = table.activator_tracked_poly() {
        fields.push(ACTIVATOR_FIELD.as_ref().clone());
        tracked_polys.insert(ACTIVATOR_FIELD.clone(), activator);
    }

    TrackedTable::new(Some(Schema::new(fields)), tracked_polys, table.log_size())
}

/// Verifier mirror of `fold_table_by_names`. Same rationale: fold both
/// sides over the intersection of data-column names with matching
/// challenges so the folded oracles are structurally comparable at the
/// keyed-sumcheck stage.
fn fold_table_oracle_by_names<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    names: &[String],
    label: &str,
) -> TrackedTableOracle<B> {
    let flat = table.tracked_oracles();
    let indices: Vec<usize> = names
        .iter()
        .filter_map(|n| {
            flat.keys()
                .enumerate()
                .find(|(_, f)| f.name() == n)
                .map(|(i, _)| i)
        })
        .collect();
    assert_eq!(
        indices.len(),
        names.len(),
        "fold_table_oracle_by_names: perm side missing shared column(s) — LEFT/RIGHT diverged unexpectedly"
    );
    let challenges = folding_challenges::<B::F>(indices.len());
    let folded_col = table.fold(&indices, &challenges);

    let data_field = folded_field_from_schema(table.schema_ref(), label);
    let mut fields = vec![data_field.as_ref().clone()];
    let mut tracked_oracles = IndexMap::new();
    tracked_oracles.insert(data_field, folded_col.data_tracked_oracle());

    if let Some(activator) = table.activator_tracked_poly() {
        fields.push(ACTIVATOR_FIELD.as_ref().clone());
        tracked_oracles.insert(ACTIVATOR_FIELD.clone(), activator);
    }

    TrackedTableOracle::new(Some(Schema::new(fields)), tracked_oracles, table.log_size())
}

fn constant_one_table<B: SnarkBackend>(base: &TrackedTable<B>, label: &str) -> TrackedTable<B> {
    let tracker = base
        .tracked_polys_iter()
        .next()
        .map(|(_, poly)| poly.tracker())
        .expect("Permutation gadget expects a non-empty table");
    let log_size = base.log_size();
    let one_poly = TrackedPoly::new(Either::Right(B::F::one()), log_size, tracker);

    let data_field = folded_field_from_schema(base.schema_ref(), label);
    let mut tracked_polys = IndexMap::new();
    tracked_polys.insert(data_field.clone(), one_poly);
    TrackedTable::new(
        Some(Schema::new(vec![data_field.as_ref().clone()])),
        tracked_polys,
        log_size,
    )
}

fn constant_one_table_oracle<B: SnarkBackend>(
    base: &TrackedTableOracle<B>,
    label: &str,
) -> TrackedTableOracle<B> {
    let tracker = base
        .tracked_oracles_iter()
        .next()
        .map(|(_, oracle)| oracle.tracker())
        .expect("Permutation gadget expects a non-empty oracle table");
    let log_size = base.log_size();
    let one_oracle = TrackedOracle::new(Either::Right(B::F::one()), tracker, log_size);

    let data_field = folded_field_from_schema(base.schema_ref(), label);
    let mut tracked_oracles = IndexMap::new();
    tracked_oracles.insert(data_field.clone(), one_oracle);
    TrackedTableOracle::new(
        Some(Schema::new(vec![data_field.as_ref().clone()])),
        tracked_oracles,
        log_size,
    )
}

/// Multiset of this table's active rows, each row rendered as a string
/// key. When `names` is given, columns are read in that order (and only
/// those columns); otherwise the table's own flat data order is used.
fn active_row_multiset<B: SnarkBackend>(
    table: &TrackedTable<B>,
    names: Option<&[String]>,
) -> std::collections::HashMap<String, usize> {
    let flat = table.tracked_polys();
    let data_indices = match names {
        Some(names) => names
            .iter()
            .map(|n| {
                flat.keys()
                    .position(|f| f.name() == n)
                    .expect("active_row_multiset: perm side missing shared column")
            })
            .collect(),
        None => table.data_tracked_polys_indices(),
    };
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
