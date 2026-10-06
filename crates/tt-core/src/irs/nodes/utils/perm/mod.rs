use arithmetic::{
    col::TrackedCol, col_oracle::TrackedColOracle, is_system_column, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::One;
use ark_piop::{SnarkBackend, piop::PIOP};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{
            IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps,
            utils::nodup::perm_check::{PermPIOP, PermPIOPProverInput, PermPIOPVerifierInput},
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
const ROW_FOLD_CHALLENGE_LABEL: &[u8] = b"truth-table/perm/row-fold/v1";

/// Proves equality of the active-row multisets over the selected columns.
///
/// Present activators are required to be Boolean; callers establish that
/// separately. Proof witnesses must be committed before proving, while
/// public and virtual inputs must be verifier-fixed or derived from bound data.
pub struct GadgetNode<B: SnarkBackend> {
    _backend: std::marker::PhantomData<B>,
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
        vec![]
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
        _id: crate::irs::nodes::NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
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
        _id: crate::irs::nodes::NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
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
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
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
        let (left_inds, right_inds) = if should_fold_by_names(
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
                indices_by_names(left.tracked_polys().keys(), &shared_names),
                indices_by_names(right.tracked_polys().keys(), &shared_names),
            )
        } else {
            (
                left.data_tracked_polys_indices(),
                right.data_tracked_polys_indices(),
            )
        };
        // The fold must be a random linear combination: with coefficients
        // fixed before the columns are committed, distinct rows can be chosen
        // to fold to the same value. The leading coefficient is one, so a
        // one-column permutation is checked exactly.
        let mut challenges = Vec::with_capacity(left_inds.len());
        challenges.push(B::F::one());
        for _ in 1..left_inds.len() {
            challenges.push(prover.get_and_append_challenge(ROW_FOLD_CHALLENGE_LABEL)?);
        }
        let left_col: TrackedCol<B> = left.fold(&left_inds, &challenges);
        let right_col: TrackedCol<B> = right.fold(&right_inds, &challenges);
        // The honest-prover pass checks this claim through
        // `honest_prover_check`, so skip the PIOP's own copy of that check.
        PermPIOP::<B>::prove_inner(
            prover,
            PermPIOPProverInput {
                left_col,
                right_col,
            },
        )
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
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
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
        let (left_inds, right_inds) = if should_fold_by_names(
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
                indices_by_names(left.tracked_oracles().keys(), &shared_names),
                indices_by_names(right.tracked_oracles().keys(), &shared_names),
            )
        } else {
            (
                left.data_tracked_oracles_indices(),
                right.data_tracked_oracles_indices(),
            )
        };
        // Mirror the prover's challenge draws.
        let mut challenges = Vec::with_capacity(left_inds.len());
        challenges.push(B::F::one());
        for _ in 1..left_inds.len() {
            challenges.push(verifier.get_and_append_challenge(ROW_FOLD_CHALLENGE_LABEL)?);
        }
        let left_tracked_col_oracle: TrackedColOracle<B> = left.fold(&left_inds, &challenges);
        let right_tracked_col_oracle: TrackedColOracle<B> = right.fold(&right_inds, &challenges);
        PermPIOP::<B>::verify(
            verifier,
            PermPIOPVerifierInput {
                left_tracked_col_oracle,
                right_tracked_col_oracle,
            },
        )
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
        Self {
            _backend: std::marker::PhantomData,
        }
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
/// `indices_by_names` resolves a name to its first match and would
/// otherwise fold one column twice.
fn should_fold_by_names(left_count: usize, right_count: usize, shared_names: &[String]) -> bool {
    if left_count != right_count {
        return true;
    }
    let mut seen = std::collections::HashSet::with_capacity(shared_names.len());
    shared_names.len() == left_count && shared_names.iter().all(|n| seen.insert(n))
}

/// Compute the intersection of data-column names between LEFT and
/// RIGHT, ordered by RIGHT's tracked_polys flat-view order. RIGHT is
/// treated as the reference because for the compaction permutation
/// it is always a (non-strict) subset of LEFT — the compacted output's
/// tracked columns are a subset of the filter's input's tracked columns.
///
/// Returns an empty vector when RIGHT has no data columns (would be a
/// degenerate perm anyway). If RIGHT names a column that LEFT does not
/// carry (defensive, shouldn't happen for compaction), that name is
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

/// Flat-view indices of `names` (in `names` order) among `fields`. Both
/// sides resolve the same `names`, so challenge `k` meets the same column
/// on each.
fn indices_by_names<'a>(
    fields: impl Iterator<Item = &'a datafusion::arrow::datatypes::FieldRef> + Clone,
    names: &[String],
) -> Vec<usize> {
    names
        .iter()
        .map(|n| {
            fields
                .clone()
                .position(|f| f.name() == n)
                .expect("perm side missing shared column — LEFT/RIGHT diverged unexpectedly")
        })
        .collect()
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
