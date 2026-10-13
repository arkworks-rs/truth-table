//! Pre-Filtering Check (paper §6.2, PIOP 8).
//!
//! Proves that the prover's filtered activator `a'` keeps exactly the active
//! strings that set every tested bin,
//!
//!   a'[i] = a[i] · ∏_{b ∈ Q} fp_b[i]
//!
//! where `fp_b` is the fingerprint column of bin `b` and `Q` the tested bins,
//! and, in full mode, that `char-act'` is the matching char-level activator.
//!
//! The data owner commits the fingerprint as one boolean column per bin (see
//! [`arithmetic::fingerprint`]), trusted like the rest of the table. The
//! product is therefore 1 exactly on the active rows that set every tested
//! bin, and one zerocheck pins `a'` completely: it is boolean, contained in
//! `a`, with no false negatives and no false positives. Both sides derive `Q`
//! from the public `φ`, the subset of the pattern's bins the query tests.
//!
//! 1. Full mode only (see [`GadgetNode::new_row_only`]): Data-Preserving
//!    Update Check on `(char-act', a', orig-ind, ind, l)`.
//! 2. Zerocheck on `a' - a · ∏_{b ∈ Q} fp_b`, of degree `|Q| + 1`.

use std::marker::PhantomData;
use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_FIELD,
    col::TrackedCol,
    col_oracle::TrackedColOracle,
    fingerprint::{self, FpMask, LIMB_BITS},
    table::TrackedTable,
    table_oracle::TrackedTableOracle,
};

// Each committed fingerprint column is one bin, so the columns are boolean
// and the subset test is their product.
const _: () = assert!(LIMB_BITS == 1);
use ark_piop::{
    SnarkBackend, errors::SnarkResult, prover::structs::polynomial::TrackedPoly,
    verifier::structs::oracle::TrackedOracle,
};
use datafusion::arrow::datatypes::Schema;
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{
            IsGadgetNode, IsNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
            utils::data_preserving_update_check,
        },
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

/// Full mode only: `{ orig-ind }` under `char-act`.
pub const CHAR_INPUT_LABEL: &str = "__char_input__";
/// `{ fp_b for b ∈ Q }` under `a`.
pub const STR_INPUT_LABEL: &str = "__str_input__";
/// Full mode only: `{ ind, l }`.
pub const STR_INDEX_LABEL: &str = "__str_index__";
/// Full mode only: `{ char-act' }`.
pub const CHAR_FILTERED_LABEL: &str = "__char_filtered__";
/// `{ a' }`.
pub const STR_FILTERED_LABEL: &str = "__str_filtered__";

/// See `length_filtering_check::resize_poly`.
fn resize_poly<B: SnarkBackend>(p: &TrackedPoly<B>, log_size: usize) -> TrackedPoly<B> {
    TrackedPoly::new(p.id_or_const(), log_size, p.tracker())
}

fn resize_oracle<B: SnarkBackend>(o: &TrackedOracle<B>, log_size: usize) -> TrackedOracle<B> {
    TrackedOracle::new(o.id_or_const(), o.tracker(), log_size)
}

pub struct GadgetNode<B: SnarkBackend> {
    /// The public `φ`: the bins the query tests.
    pattern_fingerprint: FpMask,
    /// The tested bins `Q`, ascending; one fp column each.
    needed: Vec<usize>,
    /// The DPUC child that ties `char-act'` to `a'`. `None` in row-only
    /// mode, which is for plans where nothing consumes `char-act'`: MCPM
    /// derives its own consistent pair in its LengthFilteringCheck, and the
    /// compaction path reads the compacted table's activator. Committing
    /// and checking `char-act'` there would cost char-domain work for a
    /// statement nothing relies on. A composition that consumes the
    /// narrowed char activator directly (the paper's same-tables
    /// composition) needs full mode.
    data_preserving: Option<Arc<Node<B>>>,
    _phantom: PhantomData<B>,
}

impl<B: SnarkBackend> GadgetNode<B> {
    /// Full mode, as in the paper. `pattern_fingerprint` is the public `φ`,
    /// which the verifier derives from the pattern with the shared scheme.
    pub fn new(pattern_fingerprint: FpMask) -> Self {
        Self::build(pattern_fingerprint, true)
    }

    /// Row-only mode: proves the string-level relation `a' = a · ∏ fp_b`
    /// and skips the `char-act'` DPUC (see the `data_preserving` field for
    /// when that is sound).
    pub fn new_row_only(pattern_fingerprint: FpMask) -> Self {
        Self::build(pattern_fingerprint, false)
    }

    fn build(pattern_fingerprint: FpMask, char_side: bool) -> Self {
        let needed = fingerprint::touched_limbs(&pattern_fingerprint);
        assert!(
            !needed.is_empty(),
            "pattern fingerprint must set at least one bin — an all-zero φ \
             pre-filters nothing and belongs on the passthrough path"
        );
        let data_preserving = char_side.then(|| {
            Arc::new(Node::<B>::Gadget(Arc::new(
                data_preserving_update_check::GadgetNode::new(),
            )))
        });
        Self {
            pattern_fingerprint,
            needed,
            data_preserving,
            _phantom: PhantomData,
        }
    }

    pub fn pattern_fingerprint(&self) -> &FpMask {
        &self.pattern_fingerprint
    }

    /// The tested bins, ascending.
    pub fn needed_limbs(&self) -> &[usize] {
        &self.needed
    }
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "PreFilteringCheck".to_string()
    }

    fn display(&self) -> String {
        crate::irs::nodes::display_with_inputs(&self.name(), &self.children())
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        self.data_preserving.iter().cloned().collect()
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let inputs = extract_prover_inputs(virtualized_ir, id);
        assert_eq!(
            inputs.str_input.data_tracked_polys_indices().len(),
            self.needed.len(),
            "PreFilteringCheck: {STR_INPUT_LABEL} must carry one column per tested bin"
        );
        let a_prime = inputs
            .str_filtered
            .tracked_col_by_ind(inputs.str_filtered.data_tracked_polys_indices()[0])
            .data_tracked_poly();

        // Full mode: take the DPUC inputs out of the payload before the IR
        // is mutated.
        let dpuc_inputs = self.data_preserving.as_ref().map(|dpuc_node| {
            let char_input = inputs
                .char_input
                .expect("PreFilteringCheck full mode: missing CHAR_INPUT");
            let str_index = inputs
                .str_index
                .expect("PreFilteringCheck full mode: missing STR_INDEX");
            let char_filtered = inputs
                .char_filtered
                .expect("PreFilteringCheck full mode: missing CHAR_FILTERED");
            let orig_ind_col =
                char_input.tracked_col_by_ind(char_input.data_tracked_polys_indices()[0]);
            let ind_col = str_index.tracked_col_by_ind(str_index.data_tracked_polys_indices()[0]);
            let l_col = str_index.tracked_col_by_ind(str_index.data_tracked_polys_indices()[1]);
            let a_c_prime = char_filtered
                .tracked_col_by_ind(char_filtered.data_tracked_polys_indices()[0])
                .data_tracked_poly();
            (dpuc_node.clone(), orig_ind_col, ind_col, l_col, a_c_prime)
        });

        if let Some((dpuc_node, orig_ind_col, ind_col, l_col, a_c_prime)) = dpuc_inputs {
            set_dpuc_payload_prover(
                &dpuc_node,
                &orig_ind_col,
                &a_c_prime,
                &ind_col,
                &l_col,
                &a_prime,
                virtualized_ir,
            );
        }

        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let inputs = extract_verifier_inputs(virtualized_ir, id);
        assert_eq!(
            inputs.str_input.data_tracked_oracles_indices().len(),
            self.needed.len(),
            "PreFilteringCheck: {STR_INPUT_LABEL} must carry one column per tested bin"
        );
        let a_prime = inputs
            .str_filtered
            .tracked_col_oracle_by_ind(inputs.str_filtered.data_tracked_oracles_indices()[0])
            .data_tracked_oracle();

        let dpuc_inputs = self.data_preserving.as_ref().map(|dpuc_node| {
            let char_input = inputs
                .char_input
                .expect("PreFilteringCheck full mode: missing CHAR_INPUT");
            let str_index = inputs
                .str_index
                .expect("PreFilteringCheck full mode: missing STR_INDEX");
            let char_filtered = inputs
                .char_filtered
                .expect("PreFilteringCheck full mode: missing CHAR_FILTERED");
            let orig_ind_col =
                char_input.tracked_col_oracle_by_ind(char_input.data_tracked_oracles_indices()[0]);
            let ind_col =
                str_index.tracked_col_oracle_by_ind(str_index.data_tracked_oracles_indices()[0]);
            let l_col =
                str_index.tracked_col_oracle_by_ind(str_index.data_tracked_oracles_indices()[1]);
            let a_c_prime = char_filtered
                .tracked_col_oracle_by_ind(char_filtered.data_tracked_oracles_indices()[0])
                .data_tracked_oracle();
            (dpuc_node.clone(), orig_ind_col, ind_col, l_col, a_c_prime)
        });

        if let Some((dpuc_node, orig_ind_col, ind_col, l_col, a_c_prime)) = dpuc_inputs {
            set_dpuc_payload_verifier(
                &dpuc_node,
                &orig_ind_col,
                &a_c_prime,
                &ind_col,
                &l_col,
                &a_prime,
                virtualized_ir,
            );
        }

        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        let inputs = extract_prover_inputs(gadget_ready_ir, id);
        let str_input = inputs.str_input;
        let a = str_input
            .activator_tracked_poly()
            .expect("Pre-Filtering: string input must carry an activator (a)");
        let a_prime = inputs
            .str_filtered
            .tracked_col_by_ind(inputs.str_filtered.data_tracked_polys_indices()[0])
            .data_tracked_poly();
        let str_domain = str_input.log_size();

        let fp_bins: Vec<TrackedPoly<B>> = str_input
            .data_tracked_polys_indices()
            .into_iter()
            .map(|ind| str_input.tracked_col_by_ind(ind).data_tracked_poly())
            .collect();

        // Step 2: a' - a · ∏ fp_b = 0. `a'` is on the left for the log_size
        // (see length_filtering_check).
        let kept = fp_bins.iter().fold(a, |acc, fp_b| &acc * fp_b);
        let subset_test = &a_prime - &kept;
        prover.add_mv_zerocheck_claim(resize_poly(&subset_test, str_domain).id())?;

        Ok(())
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: NodeId,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        let inputs = extract_verifier_inputs(gadget_ready_ir, id);
        let str_input = inputs.str_input;
        let a = str_input
            .activator_tracked_poly()
            .expect("Pre-Filtering: string input must carry an activator (a)");
        let a_prime = inputs
            .str_filtered
            .tracked_col_oracle_by_ind(inputs.str_filtered.data_tracked_oracles_indices()[0])
            .data_tracked_oracle();
        let str_domain = str_input.log_size();

        let fp_bins: Vec<TrackedOracle<B>> = str_input
            .data_tracked_oracles_indices()
            .into_iter()
            .map(|ind| {
                str_input
                    .tracked_col_oracle_by_ind(ind)
                    .data_tracked_oracle()
            })
            .collect();

        let kept = fp_bins.iter().fold(a, |acc, fp_b| &acc * fp_b);
        let subset_test = &a_prime - &kept;
        verifier.add_mv_zerocheck_claim(resize_oracle(&subset_test, str_domain).id());

        Ok(())
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

struct PayloadInputsProver<'a, B: SnarkBackend> {
    str_input: &'a TrackedTable<B>,
    str_filtered: &'a TrackedTable<B>,
    /// Full mode only.
    char_input: Option<&'a TrackedTable<B>>,
    str_index: Option<&'a TrackedTable<B>>,
    char_filtered: Option<&'a TrackedTable<B>>,
}

struct PayloadInputsVerifier<'a, B: SnarkBackend> {
    str_input: &'a TrackedTableOracle<B>,
    str_filtered: &'a TrackedTableOracle<B>,
    char_input: Option<&'a TrackedTableOracle<B>>,
    str_index: Option<&'a TrackedTableOracle<B>>,
    char_filtered: Option<&'a TrackedTableOracle<B>>,
}

fn extract_prover_inputs<B: SnarkBackend>(
    ir: &GadgetReadyIr<B>,
    id: NodeId,
) -> PayloadInputsProver<'_, B> {
    let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
        panic!("PreFilteringCheck: missing gadget payload");
    };
    PayloadInputsProver {
        str_input: payload.get(STR_INPUT_LABEL).expect("missing STR_INPUT"),
        str_filtered: payload
            .get(STR_FILTERED_LABEL)
            .expect("missing STR_FILTERED"),
        char_input: payload.get(CHAR_INPUT_LABEL),
        str_index: payload.get(STR_INDEX_LABEL),
        char_filtered: payload.get(CHAR_FILTERED_LABEL),
    }
}

fn extract_verifier_inputs<B: SnarkBackend>(
    ir: &VerifierGadgetReadyIr<B>,
    id: NodeId,
) -> PayloadInputsVerifier<'_, B> {
    let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
        panic!("PreFilteringCheck: missing gadget payload");
    };
    PayloadInputsVerifier {
        str_input: payload.get(STR_INPUT_LABEL).expect("missing STR_INPUT"),
        str_filtered: payload
            .get(STR_FILTERED_LABEL)
            .expect("missing STR_FILTERED"),
        char_input: payload.get(CHAR_INPUT_LABEL),
        str_index: payload.get(STR_INDEX_LABEL),
        char_filtered: payload.get(CHAR_FILTERED_LABEL),
    }
}

#[allow(clippy::too_many_arguments)]
fn set_dpuc_payload_prover<B: SnarkBackend>(
    dpuc_node: &Arc<Node<B>>,
    orig_ind_col: &TrackedCol<B>,
    a_c_prime: &TrackedPoly<B>,
    ind_col: &TrackedCol<B>,
    l_col: &TrackedCol<B>,
    a_prime: &TrackedPoly<B>,
    ir: &mut GadgetReadyIr<B>,
) {
    let orig_ind_field = orig_ind_col
        .field_ref()
        .expect("orig-ind must have a field ref");
    let ind_field = ind_col.field_ref().expect("ind must have a field ref");
    let l_field = l_col.field_ref().expect("l must have a field ref");

    let char_domain = a_c_prime.log_size().max(orig_ind_col.log_size());
    let mut lhs_polys = IndexMap::new();
    lhs_polys.insert(orig_ind_field.clone(), orig_ind_col.data_tracked_poly());
    lhs_polys.insert(ACTIVATOR_FIELD.clone(), a_c_prime.clone());
    let lhs_schema = Schema::new(vec![orig_ind_field.as_ref().clone()]);
    let lhs = TrackedTable::new(Some(lhs_schema), lhs_polys, char_domain);

    let str_domain = a_prime
        .log_size()
        .max(ind_col.log_size())
        .max(l_col.log_size());
    let mut rhs_polys = IndexMap::new();
    rhs_polys.insert(ind_field.clone(), ind_col.data_tracked_poly());
    rhs_polys.insert(l_field.clone(), l_col.data_tracked_poly());
    rhs_polys.insert(ACTIVATOR_FIELD.clone(), a_prime.clone());
    let rhs_schema = Schema::new(vec![ind_field.as_ref().clone(), l_field.as_ref().clone()]);
    let rhs = TrackedTable::new(Some(rhs_schema), rhs_polys, str_domain);

    let mut payload = IndexMap::new();
    payload.insert(data_preserving_update_check::LHS_LABEL.to_string(), lhs);
    payload.insert(data_preserving_update_check::RHS_LABEL.to_string(), rhs);
    ir.set_payload_for_node(
        dpuc_node.id(),
        Some(PayloadStructure::GadgetPayload(payload)),
    );
}

#[allow(clippy::too_many_arguments)]
fn set_dpuc_payload_verifier<B: SnarkBackend>(
    dpuc_node: &Arc<Node<B>>,
    orig_ind_col: &TrackedColOracle<B>,
    a_c_prime: &TrackedOracle<B>,
    ind_col: &TrackedColOracle<B>,
    l_col: &TrackedColOracle<B>,
    a_prime: &TrackedOracle<B>,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let orig_ind_field = orig_ind_col
        .field_ref()
        .expect("orig-ind must have a field ref");
    let ind_field = ind_col.field_ref().expect("ind must have a field ref");
    let l_field = l_col.field_ref().expect("l must have a field ref");

    let char_domain = a_c_prime.log_size().max(orig_ind_col.log_size());
    let mut lhs_oracles = IndexMap::new();
    lhs_oracles.insert(orig_ind_field.clone(), orig_ind_col.data_tracked_oracle());
    lhs_oracles.insert(ACTIVATOR_FIELD.clone(), a_c_prime.clone());
    let lhs_schema = Schema::new(vec![orig_ind_field.as_ref().clone()]);
    let lhs = TrackedTableOracle::new(Some(lhs_schema), lhs_oracles, char_domain);

    let str_domain = a_prime
        .log_size()
        .max(ind_col.log_size())
        .max(l_col.log_size());
    let mut rhs_oracles = IndexMap::new();
    rhs_oracles.insert(ind_field.clone(), ind_col.data_tracked_oracle());
    rhs_oracles.insert(l_field.clone(), l_col.data_tracked_oracle());
    rhs_oracles.insert(ACTIVATOR_FIELD.clone(), a_prime.clone());
    let rhs_schema = Schema::new(vec![ind_field.as_ref().clone(), l_field.as_ref().clone()]);
    let rhs = TrackedTableOracle::new(Some(rhs_schema), rhs_oracles, str_domain);

    let mut payload = IndexMap::new();
    payload.insert(data_preserving_update_check::LHS_LABEL.to_string(), lhs);
    payload.insert(data_preserving_update_check::RHS_LABEL.to_string(), rhs);
    ir.set_payload_for_node(
        dpuc_node.id(),
        Some(PayloadStructure::GadgetPayload(payload)),
    );
}

#[cfg(test)]
mod tests;
