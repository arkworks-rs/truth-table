//! Top-level composite gadget for paper §6.1 PIOP 6 Multi-Character
//! Pattern Matching.
//!
//! Supports arbitrary `t ≥ 1` factor lists via the Sweep Factors
//! orchestration (paper PIOP 7). For `t = 1` this reduces to a single
//! FactorPlacement wrapped in the usual DPUC + LFC + verdict frame; for
//! `t ≥ 2` Sweep Factors additionally threads a `past_j`-gated alive
//! activator through the round-by-round placements.
//!
//! # Relation
//!
//! Given the original tuple `(a^old, char-act^old, char, orig-ind,
//! int-ind, ind, bnd, l)`, a factor `p_1 = (str_1, mode_1)` with
//! `k = |str_1|`, and prover-claimed new activators `(a^new, char-act^new)`
//! plus a length-filter output `(a^{old'}, char-act^{old'})`, the gadget
//! proves `a^new[i] = 1` iff string `i` was originally active, has
//! length ≥ k, and satisfies pattern `p_1`.
//!
//! # Decomposition (Steps 1–5 of PIOP 6)
//!
//! 1. **Activator validity** — `DataPreservingUpdateCheck` on
//!    `(char-act^new, a^new, orig-ind, ind, l)`.
//! 2. **Length filtering** — `LengthFilteringCheck` with threshold
//!    `Σ_j |str_j|` on `(a^old, char-act^old, a^{old'}, char-act^{old'})`.
//! 3. **Containment** — inline `Zerocheck` on `a^new · (1 − a^{old'})`.
//! 4. **Sweep factors** — `SweepFactors([(str_1, mode_1), …, (str_t,
//!    mode_t)])` with `(char-act^{old'}, a^{old'})` as the initial
//!    alive activators. For `t = 1` this reduces to a single Factor
//!    Placement; for `t ≥ 2` past_j indicators gate subsequent
//!    factors' char domains.
//! 5. **Verdict** — inline `Zerocheck` on `a^new − alive_h` where
//!    `alive_h = match_{t-1}`.
//!
//! # Payload structure
//!
//! Shared slots:
//! - [`CHAR_INPUT_LABEL`] — `{ char, orig-ind, int-ind, bnd }` with
//!   activator `char-act^old`.
//! - [`STR_INPUT_LABEL`] — `{ ind, l }` with activator `a^old`.
//! - [`LENGTH_FILTERED_CHAR_LABEL`] — `{ char-act^{old'} }`, no activator.
//! - [`LENGTH_FILTERED_STR_LABEL`] — `{ a^{old'} }`, no activator.
//! - [`NEW_CHAR_LABEL`] — `{ char-act^new }`, no activator.
//! - [`NEW_STR_LABEL`] — `{ a^new }`, no activator.
//!
//! Per factor `j` (0-indexed), via [`factor_label`]`(j, …)` (re-exported
//! from [`sweep_factors::factor_label`]):
//! - `"rotated_char"` — `k_j` char-level columns `char^{(0)}_j..char^{(k_j−1)}_j`
//!   for factor `j` (each verified against `char` by SweepFactors's
//!   internal rotation chain).
//! - `"occurs"`, `"match"`, `"mark"`, `"start"`, `"match_broadcast"`,
//!   `"start_broadcast"`, `"leftmost_mask"` — FactorPlacement witnesses.
//! - `"att_mask"` — suffix mode only.
//! - `"rotated_bnd"` — infix mode with `k_j ≥ 2` only.
//! - `"past"` — only for `j < t − 1` (past_j indicator for the
//!   inter-factor alive chain).

use std::marker::PhantomData;
use std::sync::Arc;

use arithmetic::{ACTIVATOR_FIELD, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_piop::{
    SnarkBackend, errors::SnarkResult, prover::structs::polynomial::TrackedPoly,
    verifier::structs::oracle::TrackedOracle,
};
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{
            IsGadgetNode, IsNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
            utils::{
                data_preserving_update_check, length_filtering_check, sweep_factors,
            },
        },
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub use sweep_factors::{Mode, factor_label};

pub const CHAR_INPUT_LABEL: &str = "__char_input__";
pub const STR_INPUT_LABEL: &str = "__str_input__";
pub const LENGTH_FILTERED_CHAR_LABEL: &str = "__length_filtered_char__";
pub const LENGTH_FILTERED_STR_LABEL: &str = "__length_filtered_str__";
pub const NEW_CHAR_LABEL: &str = "__new_char__";
pub const NEW_STR_LABEL: &str = "__new_str__";

fn resize_poly<B: SnarkBackend>(p: &TrackedPoly<B>, log_size: usize) -> TrackedPoly<B> {
    TrackedPoly::new(p.id_or_const(), log_size, p.tracker())
}
fn resize_oracle<B: SnarkBackend>(o: &TrackedOracle<B>, log_size: usize) -> TrackedOracle<B> {
    TrackedOracle::new(o.id_or_const(), o.tracker(), log_size)
}

fn bool_field() -> FieldRef {
    Arc::new(Field::new("data", DataType::Boolean, false))
}
fn u64_field(name: &str) -> FieldRef {
    Arc::new(Field::new(name, DataType::UInt64, false))
}

/// Multi-Character Pattern Matching gadget, arbitrary factor count.
pub struct GadgetNode<B: SnarkBackend> {
    factors: Vec<(Vec<B::F>, Mode)>,
    data_preserving: Arc<Node<B>>,
    length_filtering: Arc<Node<B>>,
    sweep: Arc<Node<B>>,
    _phantom: PhantomData<B>,
}

impl<B: SnarkBackend> GadgetNode<B> {
    /// Construct with an explicit factor list.
    pub fn new(factors: Vec<(Vec<B::F>, Mode)>) -> Self {
        Self::new_with_nodup_mode(
            factors,
            crate::irs::nodes::utils::nodup::Mode::SortBased,
        )
    }

    /// Test-facing constructor exposing the nodup_mark mode of each
    /// nested FactorPlacement. Production callers should use
    /// [`Self::new`]; test harnesses that bypass
    /// `initialize_gadget_plans` should pass `BezoutBased`.
    pub fn new_with_nodup_mode(
        factors: Vec<(Vec<B::F>, Mode)>,
        nodup_mode: crate::irs::nodes::utils::nodup::Mode,
    ) -> Self {
        assert!(!factors.is_empty(), "MCPM: factor list must be non-empty");
        for (pat, _) in &factors {
            assert!(!pat.is_empty(), "MCPM: each factor pattern must be non-empty");
        }
        // Length-filter threshold is the total pattern content (Σ_j |str_j|):
        // a string can satisfy the pattern only if it has at least that
        // many chars in total (the wildcards demand zero or more chars
        // between factors, so their contribution is 0).
        let total_len: usize = factors.iter().map(|(pat, _)| pat.len()).sum();
        let data_preserving = Arc::new(Node::<B>::Gadget(Arc::new(
            data_preserving_update_check::GadgetNode::new(),
        )));
        let length_filtering = Arc::new(Node::<B>::Gadget(Arc::new(
            length_filtering_check::GadgetNode::new(total_len as u64),
        )));
        let sweep = Arc::new(Node::<B>::Gadget(Arc::new(
            sweep_factors::GadgetNode::new_with_nodup_mode(factors.clone(), nodup_mode),
        )));
        Self {
            factors,
            data_preserving,
            length_filtering,
            sweep,
            _phantom: PhantomData,
        }
    }

    /// Convenience constructor for the common `t = 1` case.
    pub fn new_single(pattern: Vec<B::F>, mode: Mode) -> Self {
        Self::new(vec![(pattern, mode)])
    }

    pub fn num_factors(&self) -> usize {
        self.factors.len()
    }
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        format!("MultiCharacterPatternMatching(t={})", self.factors.len())
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
        vec![
            self.data_preserving.clone(),
            self.length_filtering.clone(),
            self.sweep.clone(),
        ]
    }
}

// --- Payload extraction ---

struct PayloadProver<B: SnarkBackend> {
    char_input: TrackedTable<B>,
    str_input: TrackedTable<B>,
    a_h_old_prime: TrackedPoly<B>,
    a_h_new: TrackedPoly<B>,
    match_str: TrackedPoly<B>,
}

struct PayloadVerifier<B: SnarkBackend> {
    char_input: TrackedTableOracle<B>,
    str_input: TrackedTableOracle<B>,
    a_h_old_prime: TrackedOracle<B>,
    a_h_new: TrackedOracle<B>,
    match_str: TrackedOracle<B>,
}

fn extract_prover<B: SnarkBackend>(
    ir: &GadgetReadyIr<B>,
    id: NodeId,
    last_factor_idx: usize,
) -> PayloadProver<B> {
    let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
        panic!("MCPM: missing gadget payload");
    };
    let char_input = payload.get(CHAR_INPUT_LABEL).expect("missing CHAR_INPUT").clone();
    let str_input = payload.get(STR_INPUT_LABEL).expect("missing STR_INPUT").clone();
    let lf_str = payload
        .get(LENGTH_FILTERED_STR_LABEL)
        .expect("missing LENGTH_FILTERED_STR");
    let new_str = payload.get(NEW_STR_LABEL).expect("missing NEW_STR");
    // The verdict reads alive_h = match_{t-1}, i.e. the last factor's
    // match column.
    let match_key = factor_label(last_factor_idx, "match");
    let match_t = payload
        .get(&match_key)
        .unwrap_or_else(|| panic!("MCPM: missing {match_key} (last factor's match)"));

    let a_h_old_prime = lf_str
        .tracked_col_by_ind(lf_str.data_tracked_polys_indices()[0])
        .data_tracked_poly();
    let a_h_new = new_str
        .tracked_col_by_ind(new_str.data_tracked_polys_indices()[0])
        .data_tracked_poly();
    let match_str = match_t
        .tracked_col_by_ind(match_t.data_tracked_polys_indices()[0])
        .data_tracked_poly();
    PayloadProver {
        char_input,
        str_input,
        a_h_old_prime,
        a_h_new,
        match_str,
    }
}

fn extract_verifier<B: SnarkBackend>(
    ir: &VerifierGadgetReadyIr<B>,
    id: NodeId,
    last_factor_idx: usize,
) -> PayloadVerifier<B> {
    let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
        panic!("MCPM: missing gadget payload");
    };
    let char_input = payload.get(CHAR_INPUT_LABEL).expect("missing CHAR_INPUT").clone();
    let str_input = payload.get(STR_INPUT_LABEL).expect("missing STR_INPUT").clone();
    let lf_str = payload
        .get(LENGTH_FILTERED_STR_LABEL)
        .expect("missing LENGTH_FILTERED_STR");
    let new_str = payload.get(NEW_STR_LABEL).expect("missing NEW_STR");
    let match_key = factor_label(last_factor_idx, "match");
    let match_t = payload
        .get(&match_key)
        .unwrap_or_else(|| panic!("MCPM: missing {match_key} (last factor's match)"));

    let a_h_old_prime = lf_str
        .tracked_col_oracle_by_ind(lf_str.data_tracked_oracles_indices()[0])
        .data_tracked_oracle();
    let a_h_new = new_str
        .tracked_col_oracle_by_ind(new_str.data_tracked_oracles_indices()[0])
        .data_tracked_oracle();
    let match_str = match_t
        .tracked_col_oracle_by_ind(match_t.data_tracked_oracles_indices()[0])
        .data_tracked_oracle();
    PayloadVerifier {
        char_input,
        str_input,
        a_h_old_prime,
        a_h_new,
        match_str,
    }
}

// --- Child payload wiring ---

fn set_dpuc_payload_prover<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    ir: &mut GadgetReadyIr<B>,
    id: NodeId,
) {
    // Reuse extraction to pull the child inputs.
    let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
        panic!("MCPM: missing gadget payload");
    };
    let char_input: &TrackedTable<B> = payload.get(CHAR_INPUT_LABEL).unwrap();
    let str_input: &TrackedTable<B> = payload.get(STR_INPUT_LABEL).unwrap();
    let new_char = payload.get(NEW_CHAR_LABEL).unwrap();
    let new_str = payload.get(NEW_STR_LABEL).unwrap();

    let orig_ind = char_input
        .tracked_col_by_ind(char_input.data_tracked_polys_indices()[1])
        .data_tracked_poly();
    let ind = str_input
        .tracked_col_by_ind(str_input.data_tracked_polys_indices()[0])
        .data_tracked_poly();
    let l = str_input
        .tracked_col_by_ind(str_input.data_tracked_polys_indices()[1])
        .data_tracked_poly();
    let char_act_new = new_char
        .tracked_col_by_ind(new_char.data_tracked_polys_indices()[0])
        .data_tracked_poly();
    let a_new = new_str
        .tracked_col_by_ind(new_str.data_tracked_polys_indices()[0])
        .data_tracked_poly();

    let char_domain = char_input.log_size();
    let str_domain = str_input.log_size();

    let orig_ind_f = u64_field("orig_ind");
    let ind_f = u64_field("ind");
    let l_f = Arc::new(Field::new("l", DataType::Int32, false));

    let mut lhs_polys = IndexMap::new();
    lhs_polys.insert(orig_ind_f.clone(), orig_ind);
    lhs_polys.insert(ACTIVATOR_FIELD.clone(), char_act_new);
    let lhs = TrackedTable::new(
        Some(Schema::new(vec![orig_ind_f.as_ref().clone()])),
        lhs_polys,
        char_domain,
    );

    let mut rhs_polys = IndexMap::new();
    rhs_polys.insert(ind_f.clone(), ind);
    rhs_polys.insert(l_f.clone(), l);
    rhs_polys.insert(ACTIVATOR_FIELD.clone(), a_new);
    let rhs = TrackedTable::new(
        Some(Schema::new(vec![
            ind_f.as_ref().clone(),
            l_f.as_ref().clone(),
        ])),
        rhs_polys,
        str_domain,
    );

    let mut child_payload = IndexMap::new();
    child_payload.insert(data_preserving_update_check::LHS_LABEL.to_string(), lhs);
    child_payload.insert(data_preserving_update_check::RHS_LABEL.to_string(), rhs);
    ir.set_payload_for_node(
        node.id(),
        Some(PayloadStructure::GadgetPayload(child_payload)),
    );
}

fn set_dpuc_payload_verifier<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    ir: &mut VerifierGadgetReadyIr<B>,
    id: NodeId,
) {
    let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
        panic!("MCPM: missing gadget payload");
    };
    let char_input: &TrackedTableOracle<B> = payload.get(CHAR_INPUT_LABEL).unwrap();
    let str_input: &TrackedTableOracle<B> = payload.get(STR_INPUT_LABEL).unwrap();
    let new_char = payload.get(NEW_CHAR_LABEL).unwrap();
    let new_str = payload.get(NEW_STR_LABEL).unwrap();

    let orig_ind = char_input
        .tracked_col_oracle_by_ind(char_input.data_tracked_oracles_indices()[1])
        .data_tracked_oracle();
    let ind = str_input
        .tracked_col_oracle_by_ind(str_input.data_tracked_oracles_indices()[0])
        .data_tracked_oracle();
    let l = str_input
        .tracked_col_oracle_by_ind(str_input.data_tracked_oracles_indices()[1])
        .data_tracked_oracle();
    let char_act_new = new_char
        .tracked_col_oracle_by_ind(new_char.data_tracked_oracles_indices()[0])
        .data_tracked_oracle();
    let a_new = new_str
        .tracked_col_oracle_by_ind(new_str.data_tracked_oracles_indices()[0])
        .data_tracked_oracle();

    let char_domain = char_input.log_size();
    let str_domain = str_input.log_size();

    let orig_ind_f = u64_field("orig_ind");
    let ind_f = u64_field("ind");
    let l_f = Arc::new(Field::new("l", DataType::Int32, false));

    let mut lhs_oracles = IndexMap::new();
    lhs_oracles.insert(orig_ind_f.clone(), orig_ind);
    lhs_oracles.insert(ACTIVATOR_FIELD.clone(), char_act_new);
    let lhs = TrackedTableOracle::new(
        Some(Schema::new(vec![orig_ind_f.as_ref().clone()])),
        lhs_oracles,
        char_domain,
    );

    let mut rhs_oracles = IndexMap::new();
    rhs_oracles.insert(ind_f.clone(), ind);
    rhs_oracles.insert(l_f.clone(), l);
    rhs_oracles.insert(ACTIVATOR_FIELD.clone(), a_new);
    let rhs = TrackedTableOracle::new(
        Some(Schema::new(vec![
            ind_f.as_ref().clone(),
            l_f.as_ref().clone(),
        ])),
        rhs_oracles,
        str_domain,
    );

    let mut child_payload = IndexMap::new();
    child_payload.insert(data_preserving_update_check::LHS_LABEL.to_string(), lhs);
    child_payload.insert(data_preserving_update_check::RHS_LABEL.to_string(), rhs);
    ir.set_payload_for_node(
        node.id(),
        Some(PayloadStructure::GadgetPayload(child_payload)),
    );
}

fn set_lfc_payload_prover<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    ir: &mut GadgetReadyIr<B>,
    id: NodeId,
) {
    let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
        panic!("MCPM: missing gadget payload");
    };
    let char_input: &TrackedTable<B> = payload.get(CHAR_INPUT_LABEL).unwrap();
    let str_input: &TrackedTable<B> = payload.get(STR_INPUT_LABEL).unwrap();
    let lf_char = payload.get(LENGTH_FILTERED_CHAR_LABEL).unwrap();
    let lf_str = payload.get(LENGTH_FILTERED_STR_LABEL).unwrap();

    let char_domain = char_input.log_size();
    let str_domain = str_input.log_size();

    let orig_ind = char_input
        .tracked_col_by_ind(char_input.data_tracked_polys_indices()[1])
        .data_tracked_poly();
    let ind = str_input
        .tracked_col_by_ind(str_input.data_tracked_polys_indices()[0])
        .data_tracked_poly();
    let l = str_input
        .tracked_col_by_ind(str_input.data_tracked_polys_indices()[1])
        .data_tracked_poly();
    let char_act_old = char_input
        .activator_tracked_poly()
        .expect("char-act^old required");
    let a_old = str_input.activator_tracked_poly().expect("a^old required");
    let char_act_old_prime = lf_char
        .tracked_col_by_ind(lf_char.data_tracked_polys_indices()[0])
        .data_tracked_poly();
    let a_old_prime = lf_str
        .tracked_col_by_ind(lf_str.data_tracked_polys_indices()[0])
        .data_tracked_poly();

    let orig_ind_f = u64_field("orig_ind");
    let ind_f = u64_field("ind");
    let l_f = Arc::new(Field::new("l", DataType::Int32, false));

    let mut char_polys = IndexMap::new();
    char_polys.insert(orig_ind_f.clone(), orig_ind);
    char_polys.insert(ACTIVATOR_FIELD.clone(), char_act_old);
    let char_table = TrackedTable::new(
        Some(Schema::new(vec![orig_ind_f.as_ref().clone()])),
        char_polys,
        char_domain,
    );

    let mut str_polys = IndexMap::new();
    str_polys.insert(ind_f.clone(), ind);
    str_polys.insert(l_f.clone(), l);
    str_polys.insert(ACTIVATOR_FIELD.clone(), a_old);
    let str_table = TrackedTable::new(
        Some(Schema::new(vec![
            ind_f.as_ref().clone(),
            l_f.as_ref().clone(),
        ])),
        str_polys,
        str_domain,
    );

    let mut char_filt_polys = IndexMap::new();
    char_filt_polys.insert(bool_field(), char_act_old_prime);
    let char_filt = TrackedTable::new(
        Some(Schema::new(vec![bool_field().as_ref().clone()])),
        char_filt_polys,
        char_domain,
    );

    let mut str_filt_polys = IndexMap::new();
    str_filt_polys.insert(bool_field(), a_old_prime);
    let str_filt = TrackedTable::new(
        Some(Schema::new(vec![bool_field().as_ref().clone()])),
        str_filt_polys,
        str_domain,
    );

    let mut child = IndexMap::new();
    child.insert(length_filtering_check::CHAR_INPUT_LABEL.to_string(), char_table);
    child.insert(length_filtering_check::STR_INPUT_LABEL.to_string(), str_table);
    child.insert(length_filtering_check::CHAR_FILTERED_LABEL.to_string(), char_filt);
    child.insert(length_filtering_check::STR_FILTERED_LABEL.to_string(), str_filt);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(child)));
}

fn set_lfc_payload_verifier<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    ir: &mut VerifierGadgetReadyIr<B>,
    id: NodeId,
) {
    let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
        panic!("MCPM: missing gadget payload");
    };
    let char_input: &TrackedTableOracle<B> = payload.get(CHAR_INPUT_LABEL).unwrap();
    let str_input: &TrackedTableOracle<B> = payload.get(STR_INPUT_LABEL).unwrap();
    let lf_char = payload.get(LENGTH_FILTERED_CHAR_LABEL).unwrap();
    let lf_str = payload.get(LENGTH_FILTERED_STR_LABEL).unwrap();

    let char_domain = char_input.log_size();
    let str_domain = str_input.log_size();

    let orig_ind = char_input
        .tracked_col_oracle_by_ind(char_input.data_tracked_oracles_indices()[1])
        .data_tracked_oracle();
    let ind = str_input
        .tracked_col_oracle_by_ind(str_input.data_tracked_oracles_indices()[0])
        .data_tracked_oracle();
    let l = str_input
        .tracked_col_oracle_by_ind(str_input.data_tracked_oracles_indices()[1])
        .data_tracked_oracle();
    let char_act_old = char_input
        .activator_tracked_poly()
        .expect("char-act^old required");
    let a_old = str_input.activator_tracked_poly().expect("a^old required");
    let char_act_old_prime = lf_char
        .tracked_col_oracle_by_ind(lf_char.data_tracked_oracles_indices()[0])
        .data_tracked_oracle();
    let a_old_prime = lf_str
        .tracked_col_oracle_by_ind(lf_str.data_tracked_oracles_indices()[0])
        .data_tracked_oracle();

    let orig_ind_f = u64_field("orig_ind");
    let ind_f = u64_field("ind");
    let l_f = Arc::new(Field::new("l", DataType::Int32, false));

    let mut char_oracles = IndexMap::new();
    char_oracles.insert(orig_ind_f.clone(), orig_ind);
    char_oracles.insert(ACTIVATOR_FIELD.clone(), char_act_old);
    let char_table = TrackedTableOracle::new(
        Some(Schema::new(vec![orig_ind_f.as_ref().clone()])),
        char_oracles,
        char_domain,
    );

    let mut str_oracles = IndexMap::new();
    str_oracles.insert(ind_f.clone(), ind);
    str_oracles.insert(l_f.clone(), l);
    str_oracles.insert(ACTIVATOR_FIELD.clone(), a_old);
    let str_table = TrackedTableOracle::new(
        Some(Schema::new(vec![
            ind_f.as_ref().clone(),
            l_f.as_ref().clone(),
        ])),
        str_oracles,
        str_domain,
    );

    let mut char_filt_oracles = IndexMap::new();
    char_filt_oracles.insert(bool_field(), char_act_old_prime);
    let char_filt = TrackedTableOracle::new(
        Some(Schema::new(vec![bool_field().as_ref().clone()])),
        char_filt_oracles,
        char_domain,
    );

    let mut str_filt_oracles = IndexMap::new();
    str_filt_oracles.insert(bool_field(), a_old_prime);
    let str_filt = TrackedTableOracle::new(
        Some(Schema::new(vec![bool_field().as_ref().clone()])),
        str_filt_oracles,
        str_domain,
    );

    let mut child = IndexMap::new();
    child.insert(length_filtering_check::CHAR_INPUT_LABEL.to_string(), char_table);
    child.insert(length_filtering_check::STR_INPUT_LABEL.to_string(), str_table);
    child.insert(length_filtering_check::CHAR_FILTERED_LABEL.to_string(), char_filt);
    child.insert(length_filtering_check::STR_FILTERED_LABEL.to_string(), str_filt);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(child)));
}

/// Labels the MCPM-level payload owns; everything else in the parent
/// payload is assumed to belong to a per-factor slot and gets forwarded
/// to SweepFactors unchanged.
const MCPM_OWNED_LABELS: &[&str] = &[
    CHAR_INPUT_LABEL,
    STR_INPUT_LABEL,
    LENGTH_FILTERED_CHAR_LABEL,
    LENGTH_FILTERED_STR_LABEL,
    NEW_CHAR_LABEL,
    NEW_STR_LABEL,
];

fn set_sweep_factors_payload_prover<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    ir: &mut GadgetReadyIr<B>,
    id: NodeId,
) {
    // SweepFactors takes over from the LFC-filtered activator pair:
    // `(char-act^{old'}, a^{old'})` become alive_c_0 / alive_h_0.
    let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
        panic!("MCPM: missing gadget payload");
    };

    let char_input: &TrackedTable<B> = payload.get(CHAR_INPUT_LABEL).unwrap();
    let str_input: &TrackedTable<B> = payload.get(STR_INPUT_LABEL).unwrap();
    let lf_char = payload.get(LENGTH_FILTERED_CHAR_LABEL).unwrap();
    let lf_str = payload.get(LENGTH_FILTERED_STR_LABEL).unwrap();

    let char_domain = char_input.log_size();
    let str_domain = str_input.log_size();

    let char_col = char_input
        .tracked_col_by_ind(char_input.data_tracked_polys_indices()[0])
        .data_tracked_poly();
    let orig_ind = char_input
        .tracked_col_by_ind(char_input.data_tracked_polys_indices()[1])
        .data_tracked_poly();
    let int_ind = char_input
        .tracked_col_by_ind(char_input.data_tracked_polys_indices()[2])
        .data_tracked_poly();
    let bnd = char_input
        .tracked_col_by_ind(char_input.data_tracked_polys_indices()[3])
        .data_tracked_poly();
    let ind = str_input
        .tracked_col_by_ind(str_input.data_tracked_polys_indices()[0])
        .data_tracked_poly();
    let char_act_old_prime = lf_char
        .tracked_col_by_ind(lf_char.data_tracked_polys_indices()[0])
        .data_tracked_poly();
    let a_old_prime = lf_str
        .tracked_col_by_ind(lf_str.data_tracked_polys_indices()[0])
        .data_tracked_poly();

    let mut char_polys = IndexMap::new();
    char_polys.insert(u64_field("char"), char_col);
    char_polys.insert(u64_field("orig_ind"), orig_ind);
    char_polys.insert(u64_field("int_ind"), int_ind);
    char_polys.insert(u64_field("bnd"), bnd);
    char_polys.insert(ACTIVATOR_FIELD.clone(), char_act_old_prime);
    let char_schema = Schema::new(vec![
        Field::new("char", DataType::UInt64, false),
        Field::new("orig_ind", DataType::UInt64, false),
        Field::new("int_ind", DataType::UInt64, false),
        Field::new("bnd", DataType::UInt64, false),
    ]);
    let child_char =
        TrackedTable::new(Some(char_schema), char_polys, char_domain);

    let mut str_polys = IndexMap::new();
    str_polys.insert(u64_field("ind"), ind);
    str_polys.insert(ACTIVATOR_FIELD.clone(), a_old_prime);
    let str_schema = Schema::new(vec![Field::new("ind", DataType::UInt64, false)]);
    let child_str = TrackedTable::new(Some(str_schema), str_polys, str_domain);

    let mut child = IndexMap::new();
    child.insert(sweep_factors::CHAR_INPUT_LABEL.to_string(), child_char);
    child.insert(sweep_factors::STR_INPUT_LABEL.to_string(), child_str);
    // Forward all per-factor tables (anything not owned by MCPM).
    for (key, table) in payload.iter() {
        if !MCPM_OWNED_LABELS.contains(&key.as_str()) {
            child.insert(key.clone(), table.clone());
        }
    }
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(child)));
}

fn set_sweep_factors_payload_verifier<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    ir: &mut VerifierGadgetReadyIr<B>,
    id: NodeId,
) {
    let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
        panic!("MCPM: missing gadget payload");
    };

    let char_input: &TrackedTableOracle<B> = payload.get(CHAR_INPUT_LABEL).unwrap();
    let str_input: &TrackedTableOracle<B> = payload.get(STR_INPUT_LABEL).unwrap();
    let lf_char = payload.get(LENGTH_FILTERED_CHAR_LABEL).unwrap();
    let lf_str = payload.get(LENGTH_FILTERED_STR_LABEL).unwrap();

    let char_domain = char_input.log_size();
    let str_domain = str_input.log_size();

    let char_col = char_input
        .tracked_col_oracle_by_ind(char_input.data_tracked_oracles_indices()[0])
        .data_tracked_oracle();
    let orig_ind = char_input
        .tracked_col_oracle_by_ind(char_input.data_tracked_oracles_indices()[1])
        .data_tracked_oracle();
    let int_ind = char_input
        .tracked_col_oracle_by_ind(char_input.data_tracked_oracles_indices()[2])
        .data_tracked_oracle();
    let bnd = char_input
        .tracked_col_oracle_by_ind(char_input.data_tracked_oracles_indices()[3])
        .data_tracked_oracle();
    let ind = str_input
        .tracked_col_oracle_by_ind(str_input.data_tracked_oracles_indices()[0])
        .data_tracked_oracle();
    let char_act_old_prime = lf_char
        .tracked_col_oracle_by_ind(lf_char.data_tracked_oracles_indices()[0])
        .data_tracked_oracle();
    let a_old_prime = lf_str
        .tracked_col_oracle_by_ind(lf_str.data_tracked_oracles_indices()[0])
        .data_tracked_oracle();

    let mut char_oracles = IndexMap::new();
    char_oracles.insert(u64_field("char"), char_col);
    char_oracles.insert(u64_field("orig_ind"), orig_ind);
    char_oracles.insert(u64_field("int_ind"), int_ind);
    char_oracles.insert(u64_field("bnd"), bnd);
    char_oracles.insert(ACTIVATOR_FIELD.clone(), char_act_old_prime);
    let char_schema = Schema::new(vec![
        Field::new("char", DataType::UInt64, false),
        Field::new("orig_ind", DataType::UInt64, false),
        Field::new("int_ind", DataType::UInt64, false),
        Field::new("bnd", DataType::UInt64, false),
    ]);
    let child_char =
        TrackedTableOracle::new(Some(char_schema), char_oracles, char_domain);

    let mut str_oracles = IndexMap::new();
    str_oracles.insert(u64_field("ind"), ind);
    str_oracles.insert(ACTIVATOR_FIELD.clone(), a_old_prime);
    let str_schema = Schema::new(vec![Field::new("ind", DataType::UInt64, false)]);
    let child_str =
        TrackedTableOracle::new(Some(str_schema), str_oracles, str_domain);

    let mut child = IndexMap::new();
    child.insert(sweep_factors::CHAR_INPUT_LABEL.to_string(), child_char);
    child.insert(sweep_factors::STR_INPUT_LABEL.to_string(), child_str);
    for (key, table) in payload.iter() {
        if !MCPM_OWNED_LABELS.contains(&key.as_str()) {
            child.insert(key.clone(), table.clone());
        }
    }
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(child)));
}

// --- Prover / Verifier impls ---

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
        set_dpuc_payload_prover(&self.data_preserving, virtualized_ir, id);
        set_lfc_payload_prover(&self.length_filtering, virtualized_ir, id);
        set_sweep_factors_payload_prover(&self.sweep, virtualized_ir, id);
        Ok(())
    }
    fn initialize_gadget_plans(
        &self,
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        // Forward the LIKE-injected plan-time hints down to the
        // SweepFactors child so it can further route them to each
        // per-factor FactorPlacement. If no hints are present (e.g.
        // isolated MCPM test harness), skip silently.
        let own = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        let orig_key = "__like_orig_ind_plan_hint__".to_string();
        let orig_ind_hint = match own.get(&orig_key) {
            Some(h) => h.clone(),
            None => return Ok(()),
        };

        let mut sweep_payload = match planned_ir.payload_for_node(&self.sweep.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        sweep_payload.insert(orig_key, orig_ind_hint);
        for j in 0..self.factors.len() {
            let key = format!("__like_f{j}_mark_plan_hint__");
            if let Some(mark_hint) = own.get(&key) {
                sweep_payload.insert(key, mark_hint.clone());
            }
        }
        planned_ir.set_payload_for_node(
            self.sweep.id(),
            Some(PayloadStructure::GadgetPayload(sweep_payload)),
        );
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
        set_dpuc_payload_verifier(&self.data_preserving, virtualized_ir, id);
        set_lfc_payload_verifier(&self.length_filtering, virtualized_ir, id);
        set_sweep_factors_payload_verifier(&self.sweep, virtualized_ir, id);
        Ok(())
    }
    fn initialize_gadget_plans(
        &self,
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        // Forward the LIKE-injected plan-time hints down to the
        // SweepFactors child so it can further route them to each
        // per-factor FactorPlacement. If no hints are present (e.g.
        // isolated MCPM test harness), skip silently.
        let own = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        let orig_key = "__like_orig_ind_plan_hint__".to_string();
        let orig_ind_hint = match own.get(&orig_key) {
            Some(h) => h.clone(),
            None => return Ok(()),
        };

        let mut sweep_payload = match planned_ir.payload_for_node(&self.sweep.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        sweep_payload.insert(orig_key, orig_ind_hint);
        for j in 0..self.factors.len() {
            let key = format!("__like_f{j}_mark_plan_hint__");
            if let Some(mark_hint) = own.get(&key) {
                sweep_payload.insert(key, mark_hint.clone());
            }
        }
        planned_ir.set_payload_for_node(
            self.sweep.id(),
            Some(PayloadStructure::GadgetPayload(sweep_payload)),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        let last = self.factors.len() - 1;
        let inputs = extract_prover(gadget_ready_ir, id, last);
        let str_domain = inputs.str_input.log_size();
        let _ = &inputs.char_input;

        // Step 3 (Containment): a^new · (1 − a^{old'}) = 0.
        {
            let one_minus = inputs
                .a_h_old_prime
                .mul_scalar_poly(-B::F::from(1u64))
                .add_scalar_poly(B::F::from(1u64));
            let claim = &inputs.a_h_new * &one_minus;
            prover.add_mv_zerocheck_claim(resize_poly(&claim, str_domain).id())?;
        }
        // Step 5 (Verdict): a^new − alive_h = a^new − match_{t-1} = 0.
        {
            let claim = &inputs.a_h_new - &inputs.match_str;
            prover.add_mv_zerocheck_claim(resize_poly(&claim, str_domain).id())?;
        }
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
        let last = self.factors.len() - 1;
        let inputs = extract_verifier(gadget_ready_ir, id, last);
        let str_domain = inputs.str_input.log_size();
        let _ = &inputs.char_input;

        {
            let one_minus = inputs
                .a_h_old_prime
                .mul_scalar_oracle(-B::F::from(1u64))
                .add_scalar_oracle(B::F::from(1u64));
            let claim = &inputs.a_h_new * &one_minus;
            verifier.add_mv_zerocheck_claim(resize_oracle(&claim, str_domain).id());
        }
        {
            let claim = &inputs.a_h_new - &inputs.match_str;
            verifier.add_mv_zerocheck_claim(resize_oracle(&claim, str_domain).id());
        }
        Ok(())
    }
    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}
