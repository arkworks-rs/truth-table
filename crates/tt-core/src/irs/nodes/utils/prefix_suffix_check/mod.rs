//! A composite gadget node for paper §7.1 Prefix/Suffix Check (PIOP 8).
//!
//! Unified prefix and suffix support via a `Direction` parameter, matching
//! the paper's ε ∈ {+1, −1} formulation.
//!
//! **Test-fixture caveat on NoDup(Bezout).** The paper's NoDup check
//! is present and wired up in Bezout mode. Its `defrag_col` reduces the
//! active-mark support to a size-`2^ceil(log2(k))` polynomial; for
//! `k = 1` the resulting log_size collapses to 0, which trips a `None`
//! unwrap deep inside ark-piop's mv-PCS compile path. This is an ark-piop
//! degeneracy, not a soundness issue in this gadget — an honest prover
//! marking exactly one mismatch (or an adversarial witness with a single
//! mark) will panic before the verifier can reject it. The unit tests
//! deliberately arrange fixtures so `s_n` carries ≥ 2 marks in every
//! case. Followup: harden Bezout for the `size-1` support case in
//! ark-piop.
//!
//! # Relation proved
//!
//! Given the original tuple `(h, l, a_h^old, c, src, a_c^old, s_b)`, a
//! fixed pattern `str` of length `k`, and prover-provided new activators
//! `(a_h^new, a_c^new)`, the gadget proves that the new activators are
//! exactly the result of applying the anchored filter to the tuple:
//! - [`Direction::Prefix`] — kept string starts with `str` (`LIKE 'str%'`).
//! - [`Direction::Suffix`] — kept string ends with `str` (`LIKE '%str'`).
//!
//! Following the paper's unified formulation, both cases share the same
//! decomposition; the two knobs are the rotation direction of the anchored
//! selectors (`ρ_{ε·i}`) and the pattern indexing `π(i) = i` for prefix,
//! `k−1−i` for suffix.
//!
//! # Payload structure
//!
//! - [`CHAR_INPUT_LABEL`] — char-level table `{ c, src, s_b }` with activator `a_c^old`.
//! - [`STR_INPUT_LABEL`] — string-level table `{ ind, l }` with activator `a_h^old`.
//! - [`LENGTH_FILTERED_CHAR_LABEL`] — char-level table `{ a_c^{old'} }`, no activator.
//! - [`LENGTH_FILTERED_STR_LABEL`] — string-level table `{ a_h^{old'} }`, no activator.
//! - [`NEW_CHAR_LABEL`] — char-level table `{ a_c^new }`, no activator.
//! - [`NEW_STR_LABEL`] — string-level table `{ a_h^new }`, no activator.
//! - [`ROTATED_SELECTORS_LABEL`] — char-level table with `k - 1` columns
//!   holding the anchored selectors `s'^{(1)}, ..., s'^{(k-1)}` in insertion
//!   order, no activator. The 0-th selector `s'^{(0)}` is derived internally
//!   from the anchor (see below).
//! - [`SUFFIX_S_B_SHIFTED_LABEL`] — **suffix only** — char-level table
//!   `{ s_b_shifted }` with `s_b_shifted = ρ_{−1}(s_b)` (the "last character
//!   of each string" boundary), no activator. An extra `RotationCheck`
//!   child verifies this against the input `s_b`. Ignored for prefix.
//! - [`MISMATCH_LABEL`] — char-level table `{ s_n }`, no activator.
//!
//! # Decomposition
//!
//! Children (5 fixed + `k - 1` rotations + 1 optional suffix rotation):
//! 1. `BoolCheck` on `a_h^new`
//! 2. `BoolCheck` on `a_c^new`
//! 3. `BoolCheck` on `s_n`
//! 4. `ActivatorConsistencyCheck` on `(src, a_c^new, l, a_h^new)`
//! 5. `LengthFilteringCheck(k)` on `(src, l, a_h^old, a_c^old)`.
//! 6. `k − 1` `RotationCheck`s (`Direction::Right` for prefix,
//!    `Direction::Left` for suffix), each proving `s'^{(i)} = ρ_{ε·i}(s'^{(0)})`.
//! 7. (Suffix only) One extra `RotationCheck(Direction::Left, shift=1)`
//!    verifying `s_b_shifted = ρ_{−1}(s_b)`.
//! 8. `NoDup` (Bezout mode) on `src` activated by `s_n`.
//!
//! The anchor `s'^{(0)}` is derived virtually as `a_c^{old'} · s_b` for
//! prefix, and as `a_c^{old'} · s_b_shifted` for suffix.
//!
//! And these inline claims emitted from `prove`/`verify`:
//! - Zerocheck: `a_h^new · (1 - a_h^{old'})` (containment)
//! - Zerocheck: `(c - p) · a_c^new · Σ_{i=0}^{k-1} s'_b^{(i)}` (no false positives)
//! - NoZeroCheck: `(c - p, s_n)`  (marked slots really mismatch)
//! - Zerocheck: `s_n · (1 - Σ s'_b^{(i)})`  (marks are on anchored slots)
//! - Sumcheck: `Σ a_h^new = n_m`
//! - Sumcheck: `Σ s_n = n_nm`
//! - Sumcheck: `Σ a_h^{old'} = n_m + n_nm`
//!
//! The pattern column `p := Σ_{i=0}^{k-1} s'_b^{(i)} · str[i]` and the
//! selector sum `S := Σ s'_b^{(i)}` are derived inline.
//!
//! # A note on verifier-side `TrackedOracle` arithmetic
//!
//! The verifier-side arithmetic uses `self.log_size` verbatim (unlike the
//! prover, which combines sizes when multiplying), so any expression whose
//! left operand is a folded constant will inherit a `log_size` of 0.
//! Where an expression like `α · β` might have `α` constant, we
//! deliberately reorder to `β · α` so the size metadata is honest, matching
//! the workaround established by [`length_filtering_check`].
use std::marker::PhantomData;
use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_FIELD, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_ff::Zero;
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
                activator_consistency_check, bool as bool_check, length_filtering_check,
                nodup, rotation_check,
            },
        },
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub const CHAR_INPUT_LABEL: &str = "__char_input__";
pub const STR_INPUT_LABEL: &str = "__str_input__";
pub const LENGTH_FILTERED_CHAR_LABEL: &str = "__length_filtered_char__";
pub const LENGTH_FILTERED_STR_LABEL: &str = "__length_filtered_str__";
pub const NEW_CHAR_LABEL: &str = "__new_char__";
pub const NEW_STR_LABEL: &str = "__new_str__";
pub const ROTATED_SELECTORS_LABEL: &str = "__rotated_selectors__";
pub const SUFFIX_S_B_SHIFTED_LABEL: &str = "__suffix_s_b_shifted__";
pub const MISMATCH_LABEL: &str = "__mismatch__";

/// Direction of the anchored filter — corresponds to paper's ε ∈ {+1, −1}.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Prefix filter (`LIKE 'str%'`). Rotations are `Right`; pattern
    /// indexing is `π(i) = i`; anchor is `a_c^{old'} · s_b`.
    Prefix,
    /// Suffix filter (`LIKE '%str'`). Rotations are `Left`; pattern
    /// indexing is `π(i) = k − 1 − i`; anchor is `a_c^{old'} · ρ_{−1}(s_b)`.
    Suffix,
}

impl Direction {
    fn rotation_direction(self) -> rotation_check::Direction {
        match self {
            Direction::Prefix => rotation_check::Direction::Right,
            Direction::Suffix => rotation_check::Direction::Left,
        }
    }

    /// Effective pattern under the direction: `str` for prefix, reverse of
    /// `str` for suffix. Applied so downstream code can use the uniform
    /// formula `p = Σ s'^{(i)} · effective_pattern[i]`.
    fn effective_pattern<F: Clone>(self, pattern: &[F]) -> Vec<F> {
        match self {
            Direction::Prefix => pattern.to_vec(),
            Direction::Suffix => pattern.iter().rev().cloned().collect(),
        }
    }
}

/// Rebuild a `TrackedPoly` with the specified `log_size`. Used to sanitize
/// derived polys whose stored `log_size` may be `0` when their inputs fold
/// to constants — see [`length_filtering_check`].
fn resize_poly<B: SnarkBackend>(p: &TrackedPoly<B>, log_size: usize) -> TrackedPoly<B> {
    TrackedPoly::new(p.id_or_const(), log_size, p.tracker())
}

fn resize_oracle<B: SnarkBackend>(o: &TrackedOracle<B>, log_size: usize) -> TrackedOracle<B> {
    TrackedOracle::new(o.id_or_const(), o.tracker(), log_size)
}

fn bool_field() -> FieldRef {
    Arc::new(Field::new("data", DataType::Boolean, false))
}

fn src_field() -> FieldRef {
    Arc::new(Field::new("src", DataType::UInt64, false))
}

/// Composite gadget node for the Prefix/Suffix Check relation.
pub struct GadgetNode<B: SnarkBackend> {
    /// The fixed pattern of length `k` (as given by the caller — pattern
    /// reversal for suffix is done downstream via `effective_pattern`).
    pattern: Vec<B::F>,
    direction: Direction,
    /// `BoolCheck` children — one per boolean input activator.
    bool_ah_new: Arc<Node<B>>,
    bool_ac_new: Arc<Node<B>>,
    bool_sn: Arc<Node<B>>,
    activator_consistency: Arc<Node<B>>,
    length_filtering: Arc<Node<B>>,
    /// `k - 1` `RotationCheck` children, `rotation_checks[i]` proves
    /// `s'^{(i+1)} = ρ_{ε·(i+1)}(s'^{(0)})`.
    rotation_checks: Vec<Arc<Node<B>>>,
    /// Suffix-only: verifies `s_b_shifted = ρ_{−1}(s_b)`. `None` for prefix.
    s_b_shift_check: Option<Arc<Node<B>>>,
    nodup: Arc<Node<B>>,
    _phantom: PhantomData<B>,
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(pattern: Vec<B::F>, direction: Direction) -> Self {
        let k = pattern.len();
        assert!(k >= 1, "PrefixSuffixCheck: pattern length must be ≥ 1");
        let bool_ah_new = Arc::new(Node::<B>::Gadget(Arc::new(bool_check::GadgetNode::new())));
        let bool_ac_new = Arc::new(Node::<B>::Gadget(Arc::new(bool_check::GadgetNode::new())));
        let bool_sn = Arc::new(Node::<B>::Gadget(Arc::new(bool_check::GadgetNode::new())));
        let activator_consistency = Arc::new(Node::<B>::Gadget(Arc::new(
            activator_consistency_check::GadgetNode::new(),
        )));
        let length_filtering = Arc::new(Node::<B>::Gadget(Arc::new(
            length_filtering_check::GadgetNode::new(k as u64),
        )));
        let rot_direction = direction.rotation_direction();
        let rotation_checks: Vec<Arc<Node<B>>> = (1..k)
            .map(|i| {
                Arc::new(Node::<B>::Gadget(Arc::new(rotation_check::GadgetNode::new(
                    i,
                    rot_direction,
                ))))
            })
            .collect();
        let s_b_shift_check = match direction {
            Direction::Prefix => None,
            Direction::Suffix => Some(Arc::new(Node::<B>::Gadget(Arc::new(
                rotation_check::GadgetNode::new(1, rotation_check::Direction::Left),
            )))),
        };
        let nodup = Arc::new(Node::<B>::Gadget(Arc::new(nodup::GadgetNode::new(
            nodup::Mode::BezoutBased,
        ))));
        Self {
            pattern,
            direction,
            bool_ah_new,
            bool_ac_new,
            bool_sn,
            activator_consistency,
            length_filtering,
            rotation_checks,
            s_b_shift_check,
            nodup,
            _phantom: PhantomData,
        }
    }

    pub fn k(&self) -> usize {
        self.pattern.len()
    }

    pub fn direction(&self) -> Direction {
        self.direction
    }
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "PrefixSuffixCheck".to_string()
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
        let mut out = vec![
            self.bool_ah_new.clone(),
            self.bool_ac_new.clone(),
            self.bool_sn.clone(),
            self.activator_consistency.clone(),
            self.length_filtering.clone(),
        ];
        out.extend(self.rotation_checks.iter().cloned());
        if let Some(ref child) = self.s_b_shift_check {
            out.push(child.clone());
        }
        out.push(self.nodup.clone());
        out
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

        let char_domain = inputs.char_input.log_size();
        let str_domain = inputs.str_input.log_size();

        // --- children 1a & 1b: booleanity on a_h^new, a_c^new, s_n ---
        set_bool_payload_prover(&self.bool_ah_new, &inputs.a_h_new, virtualized_ir);
        set_bool_payload_prover(&self.bool_ac_new, &inputs.a_c_new, virtualized_ir);
        set_bool_payload_prover(&self.bool_sn, &inputs.s_n, virtualized_ir);

        // --- child 1c: activator consistency on (src, a_c^new, l, a_h^new) ---
        set_ac_payload_prover(
            &self.activator_consistency,
            &inputs,
            char_domain,
            str_domain,
            virtualized_ir,
        );

        // --- child 2: length filtering with threshold k ---
        set_length_filter_payload_prover(
            &self.length_filtering,
            &inputs,
            char_domain,
            str_domain,
            virtualized_ir,
        );

        // --- suffix-only child: s_b_shifted = ρ_{−1}(s_b) ---
        if let Some(ref shift_node) = self.s_b_shift_check {
            let s_b_shifted = inputs
                .s_b_shifted
                .clone()
                .expect("PrefixSuffixCheck: suffix direction requires SUFFIX_S_B_SHIFTED_LABEL");
            set_rotation_payload_prover(
                shift_node,
                &inputs.s_b,
                &s_b_shifted,
                char_domain,
                virtualized_ir,
            );
        }

        // --- rotation children: s'^{(i)} = ρ_{ε·i}(s'^{(0)}) ---
        // Anchor: s'^{(0)} := a_c^{old'} · s_b for prefix, or
        //         a_c^{old'} · s_b_shifted for suffix.
        // Put a_c^{old'} on the left when a candidate would otherwise be a
        // folded constant.
        let anchor_base = match self.direction {
            Direction::Prefix => inputs.s_b.clone(),
            Direction::Suffix => inputs
                .s_b_shifted
                .clone()
                .expect("PrefixSuffixCheck: suffix direction requires SUFFIX_S_B_SHIFTED_LABEL"),
        };
        let anchor = &inputs.a_c_old_prime * &anchor_base;
        let anchor = resize_poly(&anchor, char_domain);
        for (i, child) in self.rotation_checks.iter().enumerate() {
            let rotated = inputs.rotated_selectors[i].clone();
            set_rotation_payload_prover(child, &anchor, &rotated, char_domain, virtualized_ir);
        }

        set_nodup_payload_prover(&self.nodup, &inputs.src, &inputs.s_n, char_domain, virtualized_ir);

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
        let char_domain = inputs.char_input.log_size();
        let str_domain = inputs.str_input.log_size();

        set_bool_payload_verifier(&self.bool_ah_new, &inputs.a_h_new, virtualized_ir);
        set_bool_payload_verifier(&self.bool_ac_new, &inputs.a_c_new, virtualized_ir);
        set_bool_payload_verifier(&self.bool_sn, &inputs.s_n, virtualized_ir);

        set_ac_payload_verifier(
            &self.activator_consistency,
            &inputs,
            char_domain,
            str_domain,
            virtualized_ir,
        );

        set_length_filter_payload_verifier(
            &self.length_filtering,
            &inputs,
            char_domain,
            str_domain,
            virtualized_ir,
        );

        if let Some(ref shift_node) = self.s_b_shift_check {
            let s_b_shifted = inputs
                .s_b_shifted
                .clone()
                .expect("PrefixSuffixCheck: suffix direction requires SUFFIX_S_B_SHIFTED_LABEL");
            set_rotation_payload_verifier(
                shift_node,
                &inputs.s_b,
                &s_b_shifted,
                char_domain,
                virtualized_ir,
            );
        }

        let anchor_base = match self.direction {
            Direction::Prefix => inputs.s_b.clone(),
            Direction::Suffix => inputs
                .s_b_shifted
                .clone()
                .expect("PrefixSuffixCheck: suffix direction requires SUFFIX_S_B_SHIFTED_LABEL"),
        };
        let anchor = &inputs.a_c_old_prime * &anchor_base;
        let anchor = resize_oracle(&anchor, char_domain);
        for (i, child) in self.rotation_checks.iter().enumerate() {
            let rotated = inputs.rotated_selectors[i].clone();
            set_rotation_payload_verifier(child, &anchor, &rotated, char_domain, virtualized_ir);
        }

        set_nodup_payload_verifier(&self.nodup, &inputs.src, &inputs.s_n, char_domain, virtualized_ir);

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
        let char_domain = inputs.char_input.log_size();
        let str_domain = inputs.str_input.log_size();
        // Containment: a_h^new · (1 - a_h^{old'}) = 0.
        {
            let one_minus = inputs
                .a_h_old_prime
                .mul_scalar_poly(-B::F::from(1u64))
                .add_scalar_poly(B::F::from(1u64));
            let containment = &inputs.a_h_new * &one_minus;
            prover.add_mv_zerocheck_claim(containment.id())?;
        }

        // Anchor: s'^{(0)} := a_c^{old'} · anchor_base, where anchor_base
        // is s_b for prefix and s_b_shifted for suffix.
        let anchor_base = match self.direction {
            Direction::Prefix => inputs.s_b.clone(),
            Direction::Suffix => inputs
                .s_b_shifted
                .clone()
                .expect("PrefixSuffixCheck: suffix direction requires SUFFIX_S_B_SHIFTED_LABEL"),
        };
        let anchor = &inputs.a_c_old_prime * &anchor_base;
        let anchor = resize_poly(&anchor, char_domain);

        // S = Σ s'^{(i)}, p = Σ s'^{(i)} · effective_pattern[i]
        // where effective_pattern is str for prefix, reversed str for suffix.
        let effective_pattern = self.direction.effective_pattern(&self.pattern);
        let (s_sum, p_col) = build_selector_and_pattern_polys::<B>(
            &anchor,
            &inputs.rotated_selectors,
            &effective_pattern,
            char_domain,
        );

        // False-positive zerocheck: (c - p) · a_c^new · S = 0.
        {
            let c_minus_p = &inputs.c - &p_col;
            let c_minus_p = resize_poly(&c_minus_p, char_domain);
            let ac_new_times_s = &inputs.a_c_new * &s_sum;
            let ac_new_times_s = resize_poly(&ac_new_times_s, char_domain);
            let fp = &c_minus_p * &ac_new_times_s;
            prover.add_mv_zerocheck_claim(fp.id())?;
        }

        // Confinement zerocheck: s_n · (1 - S) = 0 — marks are on anchored slots.
        {
            let one_minus_s = s_sum
                .mul_scalar_poly(-B::F::from(1u64))
                .add_scalar_poly(B::F::from(1u64));
            let confinement = &inputs.s_n * &one_minus_s;
            let confinement = resize_poly(&confinement, char_domain);
            prover.add_mv_zerocheck_claim(confinement.id())?;
        }

        // False-negative NoZeroCheck. The paper wants "(c - p) ≠ 0 wherever
        // s_n = 1"; we encode that as `s_n·(c - p) + (1 - s_n)` being nonzero
        // everywhere — it collapses to (c - p) when s_n = 1 and to 1
        // otherwise.
        {
            let c_minus_p = &inputs.c - &p_col;
            let c_minus_p = resize_poly(&c_minus_p, char_domain);
            let one_minus_sn = inputs
                .s_n
                .mul_scalar_poly(-B::F::from(1u64))
                .add_scalar_poly(B::F::from(1u64));
            let masked_diff = &inputs.s_n * &c_minus_p;
            let masked_diff = resize_poly(&masked_diff, char_domain);
            let witness = &masked_diff + &one_minus_sn;
            let witness = resize_poly(&witness, char_domain);
            prover.add_mv_nozerocheck_claim(witness.id())?;
        }

        // Three count sumchecks: Σ a_h^new = n_m, Σ s_n = n_nm,
        // Σ a_h^{old'} = n_m + n_nm.
        let n_m = sum_of_field::<B>(&inputs.a_h_new);
        let n_nm = sum_of_field::<B>(&inputs.s_n);
        let n_eligible = n_m + n_nm;

        let n_m_key = miscellaneous_key(id, "n_m");
        let n_nm_key = miscellaneous_key(id, "n_nm");
        prover.add_miscellaneous_field_element(n_m_key, n_m)?;
        prover.add_miscellaneous_field_element(n_nm_key, n_nm)?;

        prover.add_mv_sumcheck_claim(inputs.a_h_new.id(), n_m)?;
        prover.add_mv_sumcheck_claim(inputs.s_n.id(), n_nm)?;
        prover.add_mv_sumcheck_claim(inputs.a_h_old_prime.id(), n_eligible)?;

        let _ = str_domain;
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
        let char_domain = inputs.char_input.log_size();
        let str_domain = inputs.str_input.log_size();
        {
            let one_minus = inputs
                .a_h_old_prime
                .mul_scalar_oracle(-B::F::from(1u64))
                .add_scalar_oracle(B::F::from(1u64));
            let containment = &inputs.a_h_new * &one_minus;
            verifier.add_mv_zerocheck_claim(containment.id());
        }

        let anchor_base = match self.direction {
            Direction::Prefix => inputs.s_b.clone(),
            Direction::Suffix => inputs
                .s_b_shifted
                .clone()
                .expect("PrefixSuffixCheck: suffix direction requires SUFFIX_S_B_SHIFTED_LABEL"),
        };
        let anchor = &inputs.a_c_old_prime * &anchor_base;
        let anchor = resize_oracle(&anchor, char_domain);

        let effective_pattern = self.direction.effective_pattern(&self.pattern);
        let (s_sum, p_col) = build_selector_and_pattern_oracles::<B>(
            &anchor,
            &inputs.rotated_selectors,
            &effective_pattern,
            char_domain,
        );

        {
            let c_minus_p = &inputs.c - &p_col;
            let c_minus_p = resize_oracle(&c_minus_p, char_domain);
            let ac_new_times_s = &inputs.a_c_new * &s_sum;
            let ac_new_times_s = resize_oracle(&ac_new_times_s, char_domain);
            let fp = &c_minus_p * &ac_new_times_s;
            verifier.add_mv_zerocheck_claim(fp.id());
        }

        {
            let one_minus_s = s_sum
                .mul_scalar_oracle(-B::F::from(1u64))
                .add_scalar_oracle(B::F::from(1u64));
            let confinement = &inputs.s_n * &one_minus_s;
            let confinement = resize_oracle(&confinement, char_domain);
            verifier.add_mv_zerocheck_claim(confinement.id());
        }

        {
            let c_minus_p = &inputs.c - &p_col;
            let c_minus_p = resize_oracle(&c_minus_p, char_domain);
            let one_minus_sn = inputs
                .s_n
                .mul_scalar_oracle(-B::F::from(1u64))
                .add_scalar_oracle(B::F::from(1u64));
            let masked_diff = &inputs.s_n * &c_minus_p;
            let masked_diff = resize_oracle(&masked_diff, char_domain);
            let witness = &masked_diff + &one_minus_sn;
            let witness = resize_oracle(&witness, char_domain);
            verifier.add_mv_nozerocheck_claim(witness.id());
        }

        let n_m_key = miscellaneous_key(id, "n_m");
        let n_nm_key = miscellaneous_key(id, "n_nm");
        let n_m = verifier.miscellaneous_field_element(&n_m_key)?;
        let n_nm = verifier.miscellaneous_field_element(&n_nm_key)?;
        let n_eligible = n_m + n_nm;

        verifier.add_mv_sumcheck_claim(inputs.a_h_new.id(), n_m);
        verifier.add_mv_sumcheck_claim(inputs.s_n.id(), n_nm);
        verifier.add_mv_sumcheck_claim(inputs.a_h_old_prime.id(), n_eligible);

        let _ = str_domain;
        Ok(())
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

// -------------- input extraction --------------

#[allow(dead_code)]
struct PayloadInputsProver<B: SnarkBackend> {
    char_input: TrackedTable<B>,
    str_input: TrackedTable<B>,
    c: TrackedPoly<B>,
    src: TrackedPoly<B>,
    s_b: TrackedPoly<B>,
    a_c_old: TrackedPoly<B>,
    a_h_old: TrackedPoly<B>,
    l: TrackedPoly<B>,
    ind: TrackedPoly<B>,
    a_c_old_prime: TrackedPoly<B>,
    a_h_old_prime: TrackedPoly<B>,
    a_c_new: TrackedPoly<B>,
    a_h_new: TrackedPoly<B>,
    rotated_selectors: Vec<TrackedPoly<B>>,
    /// Suffix only: `ρ_{−1}(s_b)`. `None` when the caller runs the
    /// prefix direction and doesn't provide the label.
    s_b_shifted: Option<TrackedPoly<B>>,
    s_n: TrackedPoly<B>,
}

#[allow(dead_code)]
struct PayloadInputsVerifier<B: SnarkBackend> {
    char_input: TrackedTableOracle<B>,
    str_input: TrackedTableOracle<B>,
    c: TrackedOracle<B>,
    src: TrackedOracle<B>,
    s_b: TrackedOracle<B>,
    a_c_old: TrackedOracle<B>,
    a_h_old: TrackedOracle<B>,
    l: TrackedOracle<B>,
    ind: TrackedOracle<B>,
    a_c_old_prime: TrackedOracle<B>,
    a_h_old_prime: TrackedOracle<B>,
    a_c_new: TrackedOracle<B>,
    a_h_new: TrackedOracle<B>,
    rotated_selectors: Vec<TrackedOracle<B>>,
    s_b_shifted: Option<TrackedOracle<B>>,
    s_n: TrackedOracle<B>,
}

fn extract_prover_inputs<B: SnarkBackend>(
    ir: &GadgetReadyIr<B>,
    id: NodeId,
) -> PayloadInputsProver<B> {
    let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
        panic!("PrefixSuffixCheck: missing gadget payload");
    };

    let char_input = payload
        .get(CHAR_INPUT_LABEL)
        .expect("missing CHAR_INPUT")
        .clone();
    let str_input = payload
        .get(STR_INPUT_LABEL)
        .expect("missing STR_INPUT")
        .clone();
    let length_filtered_char = payload
        .get(LENGTH_FILTERED_CHAR_LABEL)
        .expect("missing LENGTH_FILTERED_CHAR");
    let length_filtered_str = payload
        .get(LENGTH_FILTERED_STR_LABEL)
        .expect("missing LENGTH_FILTERED_STR");
    let new_char = payload
        .get(NEW_CHAR_LABEL)
        .expect("missing NEW_CHAR");
    let new_str = payload
        .get(NEW_STR_LABEL)
        .expect("missing NEW_STR");
    let rotated = payload
        .get(ROTATED_SELECTORS_LABEL)
        .expect("missing ROTATED_SELECTORS");
    let mismatch = payload
        .get(MISMATCH_LABEL)
        .expect("missing MISMATCH");

    let char_indices = char_input.data_tracked_polys_indices();
    assert_eq!(char_indices.len(), 3, "CHAR_INPUT expects 3 data columns: c, src, s_b");
    let c = char_input.tracked_col_by_ind(char_indices[0]).data_tracked_poly();
    let src = char_input.tracked_col_by_ind(char_indices[1]).data_tracked_poly();
    let s_b = char_input.tracked_col_by_ind(char_indices[2]).data_tracked_poly();
    let a_c_old = char_input
        .activator_tracked_poly()
        .expect("CHAR_INPUT must carry activator a_c^old");

    let str_indices = str_input.data_tracked_polys_indices();
    assert_eq!(str_indices.len(), 2, "STR_INPUT expects 2 data columns: ind, l");
    let ind = str_input.tracked_col_by_ind(str_indices[0]).data_tracked_poly();
    let l = str_input.tracked_col_by_ind(str_indices[1]).data_tracked_poly();
    let a_h_old = str_input
        .activator_tracked_poly()
        .expect("STR_INPUT must carry activator a_h^old");

    let a_c_old_prime = single_col_data(length_filtered_char, "LENGTH_FILTERED_CHAR");
    let a_h_old_prime = single_col_data(length_filtered_str, "LENGTH_FILTERED_STR");
    let a_c_new = single_col_data(new_char, "NEW_CHAR");
    let a_h_new = single_col_data(new_str, "NEW_STR");
    let s_n = single_col_data(mismatch, "MISMATCH");

    let rotated_selectors: Vec<TrackedPoly<B>> = rotated
        .data_tracked_polys_indices()
        .into_iter()
        .map(|idx| rotated.tracked_col_by_ind(idx).data_tracked_poly())
        .collect();

    let s_b_shifted = payload
        .get(SUFFIX_S_B_SHIFTED_LABEL)
        .map(|t| single_col_data(t, "SUFFIX_S_B_SHIFTED"));

    PayloadInputsProver {
        char_input,
        str_input,
        c,
        src,
        s_b,
        a_c_old,
        a_h_old,
        l,
        ind,
        a_c_old_prime,
        a_h_old_prime,
        a_c_new,
        a_h_new,
        rotated_selectors,
        s_b_shifted,
        s_n,
    }
}

fn extract_verifier_inputs<B: SnarkBackend>(
    ir: &VerifierGadgetReadyIr<B>,
    id: NodeId,
) -> PayloadInputsVerifier<B> {
    let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
        panic!("PrefixSuffixCheck: missing gadget payload");
    };

    let char_input = payload
        .get(CHAR_INPUT_LABEL)
        .expect("missing CHAR_INPUT")
        .clone();
    let str_input = payload
        .get(STR_INPUT_LABEL)
        .expect("missing STR_INPUT")
        .clone();
    let length_filtered_char = payload
        .get(LENGTH_FILTERED_CHAR_LABEL)
        .expect("missing LENGTH_FILTERED_CHAR");
    let length_filtered_str = payload
        .get(LENGTH_FILTERED_STR_LABEL)
        .expect("missing LENGTH_FILTERED_STR");
    let new_char = payload
        .get(NEW_CHAR_LABEL)
        .expect("missing NEW_CHAR");
    let new_str = payload
        .get(NEW_STR_LABEL)
        .expect("missing NEW_STR");
    let rotated = payload
        .get(ROTATED_SELECTORS_LABEL)
        .expect("missing ROTATED_SELECTORS");
    let mismatch = payload
        .get(MISMATCH_LABEL)
        .expect("missing MISMATCH");

    let char_indices = char_input.data_tracked_oracles_indices();
    assert_eq!(char_indices.len(), 3, "CHAR_INPUT expects 3 data columns: c, src, s_b");
    let c = char_input
        .tracked_col_oracle_by_ind(char_indices[0])
        .data_tracked_oracle();
    let src = char_input
        .tracked_col_oracle_by_ind(char_indices[1])
        .data_tracked_oracle();
    let s_b = char_input
        .tracked_col_oracle_by_ind(char_indices[2])
        .data_tracked_oracle();
    let a_c_old = char_input
        .activator_tracked_poly()
        .expect("CHAR_INPUT must carry activator a_c^old");

    let str_indices = str_input.data_tracked_oracles_indices();
    assert_eq!(str_indices.len(), 2, "STR_INPUT expects 2 data columns: ind, l");
    let ind = str_input
        .tracked_col_oracle_by_ind(str_indices[0])
        .data_tracked_oracle();
    let l = str_input
        .tracked_col_oracle_by_ind(str_indices[1])
        .data_tracked_oracle();
    let a_h_old = str_input
        .activator_tracked_poly()
        .expect("STR_INPUT must carry activator a_h^old");

    let a_c_old_prime = single_col_data_oracle(length_filtered_char, "LENGTH_FILTERED_CHAR");
    let a_h_old_prime = single_col_data_oracle(length_filtered_str, "LENGTH_FILTERED_STR");
    let a_c_new = single_col_data_oracle(new_char, "NEW_CHAR");
    let a_h_new = single_col_data_oracle(new_str, "NEW_STR");
    let s_n = single_col_data_oracle(mismatch, "MISMATCH");

    let rotated_selectors: Vec<TrackedOracle<B>> = rotated
        .data_tracked_oracles_indices()
        .into_iter()
        .map(|idx| rotated.tracked_col_oracle_by_ind(idx).data_tracked_oracle())
        .collect();

    let s_b_shifted = payload
        .get(SUFFIX_S_B_SHIFTED_LABEL)
        .map(|t| single_col_data_oracle(t, "SUFFIX_S_B_SHIFTED"));

    PayloadInputsVerifier {
        char_input,
        str_input,
        c,
        src,
        s_b,
        a_c_old,
        a_h_old,
        l,
        ind,
        a_c_old_prime,
        a_h_old_prime,
        a_c_new,
        a_h_new,
        rotated_selectors,
        s_b_shifted,
        s_n,
    }
}

fn single_col_data<B: SnarkBackend>(t: &TrackedTable<B>, label: &str) -> TrackedPoly<B> {
    let indices = t.data_tracked_polys_indices();
    assert_eq!(
        indices.len(),
        1,
        "PrefixSuffixCheck: {} expects exactly one data column",
        label
    );
    t.tracked_col_by_ind(indices[0]).data_tracked_poly()
}

fn single_col_data_oracle<B: SnarkBackend>(
    t: &TrackedTableOracle<B>,
    label: &str,
) -> TrackedOracle<B> {
    let indices = t.data_tracked_oracles_indices();
    assert_eq!(
        indices.len(),
        1,
        "PrefixSuffixCheck: {} expects exactly one data column",
        label
    );
    t.tracked_col_oracle_by_ind(indices[0]).data_tracked_oracle()
}

// -------------- child payload wiring --------------

fn set_bool_payload_prover<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    data: &TrackedPoly<B>,
    ir: &mut GadgetReadyIr<B>,
) {
    let mut polys = IndexMap::new();
    polys.insert(bool_field(), data.clone());
    let schema = Schema::new(vec![bool_field().as_ref().clone()]);
    let table = TrackedTable::new(Some(schema), polys, data.log_size());
    let mut payload = IndexMap::new();
    payload.insert(bool_check::TABLE_LABEL.to_string(), table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

fn set_bool_payload_verifier<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    data: &TrackedOracle<B>,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let mut oracles = IndexMap::new();
    oracles.insert(bool_field(), data.clone());
    let schema = Schema::new(vec![bool_field().as_ref().clone()]);
    let table = TrackedTableOracle::new(Some(schema), oracles, data.log_size());
    let mut payload = IndexMap::new();
    payload.insert(bool_check::TABLE_LABEL.to_string(), table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

fn set_ac_payload_prover<B: SnarkBackend>(
    ac_node: &Arc<Node<B>>,
    inputs: &PayloadInputsProver<B>,
    char_domain: usize,
    str_domain: usize,
    ir: &mut GadgetReadyIr<B>,
) {
    let src_f = src_field();
    let ind_f = Arc::new(Field::new("ind", DataType::UInt64, false));
    let l_f = Arc::new(Field::new("l", DataType::Int32, false));

    let mut lhs_polys = IndexMap::new();
    lhs_polys.insert(src_f.clone(), inputs.src.clone());
    lhs_polys.insert(ACTIVATOR_FIELD.clone(), inputs.a_c_new.clone());
    let lhs = TrackedTable::new(
        Some(Schema::new(vec![src_f.as_ref().clone()])),
        lhs_polys,
        char_domain,
    );

    let mut rhs_polys = IndexMap::new();
    rhs_polys.insert(ind_f.clone(), inputs.ind.clone());
    rhs_polys.insert(l_f.clone(), inputs.l.clone());
    rhs_polys.insert(ACTIVATOR_FIELD.clone(), inputs.a_h_new.clone());
    let rhs = TrackedTable::new(
        Some(Schema::new(vec![ind_f.as_ref().clone(), l_f.as_ref().clone()])),
        rhs_polys,
        str_domain,
    );

    let mut payload = IndexMap::new();
    payload.insert(activator_consistency_check::LHS_LABEL.to_string(), lhs);
    payload.insert(activator_consistency_check::RHS_LABEL.to_string(), rhs);
    ir.set_payload_for_node(ac_node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

fn set_ac_payload_verifier<B: SnarkBackend>(
    ac_node: &Arc<Node<B>>,
    inputs: &PayloadInputsVerifier<B>,
    char_domain: usize,
    str_domain: usize,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let src_f = src_field();
    let ind_f = Arc::new(Field::new("ind", DataType::UInt64, false));
    let l_f = Arc::new(Field::new("l", DataType::Int32, false));

    let mut lhs_oracles = IndexMap::new();
    lhs_oracles.insert(src_f.clone(), inputs.src.clone());
    lhs_oracles.insert(ACTIVATOR_FIELD.clone(), inputs.a_c_new.clone());
    let lhs = TrackedTableOracle::new(
        Some(Schema::new(vec![src_f.as_ref().clone()])),
        lhs_oracles,
        char_domain,
    );

    let mut rhs_oracles = IndexMap::new();
    rhs_oracles.insert(ind_f.clone(), inputs.ind.clone());
    rhs_oracles.insert(l_f.clone(), inputs.l.clone());
    rhs_oracles.insert(ACTIVATOR_FIELD.clone(), inputs.a_h_new.clone());
    let rhs = TrackedTableOracle::new(
        Some(Schema::new(vec![ind_f.as_ref().clone(), l_f.as_ref().clone()])),
        rhs_oracles,
        str_domain,
    );

    let mut payload = IndexMap::new();
    payload.insert(activator_consistency_check::LHS_LABEL.to_string(), lhs);
    payload.insert(activator_consistency_check::RHS_LABEL.to_string(), rhs);
    ir.set_payload_for_node(ac_node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

fn set_length_filter_payload_prover<B: SnarkBackend>(
    lf_node: &Arc<Node<B>>,
    inputs: &PayloadInputsProver<B>,
    char_domain: usize,
    str_domain: usize,
    ir: &mut GadgetReadyIr<B>,
) {
    let src_f = src_field();
    let ind_f = Arc::new(Field::new("ind", DataType::UInt64, false));
    let l_f = Arc::new(Field::new("l", DataType::Int32, false));

    let mut char_polys = IndexMap::new();
    char_polys.insert(src_f.clone(), inputs.src.clone());
    char_polys.insert(ACTIVATOR_FIELD.clone(), inputs.a_c_old.clone());
    let char_input = TrackedTable::new(
        Some(Schema::new(vec![src_f.as_ref().clone()])),
        char_polys,
        char_domain,
    );

    let mut str_polys = IndexMap::new();
    str_polys.insert(ind_f.clone(), inputs.ind.clone());
    str_polys.insert(l_f.clone(), inputs.l.clone());
    str_polys.insert(ACTIVATOR_FIELD.clone(), inputs.a_h_old.clone());
    let str_input = TrackedTable::new(
        Some(Schema::new(vec![ind_f.as_ref().clone(), l_f.as_ref().clone()])),
        str_polys,
        str_domain,
    );

    let mut char_filt_polys = IndexMap::new();
    char_filt_polys.insert(bool_field(), inputs.a_c_old_prime.clone());
    let char_filt = TrackedTable::new(
        Some(Schema::new(vec![bool_field().as_ref().clone()])),
        char_filt_polys,
        char_domain,
    );

    let mut str_filt_polys = IndexMap::new();
    str_filt_polys.insert(bool_field(), inputs.a_h_old_prime.clone());
    let str_filt = TrackedTable::new(
        Some(Schema::new(vec![bool_field().as_ref().clone()])),
        str_filt_polys,
        str_domain,
    );

    let mut payload = IndexMap::new();
    payload.insert(length_filtering_check::CHAR_INPUT_LABEL.to_string(), char_input);
    payload.insert(length_filtering_check::STR_INPUT_LABEL.to_string(), str_input);
    payload.insert(length_filtering_check::CHAR_FILTERED_LABEL.to_string(), char_filt);
    payload.insert(length_filtering_check::STR_FILTERED_LABEL.to_string(), str_filt);
    ir.set_payload_for_node(lf_node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

fn set_length_filter_payload_verifier<B: SnarkBackend>(
    lf_node: &Arc<Node<B>>,
    inputs: &PayloadInputsVerifier<B>,
    char_domain: usize,
    str_domain: usize,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let src_f = src_field();
    let ind_f = Arc::new(Field::new("ind", DataType::UInt64, false));
    let l_f = Arc::new(Field::new("l", DataType::Int32, false));

    let mut char_oracles = IndexMap::new();
    char_oracles.insert(src_f.clone(), inputs.src.clone());
    char_oracles.insert(ACTIVATOR_FIELD.clone(), inputs.a_c_old.clone());
    let char_input = TrackedTableOracle::new(
        Some(Schema::new(vec![src_f.as_ref().clone()])),
        char_oracles,
        char_domain,
    );

    let mut str_oracles = IndexMap::new();
    str_oracles.insert(ind_f.clone(), inputs.ind.clone());
    str_oracles.insert(l_f.clone(), inputs.l.clone());
    str_oracles.insert(ACTIVATOR_FIELD.clone(), inputs.a_h_old.clone());
    let str_input = TrackedTableOracle::new(
        Some(Schema::new(vec![ind_f.as_ref().clone(), l_f.as_ref().clone()])),
        str_oracles,
        str_domain,
    );

    let mut char_filt_oracles = IndexMap::new();
    char_filt_oracles.insert(bool_field(), inputs.a_c_old_prime.clone());
    let char_filt = TrackedTableOracle::new(
        Some(Schema::new(vec![bool_field().as_ref().clone()])),
        char_filt_oracles,
        char_domain,
    );

    let mut str_filt_oracles = IndexMap::new();
    str_filt_oracles.insert(bool_field(), inputs.a_h_old_prime.clone());
    let str_filt = TrackedTableOracle::new(
        Some(Schema::new(vec![bool_field().as_ref().clone()])),
        str_filt_oracles,
        str_domain,
    );

    let mut payload = IndexMap::new();
    payload.insert(length_filtering_check::CHAR_INPUT_LABEL.to_string(), char_input);
    payload.insert(length_filtering_check::STR_INPUT_LABEL.to_string(), str_input);
    payload.insert(length_filtering_check::CHAR_FILTERED_LABEL.to_string(), char_filt);
    payload.insert(length_filtering_check::STR_FILTERED_LABEL.to_string(), str_filt);
    ir.set_payload_for_node(lf_node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

fn set_rotation_payload_prover<B: SnarkBackend>(
    rot_node: &Arc<Node<B>>,
    left: &TrackedPoly<B>,
    right: &TrackedPoly<B>,
    log_size: usize,
    ir: &mut GadgetReadyIr<B>,
) {
    let f = Arc::new(Field::new("data", DataType::UInt64, false));

    let mut left_polys = IndexMap::new();
    left_polys.insert(f.clone(), left.clone());
    let left_table = TrackedTable::new(
        Some(Schema::new(vec![f.as_ref().clone()])),
        left_polys,
        log_size,
    );

    let mut right_polys = IndexMap::new();
    right_polys.insert(f.clone(), right.clone());
    let right_table = TrackedTable::new(
        Some(Schema::new(vec![f.as_ref().clone()])),
        right_polys,
        log_size,
    );

    let mut payload = IndexMap::new();
    payload.insert(rotation_check::LEFT_LABEL.to_string(), left_table);
    payload.insert(rotation_check::RIGHT_LABEL.to_string(), right_table);
    ir.set_payload_for_node(rot_node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

fn set_rotation_payload_verifier<B: SnarkBackend>(
    rot_node: &Arc<Node<B>>,
    left: &TrackedOracle<B>,
    right: &TrackedOracle<B>,
    log_size: usize,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let f = Arc::new(Field::new("data", DataType::UInt64, false));

    let mut left_oracles = IndexMap::new();
    left_oracles.insert(f.clone(), left.clone());
    let left_table = TrackedTableOracle::new(
        Some(Schema::new(vec![f.as_ref().clone()])),
        left_oracles,
        log_size,
    );

    let mut right_oracles = IndexMap::new();
    right_oracles.insert(f.clone(), right.clone());
    let right_table = TrackedTableOracle::new(
        Some(Schema::new(vec![f.as_ref().clone()])),
        right_oracles,
        log_size,
    );

    let mut payload = IndexMap::new();
    payload.insert(rotation_check::LEFT_LABEL.to_string(), left_table);
    payload.insert(rotation_check::RIGHT_LABEL.to_string(), right_table);
    ir.set_payload_for_node(rot_node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

#[allow(dead_code)]
fn set_nodup_payload_prover<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    src: &TrackedPoly<B>,
    s_n: &TrackedPoly<B>,
    log_size: usize,
    ir: &mut GadgetReadyIr<B>,
) {
    let src_f = src_field();
    let mut polys = IndexMap::new();
    polys.insert(src_f.clone(), src.clone());
    polys.insert(ACTIVATOR_FIELD.clone(), s_n.clone());
    let table = TrackedTable::new(
        Some(Schema::new(vec![src_f.as_ref().clone()])),
        polys,
        log_size,
    );
    let mut payload = IndexMap::new();
    payload.insert(nodup::INPUT_LABEL.to_string(), table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

#[allow(dead_code)]
fn set_nodup_payload_verifier<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    src: &TrackedOracle<B>,
    s_n: &TrackedOracle<B>,
    log_size: usize,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let src_f = src_field();
    let mut oracles = IndexMap::new();
    oracles.insert(src_f.clone(), src.clone());
    oracles.insert(ACTIVATOR_FIELD.clone(), s_n.clone());
    let table = TrackedTableOracle::new(
        Some(Schema::new(vec![src_f.as_ref().clone()])),
        oracles,
        log_size,
    );
    let mut payload = IndexMap::new();
    payload.insert(nodup::INPUT_LABEL.to_string(), table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

// -------------- helpers --------------

/// Build the selector-sum `S = Σ s'_b^{(i)}` and the pattern column
/// `p = Σ s'_b^{(i)} · str[i]` for indices `i = 0..k`, where
/// `s'_b^{(0)}` is the (virtual) `anchor` and `s'_b^{(1..k)}` are the
/// committed `rotated` selectors.
#[allow(dead_code)]
fn build_selector_and_pattern_polys<B: SnarkBackend>(
    anchor: &TrackedPoly<B>,
    rotated: &[TrackedPoly<B>],
    pattern: &[B::F],
    log_size: usize,
) -> (TrackedPoly<B>, TrackedPoly<B>) {
    assert_eq!(rotated.len(), pattern.len() - 1);
    let mut s_sum = anchor.clone();
    let mut p_col = anchor.mul_scalar_poly(pattern[0]);
    for (rot, ch) in rotated.iter().zip(pattern.iter().skip(1)) {
        s_sum = &s_sum + rot;
        let scaled = rot.mul_scalar_poly(*ch);
        p_col = &p_col + &scaled;
    }
    (resize_poly(&s_sum, log_size), resize_poly(&p_col, log_size))
}

#[allow(dead_code)]
fn build_selector_and_pattern_oracles<B: SnarkBackend>(
    anchor: &TrackedOracle<B>,
    rotated: &[TrackedOracle<B>],
    pattern: &[B::F],
    log_size: usize,
) -> (TrackedOracle<B>, TrackedOracle<B>) {
    assert_eq!(rotated.len(), pattern.len() - 1);
    let mut s_sum = anchor.clone();
    let mut p_col = anchor.mul_scalar_oracle(pattern[0]);
    for (rot, ch) in rotated.iter().zip(pattern.iter().skip(1)) {
        s_sum = &s_sum + rot;
        let scaled = rot.mul_scalar_oracle(*ch);
        p_col = &p_col + &scaled;
    }
    (
        resize_oracle(&s_sum, log_size),
        resize_oracle(&p_col, log_size),
    )
}

#[allow(dead_code)]
fn sum_of_field<B: SnarkBackend>(poly: &TrackedPoly<B>) -> B::F {
    poly.evaluations()
        .into_iter()
        .fold(B::F::zero(), |acc, v| acc + v)
}

#[allow(dead_code)]
fn miscellaneous_key(id: NodeId, tag: &str) -> String {
    format!("prefix_suffix_check_{id:?}_{tag}")
}

#[cfg(test)]
mod tests;
