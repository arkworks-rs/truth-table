//! Domain-Preserving Update Check (paper §4.2.2, the "Full String Validity
//! Check"), B1 variant, for compaction.
//!
//! Compaction repacks a filtered table's active rows into a smaller hypercube
//! and re-emits every column, including a string column's char-domain side
//! segments (`__chars`, `__orig_ind`, `__int_ind`) that the LIKE gadget
//! reads. Its row-domain Permutation (see
//! [`crate::irs::nodes::utils::compaction`]) folds every row-domain data
//! column, so it already binds each new string's hash slots, `__length` and
//! `__fingerprint` to a source row, as a bijection. It does not see the
//! char-domain segments, which would otherwise be unconstrained witnesses.
//! This gadget binds them, keyed by the perm-bound hash; there is no `src`
//! provenance witness. Each character carries a tag `HASHP`, its string's
//! hash slots broadcast to the char level.
//!
//! 1. Data-Preserving Update Check on the new activators and length:
//!    `#{ c : orig-ind_new[c] = i, active } = a_new[i] · l_new[i]`, so no
//!    character of an active new string is dropped or invented.
//! 2. No-Duplicate Check (sort-based) on the committed offset column
//!    `orig-ind_new · 2^char_domain + int-ind_new` under `char-act_new`: the
//!    `(orig-ind, int-ind)` pairs of active new chars are distinct. A
//!    zerocheck binds the column to its formula. The offset is challenge-free
//!    and injective, so the prover can stage it at plan time
//!    ([`OFFSET_PLAN_HINT_LABEL`]) for the gadget's lex-sort; the verifier
//!    needs only the schema.
//! 3. Broadcast checks, one `LookupPIOP` per hash slot per side:
//!    `HASHP_k[c] = HASH_SLOT_k[orig-ind[c]]`. They run inline because the
//!    slot count is data-dependent (a short-string column inlines to one
//!    slot).
//! 4. Lookup `(HASHP_0.., char, int-ind)_new ⊑ (HASHP_0.., char, int-ind)_old`:
//!    each new char, with its within-word position, is a char of the old
//!    string with the same hash.
//!
//! Soundness: the perm makes every active new row's hash equal some old row's
//! hash. Steps 3 and 4 make each active new char a char of the old string
//! with that hash, at the same position; step 2 forbids position collisions;
//! step 1 forces exactly `length` of them. The hash is collision-resistant,
//! so the same hash means the same content, and the new character sequence
//! is the old one.

use crate::irs::nodes::utils::{resize_oracle, resize_poly, u64_field};
use std::marker::PhantomData;
use std::sync::Arc;

use crate::irs::nodes::utils::lookup::piop::{LookupPIOP, LookupProverInput, LookupVerifierInput};
use arithmetic::{
    ACTIVATOR_FIELD, col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_piop::{
    SnarkBackend, errors::SnarkResult, piop::PIOP, prover::structs::polynomial::TrackedPoly,
    verifier::structs::oracle::TrackedOracle,
};
use datafusion::arrow::datatypes::{FieldRef, Schema};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{
            IsGadgetNode, IsNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
            hints::HintDF,
            utils::{data_preserving_update_check, lookup, nodup},
        },
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

/// Old string-level table `{ idx, HASH_SLOT_0.., length }` under `a`. `idx`
/// is the old row's natural index.
pub const OLD_STR_LABEL: &str = "__old_str__";
/// Old char-level table `{ orig-ind, int-ind, char, HASHP_0.. }` under
/// `char-act`.
pub const OLD_CHAR_LABEL: &str = "__old_char__";
/// New string-level table `{ ind, HASH_SLOT_0.., length }` under `a`.
pub const NEW_STR_LABEL: &str = "__new_str__";
/// New char-level table `{ orig-ind, int-ind, char, HASHP_0.., offset }`
/// under `char-act`.
pub const NEW_CHAR_LABEL: &str = "__new_char__";

// Names of the data columns of the payload tables.
pub const IDX_COL: &str = "__dpuc_idx__";
pub const IND_COL: &str = "__dpuc_ind__";
pub const ORIG_IND_COL: &str = "__dpuc_orig_ind__";
pub const INT_IND_COL: &str = "__dpuc_int_ind__";
pub const CHAR_COL: &str = "__dpuc_char__";
pub const LENGTH_COL: &str = "__dpuc_length__";
/// Prefix of the row-domain hash-slot columns (the string's
/// collision-resistant id, bound by the perm); the slot index follows.
pub const HASH_SLOT_PREFIX: &str = "__dpuc_hash__";
/// Prefix of the char-domain broadcast hash-slot columns `HASHP_k`; the slot
/// index follows. These are the witnesses this gadget constrains.
pub const HASHP_SLOT_PREFIX: &str = "__dpuc_hashp__";

/// The committed offset `orig-ind·STRIDE + int-ind` with
/// `STRIDE = 2^char_domain`, fed to the no-dup and bound to its formula by a
/// zerocheck.
pub const OFFSET_COL: &str = "__dpuc_offset__";
/// Plan-time payload slot of this node where the compaction parent stages
/// the concrete offset column (prover only) for the sort-based no-dup
/// child's planner; see `initialize_gadget_plans`.
pub const OFFSET_PLAN_HINT_LABEL: &str = "__dpuc_offset_plan_hint__";

pub struct GadgetNode<B: SnarkBackend> {
    /// Step 1.
    dpuc: Arc<Node<B>>,
    /// Step 2.
    offset_nodup: Arc<Node<B>>,
    /// Step 4.
    char_lookup: Arc<Node<B>>,
    _phantom: PhantomData<B>,
}

impl<B: SnarkBackend> Default for GadgetNode<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new() -> Self {
        Self {
            dpuc: Arc::new(Node::<B>::Gadget(Arc::new(
                data_preserving_update_check::GadgetNode::new(),
            ))),
            // Sort-based: the offset column is challenge-free, so it can be
            // lex-sorted at plan time from the staged offset hint.
            offset_nodup: Arc::new(Node::<B>::Gadget(Arc::new(nodup::GadgetNode::new(
                nodup::Mode::SortBased,
            )))),
            char_lookup: Arc::new(Node::<B>::Gadget(Arc::new(lookup::GadgetNode::new()))),
            _phantom: PhantomData,
        }
    }
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "DomainPreservingUpdateCheck".to_string()
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
            self.dpuc.clone(),
            self.offset_nodup.clone(),
            self.char_lookup.clone(),
        ]
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
        prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            panic!("DomainPreservingUpdateCheck: missing gadget payload");
        };
        let new_str = payload.get(NEW_STR_LABEL).expect("missing NEW_STR").clone();
        let new_char = payload
            .get(NEW_CHAR_LABEL)
            .expect("missing NEW_CHAR")
            .clone();
        let old_char = payload
            .get(OLD_CHAR_LABEL)
            .expect("missing OLD_CHAR")
            .clone();
        let _ = prover;

        let str_domain = new_str.log_size();
        let char_domain = new_char.log_size();
        let old_char_domain = old_char.log_size();
        let a_new = new_str.activator_tracked_poly().expect("NEW_STR activator");
        let cact_new = new_char
            .activator_tracked_poly()
            .expect("NEW_CHAR activator");
        let cact_old = old_char
            .activator_tracked_poly()
            .expect("OLD_CHAR activator");

        // Step 1.
        set_dpuc_prover(
            &self.dpuc,
            &poly(&new_char, ORIG_IND_COL),
            &cact_new,
            &poly(&new_str, IND_COL),
            &poly(&new_str, LENGTH_COL),
            &a_new,
            char_domain,
            str_domain,
            virtualized_ir,
        );

        // Step 2. The offset is committed, not a virtual combination, so
        // that the no-dup gadget can open its input.
        set_nodup_prover(
            &self.offset_nodup,
            poly(&new_char, OFFSET_COL),
            &cact_new,
            char_domain,
            virtualized_ir,
        );

        // Step 4.
        let mut inc_cols: Vec<(FieldRef, TrackedPoly<B>)> = hashp_polys(&new_char);
        inc_cols.push((u64_field(CHAR_COL), poly(&new_char, CHAR_COL)));
        inc_cols.push((u64_field(INT_IND_COL), poly(&new_char, INT_IND_COL)));
        let mut sup_cols: Vec<(FieldRef, TrackedPoly<B>)> = hashp_polys(&old_char);
        sup_cols.push((u64_field(CHAR_COL), poly(&old_char, CHAR_COL)));
        sup_cols.push((u64_field(INT_IND_COL), poly(&old_char, INT_IND_COL)));
        set_lookup_prover(
            &self.char_lookup,
            inc_cols,
            &cact_new,
            char_domain,
            sup_cols,
            &cact_old,
            old_char_domain,
            virtualized_ir,
        );
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        // The sort-based no-dup lex-sorts its input at plan time. The
        // compaction parent, visited just before this node in the pre-order
        // pass, rebuilds the offset column from the compacted output and
        // leaves it under `OFFSET_PLAN_HINT_LABEL`. Without it, fall back to
        // the schema-only hint.
        let concrete = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.get(OFFSET_PLAN_HINT_LABEL).cloned(),
            _ => None,
        };
        match concrete {
            Some(hint) => set_offset_nodup_input_hint(&self.offset_nodup, planned_ir, hint),
            None => set_offset_nodup_plan_hint(&self.offset_nodup, planned_ir),
        }
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
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            panic!("DomainPreservingUpdateCheck: missing gadget payload");
        };
        let new_str = payload.get(NEW_STR_LABEL).expect("missing NEW_STR").clone();
        let new_char = payload
            .get(NEW_CHAR_LABEL)
            .expect("missing NEW_CHAR")
            .clone();
        let old_char = payload
            .get(OLD_CHAR_LABEL)
            .expect("missing OLD_CHAR")
            .clone();
        let _ = verifier;

        let str_domain = new_str.log_size();
        let char_domain = new_char.log_size();
        let old_char_domain = old_char.log_size();
        let a_new = new_str.activator_tracked_poly().expect("NEW_STR activator");
        let cact_new = new_char
            .activator_tracked_poly()
            .expect("NEW_CHAR activator");
        let cact_old = old_char
            .activator_tracked_poly()
            .expect("OLD_CHAR activator");

        set_dpuc_verifier(
            &self.dpuc,
            &oracle(&new_char, ORIG_IND_COL),
            &cact_new,
            &oracle(&new_str, IND_COL),
            &oracle(&new_str, LENGTH_COL),
            &a_new,
            char_domain,
            str_domain,
            virtualized_ir,
        );

        set_nodup_verifier(
            &self.offset_nodup,
            oracle(&new_char, OFFSET_COL),
            &cact_new,
            char_domain,
            virtualized_ir,
        );

        let mut inc_cols: Vec<(FieldRef, TrackedOracle<B>)> = hashp_oracles(&new_char);
        inc_cols.push((u64_field(CHAR_COL), oracle(&new_char, CHAR_COL)));
        inc_cols.push((u64_field(INT_IND_COL), oracle(&new_char, INT_IND_COL)));
        let mut sup_cols: Vec<(FieldRef, TrackedOracle<B>)> = hashp_oracles(&old_char);
        sup_cols.push((u64_field(CHAR_COL), oracle(&old_char, CHAR_COL)));
        sup_cols.push((u64_field(INT_IND_COL), oracle(&old_char, INT_IND_COL)));
        set_lookup_verifier(
            &self.char_lookup,
            inc_cols,
            &cact_new,
            char_domain,
            sup_cols,
            &cact_old,
            old_char_domain,
            virtualized_ir,
        );
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        set_offset_nodup_plan_hint(&self.offset_nodup, planned_ir);
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
        // Step 3: broadcast each hash slot to the char level, both sides.
        let Some(PayloadStructure::GadgetPayload(payload)) =
            gadget_ready_ir.payload_for_node(&id).cloned()
        else {
            panic!("DomainPreservingUpdateCheck: missing gadget payload at prove");
        };
        let new_str = payload.get(NEW_STR_LABEL).expect("NEW_STR");
        let new_char = payload.get(NEW_CHAR_LABEL).expect("NEW_CHAR");
        let old_str = payload.get(OLD_STR_LABEL).expect("OLD_STR");
        let old_char = payload.get(OLD_CHAR_LABEL).expect("OLD_CHAR");

        let nslots = hashp_polys(new_char).len();
        for k in 0..nslots {
            broadcast_slot_prover(
                prover,
                &poly(new_str, IND_COL),
                &poly(new_str, &format!("{HASH_SLOT_PREFIX}{k}")),
                // The super side spans all rows (no activator): the `ind`
                // keys stay distinct, and an active char may reference a row
                // that the row activator excludes (after a filter the char
                // and row activators need not agree). A larger super side
                // still pins each char to hash[ind].
                None,
                &poly(new_char, ORIG_IND_COL),
                &poly(new_char, &format!("{HASHP_SLOT_PREFIX}{k}")),
                new_char.activator_tracked_poly(),
            )?;
            broadcast_slot_prover(
                prover,
                &poly(old_str, IDX_COL),
                &poly(old_str, &format!("{HASH_SLOT_PREFIX}{k}")),
                None,
                &poly(old_char, ORIG_IND_COL),
                &poly(old_char, &format!("{HASHP_SLOT_PREFIX}{k}")),
                old_char.activator_tracked_poly(),
            )?;
        }

        // offset − orig-ind·STRIDE − int-ind = 0. It holds on padding rows
        // too (all three are 0), so no activator mask is needed.
        let stride = offset_stride::<B>(new_char.log_size());
        let diff = offset_binding_poly(new_char, stride);
        prover.add_mv_zerocheck_claim(diff.id())?;
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
        let Some(PayloadStructure::GadgetPayload(payload)) =
            gadget_ready_ir.payload_for_node(&id).cloned()
        else {
            panic!("DomainPreservingUpdateCheck: missing gadget payload at verify");
        };
        let new_str = payload.get(NEW_STR_LABEL).expect("NEW_STR");
        let new_char = payload.get(NEW_CHAR_LABEL).expect("NEW_CHAR");
        let old_str = payload.get(OLD_STR_LABEL).expect("OLD_STR");
        let old_char = payload.get(OLD_CHAR_LABEL).expect("OLD_CHAR");

        let nslots = hashp_oracles(new_char).len();
        for k in 0..nslots {
            broadcast_slot_verifier(
                verifier,
                &oracle(new_str, IND_COL),
                &oracle(new_str, &format!("{HASH_SLOT_PREFIX}{k}")),
                None,
                &oracle(new_char, ORIG_IND_COL),
                &oracle(new_char, &format!("{HASHP_SLOT_PREFIX}{k}")),
                new_char.activator_tracked_poly(),
            )?;
            broadcast_slot_verifier(
                verifier,
                &oracle(old_str, IDX_COL),
                &oracle(old_str, &format!("{HASH_SLOT_PREFIX}{k}")),
                None,
                &oracle(old_char, ORIG_IND_COL),
                &oracle(old_char, &format!("{HASHP_SLOT_PREFIX}{k}")),
                old_char.activator_tracked_poly(),
            )?;
        }

        let stride = offset_stride::<B>(new_char.log_size());
        let diff = offset_binding_oracle(new_char, stride);
        verifier.add_mv_zerocheck_claim(diff.id());
        Ok(())
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

/// `STRIDE = 2^char_domain` of the injective offset encoding
/// (`char_domain` is a log-size, always < 64).
fn offset_stride<B: SnarkBackend>(char_domain: usize) -> B::F {
    B::F::from(1u64 << char_domain)
}

/// `offset − orig-ind·STRIDE − int-ind`, which must be zero everywhere.
fn offset_binding_poly<B: SnarkBackend>(
    new_char: &TrackedTable<B>,
    stride: B::F,
) -> TrackedPoly<B> {
    let neg_stride = -stride;
    let neg_one = -B::F::from(1u64);
    let orig = poly(new_char, ORIG_IND_COL).mul_scalar_poly(neg_stride);
    let int = poly(new_char, INT_IND_COL).mul_scalar_poly(neg_one);
    &(&poly(new_char, OFFSET_COL) + &orig) + &int
}

fn offset_binding_oracle<B: SnarkBackend>(
    new_char: &TrackedTableOracle<B>,
    stride: B::F,
) -> TrackedOracle<B> {
    let neg_stride = -stride;
    let neg_one = -B::F::from(1u64);
    let orig = oracle(new_char, ORIG_IND_COL).mul_scalar_oracle(neg_stride);
    let int = oracle(new_char, INT_IND_COL).mul_scalar_oracle(neg_one);
    &(&oracle(new_char, OFFSET_COL) + &orig) + &int
}

fn poly<B: SnarkBackend>(t: &TrackedTable<B>, name: &str) -> TrackedPoly<B> {
    t.tracked_polys_iter()
        .find(|(f, _)| f.name() == name)
        .map(|(_, p)| p.clone())
        .unwrap_or_else(|| panic!("DPUC: column {name} missing (prover)"))
}

fn oracle<B: SnarkBackend>(t: &TrackedTableOracle<B>, name: &str) -> TrackedOracle<B> {
    t.tracked_oracles_iter()
        .find(|(f, _)| f.name() == name)
        .map(|(_, o)| o.clone())
        .unwrap_or_else(|| panic!("DPUC: column {name} missing (verifier)"))
}

/// The `HASHP_k` char-domain columns of `t`, ordered by slot index `k`.
fn hashp_polys<B: SnarkBackend>(t: &TrackedTable<B>) -> Vec<(FieldRef, TrackedPoly<B>)> {
    let mut out: Vec<(usize, FieldRef, TrackedPoly<B>)> = t
        .tracked_polys_iter()
        .filter_map(|(f, p)| {
            f.name()
                .strip_prefix(HASHP_SLOT_PREFIX)
                .and_then(|k| k.parse::<usize>().ok())
                .map(|k| (k, f.clone(), p.clone()))
        })
        .collect();
    out.sort_by_key(|(k, _, _)| *k);
    out.into_iter().map(|(_, f, p)| (f, p)).collect()
}

fn hashp_oracles<B: SnarkBackend>(t: &TrackedTableOracle<B>) -> Vec<(FieldRef, TrackedOracle<B>)> {
    let mut out: Vec<(usize, FieldRef, TrackedOracle<B>)> = t
        .tracked_oracles_iter()
        .filter_map(|(f, o)| {
            f.name()
                .strip_prefix(HASHP_SLOT_PREFIX)
                .and_then(|k| k.parse::<usize>().ok())
                .map(|k| (k, f.clone(), o.clone()))
        })
        .collect();
    out.sort_by_key(|(k, _, _)| *k);
    out.into_iter().map(|(_, f, o)| (f, o)).collect()
}

/// The broadcast check `x'[c] = x[src[c]]` as a lookup
/// `(src + r·x') ⊑ (ind + r·x)` with a fresh challenge `r`, as in
/// [`crate::irs::nodes::utils::broadcast_check`].
#[allow(clippy::too_many_arguments)]
fn broadcast_slot_prover<B: SnarkBackend>(
    prover: &mut ark_piop::prover::ArgProver<B>,
    ind: &TrackedPoly<B>,
    x: &TrackedPoly<B>,
    str_act: Option<TrackedPoly<B>>,
    src: &TrackedPoly<B>,
    x_prime: &TrackedPoly<B>,
    char_act: Option<TrackedPoly<B>>,
) -> SnarkResult<()> {
    let r = prover.get_and_append_challenge(b"dpuc_bcast_r")?;
    let looked_up = &src.clone() + &x_prime.mul_scalar_poly(r);
    let looked_up_col = TrackedCol::new(looked_up, char_act, Some(u64_field("__dpuc_bcast__")));
    let super_data = &ind.clone() + &x.mul_scalar_poly(r);
    let super_col = TrackedCol::new(super_data, str_act, Some(u64_field("__dpuc_bcast__")));
    LookupPIOP::<B>::prove(
        prover,
        LookupProverInput {
            included_cols: vec![looked_up_col],
            super_col,
        },
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn broadcast_slot_verifier<B: SnarkBackend>(
    verifier: &mut ark_piop::verifier::ArgVerifier<B>,
    ind: &TrackedOracle<B>,
    x: &TrackedOracle<B>,
    str_act: Option<TrackedOracle<B>>,
    src: &TrackedOracle<B>,
    x_prime: &TrackedOracle<B>,
    char_act: Option<TrackedOracle<B>>,
) -> SnarkResult<()> {
    let r = verifier.get_and_append_challenge(b"dpuc_bcast_r")?;
    let looked_up = &src.clone() + &x_prime.mul_scalar_oracle(r);
    let looked_up_col =
        TrackedColOracle::new(looked_up, char_act, Some(u64_field("__dpuc_bcast__")));
    let super_data = &ind.clone() + &x.mul_scalar_oracle(r);
    let super_col = TrackedColOracle::new(super_data, str_act, Some(u64_field("__dpuc_bcast__")));
    LookupPIOP::<B>::verify(
        verifier,
        LookupVerifierInput {
            included_tracked_col_oracles: vec![looked_up_col],
            super_tracked_col_oracle: super_col,
        },
    )?;
    Ok(())
}

/// Schema-only `INPUT_LABEL` hint for the offset no-dup child. The verifier's
/// planner needs no more (schema and materialization flags); for the prover
/// it is the fallback when no concrete column was staged.
fn set_offset_nodup_plan_hint<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
) {
    let offset_f = u64_field(OFFSET_COL);
    let act_f = ACTIVATOR_FIELD.clone();
    let df = crate::irs::nodes::hints::schema_only_df(vec![
        offset_f.as_ref().clone(),
        act_f.as_ref().clone(),
    ]);
    // Both fields virtual, as in the prover's concrete hint
    // (`compaction_dpuc::build_offset_plan_hint`): the offset is committed
    // at runtime, not by the tracking pass.
    let mut should_materialize = IndexMap::new();
    should_materialize.insert(offset_f, false);
    should_materialize.insert(act_f, false);
    set_offset_nodup_input_hint(node, planned_ir, HintDF::new(df, should_materialize));
}

fn set_offset_nodup_input_hint<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    hint: HintDF,
) {
    let mut payload = match planned_ir.payload_for_node(&node.id()).cloned() {
        Some(PayloadStructure::GadgetPayload(map)) => map,
        _ => IndexMap::new(),
    };
    payload.insert(nodup::INPUT_LABEL.to_string(), hint);
    planned_ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

#[allow(clippy::too_many_arguments)]
fn set_dpuc_prover<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    orig_ind: &TrackedPoly<B>,
    char_act: &TrackedPoly<B>,
    ind: &TrackedPoly<B>,
    l: &TrackedPoly<B>,
    a: &TrackedPoly<B>,
    char_domain: usize,
    str_domain: usize,
    ir: &mut GadgetReadyIr<B>,
) {
    let orig_f = u64_field(ORIG_IND_COL);
    let ind_f = u64_field(IND_COL);
    let l_f = u64_field(LENGTH_COL);
    let mut lhs_polys = IndexMap::new();
    lhs_polys.insert(orig_f.clone(), resize_poly(orig_ind, char_domain));
    lhs_polys.insert(ACTIVATOR_FIELD.clone(), resize_poly(char_act, char_domain));
    let lhs = TrackedTable::new(
        Some(Schema::new(vec![orig_f.as_ref().clone()])),
        lhs_polys,
        char_domain,
    );
    let mut rhs_polys = IndexMap::new();
    rhs_polys.insert(ind_f.clone(), resize_poly(ind, str_domain));
    rhs_polys.insert(l_f.clone(), resize_poly(l, str_domain));
    rhs_polys.insert(ACTIVATOR_FIELD.clone(), resize_poly(a, str_domain));
    let rhs = TrackedTable::new(
        Some(Schema::new(vec![
            ind_f.as_ref().clone(),
            l_f.as_ref().clone(),
        ])),
        rhs_polys,
        str_domain,
    );
    let mut payload = IndexMap::new();
    payload.insert(data_preserving_update_check::LHS_LABEL.to_string(), lhs);
    payload.insert(data_preserving_update_check::RHS_LABEL.to_string(), rhs);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

#[allow(clippy::too_many_arguments)]
fn set_dpuc_verifier<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    orig_ind: &TrackedOracle<B>,
    char_act: &TrackedOracle<B>,
    ind: &TrackedOracle<B>,
    l: &TrackedOracle<B>,
    a: &TrackedOracle<B>,
    char_domain: usize,
    str_domain: usize,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let orig_f = u64_field(ORIG_IND_COL);
    let ind_f = u64_field(IND_COL);
    let l_f = u64_field(LENGTH_COL);
    let mut lhs_oracles = IndexMap::new();
    lhs_oracles.insert(orig_f.clone(), resize_oracle(orig_ind, char_domain));
    lhs_oracles.insert(
        ACTIVATOR_FIELD.clone(),
        resize_oracle(char_act, char_domain),
    );
    let lhs = TrackedTableOracle::new(
        Some(Schema::new(vec![orig_f.as_ref().clone()])),
        lhs_oracles,
        char_domain,
    );
    let mut rhs_oracles = IndexMap::new();
    rhs_oracles.insert(ind_f.clone(), resize_oracle(ind, str_domain));
    rhs_oracles.insert(l_f.clone(), resize_oracle(l, str_domain));
    rhs_oracles.insert(ACTIVATOR_FIELD.clone(), resize_oracle(a, str_domain));
    let rhs = TrackedTableOracle::new(
        Some(Schema::new(vec![
            ind_f.as_ref().clone(),
            l_f.as_ref().clone(),
        ])),
        rhs_oracles,
        str_domain,
    );
    let mut payload = IndexMap::new();
    payload.insert(data_preserving_update_check::LHS_LABEL.to_string(), lhs);
    payload.insert(data_preserving_update_check::RHS_LABEL.to_string(), rhs);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

fn set_nodup_prover<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    data: TrackedPoly<B>,
    activator: &TrackedPoly<B>,
    domain: usize,
    ir: &mut GadgetReadyIr<B>,
) {
    let f = u64_field(OFFSET_COL);
    let mut polys = IndexMap::new();
    polys.insert(f.clone(), data);
    polys.insert(ACTIVATOR_FIELD.clone(), resize_poly(activator, domain));
    let table = TrackedTable::new(Some(Schema::new(vec![f.as_ref().clone()])), polys, domain);
    let mut payload = match ir.payload_for_node(&node.id()).cloned() {
        Some(PayloadStructure::GadgetPayload(map)) => map,
        _ => IndexMap::new(),
    };
    payload.insert(nodup::INPUT_LABEL.to_string(), table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

fn set_nodup_verifier<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    data: TrackedOracle<B>,
    activator: &TrackedOracle<B>,
    domain: usize,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let f = u64_field(OFFSET_COL);
    let mut oracles = IndexMap::new();
    oracles.insert(f.clone(), data);
    oracles.insert(ACTIVATOR_FIELD.clone(), resize_oracle(activator, domain));
    let table =
        TrackedTableOracle::new(Some(Schema::new(vec![f.as_ref().clone()])), oracles, domain);
    let mut payload = match ir.payload_for_node(&node.id()).cloned() {
        Some(PayloadStructure::GadgetPayload(map)) => map,
        _ => IndexMap::new(),
    };
    payload.insert(nodup::INPUT_LABEL.to_string(), table);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

#[allow(clippy::too_many_arguments)]
fn set_lookup_prover<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    included: Vec<(FieldRef, TrackedPoly<B>)>,
    included_act: &TrackedPoly<B>,
    included_domain: usize,
    super_cols: Vec<(FieldRef, TrackedPoly<B>)>,
    super_act: &TrackedPoly<B>,
    super_domain: usize,
    ir: &mut GadgetReadyIr<B>,
) {
    let inc = mk_data_table(included, included_act, included_domain);
    let sup = mk_data_table(super_cols, super_act, super_domain);
    let mut payload = IndexMap::new();
    payload.insert(lookup::INCLUDED_LABEL.to_string(), inc);
    payload.insert(lookup::SUPER_LABEL.to_string(), sup);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

#[allow(clippy::too_many_arguments)]
fn set_lookup_verifier<B: SnarkBackend>(
    node: &Arc<Node<B>>,
    included: Vec<(FieldRef, TrackedOracle<B>)>,
    included_act: &TrackedOracle<B>,
    included_domain: usize,
    super_cols: Vec<(FieldRef, TrackedOracle<B>)>,
    super_act: &TrackedOracle<B>,
    super_domain: usize,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let inc = mk_data_table_oracle(included, included_act, included_domain);
    let sup = mk_data_table_oracle(super_cols, super_act, super_domain);
    let mut payload = IndexMap::new();
    payload.insert(lookup::INCLUDED_LABEL.to_string(), inc);
    payload.insert(lookup::SUPER_LABEL.to_string(), sup);
    ir.set_payload_for_node(node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

fn mk_data_table<B: SnarkBackend>(
    cols: Vec<(FieldRef, TrackedPoly<B>)>,
    activator: &TrackedPoly<B>,
    domain: usize,
) -> TrackedTable<B> {
    let mut polys = IndexMap::new();
    let mut fields = Vec::new();
    for (f, p) in cols {
        fields.push(f.as_ref().clone());
        polys.insert(f, resize_poly(&p, domain));
    }
    polys.insert(ACTIVATOR_FIELD.clone(), resize_poly(activator, domain));
    TrackedTable::new(Some(Schema::new(fields)), polys, domain)
}

fn mk_data_table_oracle<B: SnarkBackend>(
    cols: Vec<(FieldRef, TrackedOracle<B>)>,
    activator: &TrackedOracle<B>,
    domain: usize,
) -> TrackedTableOracle<B> {
    let mut oracles = IndexMap::new();
    let mut fields = Vec::new();
    for (f, o) in cols {
        fields.push(f.as_ref().clone());
        oracles.insert(f, resize_oracle(&o, domain));
    }
    oracles.insert(ACTIVATOR_FIELD.clone(), resize_oracle(activator, domain));
    TrackedTableOracle::new(Some(Schema::new(fields)), oracles, domain)
}
