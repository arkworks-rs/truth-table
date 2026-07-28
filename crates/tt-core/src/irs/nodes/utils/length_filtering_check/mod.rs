//! A composite gadget node for paper §4.4 Length Filtering Check.
//!
//! Given `src, ind, l, ah, ac`, a threshold `k`, and prover-produced
//! filtered activators `a'h, a'c`, the gadget proves that
//!
//!   a'h[i] = 1  iff  ah[i] = 1 and l[i] >= k
//!
//! and `a'c` is the matching char-level activator (`a'c[c] = a'h[src[c]]`
//! on active chars).
//!
//! Payload structure (all four slots required):
//! - `CHAR_INPUT_LABEL` — char-level table `{ src }` with activator `ac`.
//! - `STR_INPUT_LABEL` — string-level table `{ ind, l }` with activator `ah`.
//!   `l` MUST carry an integer data type the Sign gadget understands
//!   (Int32 is the natural choice for typical string lengths).
//! - `CHAR_FILTERED_LABEL` — char-level table `{ a'c }`, no activator.
//! - `STR_FILTERED_LABEL` — string-level table `{ a'h }`, no activator.
//!
//! The threshold `k` is a gadget-node parameter, not a payload column.
//!
//! Decomposition (paper PIOP 4):
//! 1. (Activator validity)
//!    a. Booleanity Check on `a'h` and on `a'c` — two `BoolCheck` children.
//!    b. Activator Consistency Check on `(a'c, a'h)` — one
//!       `ActivatorConsistencyCheck` child.
//! 2. (Containment) Zerocheck on `a'h · (1 - ah)` — inline in `prove`.
//! 3. (False negative) Negative Sign Check on `(ah · (1 - a'h), l - k)`
//!    — one `SignNode(Sign::Negative)` child.
//! 4. (False positive) Non-Negative Sign Check on `(a'h, l - k)` — one
//!    `SignNode(Sign::NonNegative)` child.
//!
//! All five children are populated in `initialize_gadgets`. `prove` /
//! `verify` only emit the containment zerocheck; everything else is
//! discharged by the child gadgets, which the pipeline walker runs in
//! post-order.
use std::marker::PhantomData;
use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_FIELD, col::TrackedCol, col_oracle::TrackedColOracle,
    table::TrackedTable, table_oracle::TrackedTableOracle,
};
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
            utils::{activator_consistency_check, bool as bool_check, sign},
        },
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub const CHAR_INPUT_LABEL: &str = "__char_input__";
pub const STR_INPUT_LABEL: &str = "__str_input__";
pub const CHAR_FILTERED_LABEL: &str = "__char_filtered__";
pub const STR_FILTERED_LABEL: &str = "__str_filtered__";

/// Field type of the (l - k) column handed to the two sign-check
/// children. Int32 comfortably covers realistic string lengths.
/// Rebuild a `TrackedPoly` with the specified `log_size`. Used to
/// sanitize derived polys (like `l - k` or `ah · (1 - a'h)`) whose
/// stored `log_size` may be `0` when their inputs happen to fold to
/// constants — the underlying value still evaluates correctly on any
/// hypercube, but downstream tables assert on the size metadata.
fn resize_poly<B: SnarkBackend>(
    p: &TrackedPoly<B>,
    log_size: usize,
) -> TrackedPoly<B> {
    TrackedPoly::new(p.id_or_const(), log_size, p.tracker())
}

/// Verifier-side counterpart of [`resize_poly`].
fn resize_oracle<B: SnarkBackend>(
    o: &TrackedOracle<B>,
    log_size: usize,
) -> TrackedOracle<B> {
    TrackedOracle::new(o.id_or_const(), o.tracker(), log_size)
}

fn l_minus_k_field() -> FieldRef {
    Arc::new(Field::new("__l_minus_k__", DataType::Int32, false))
}

fn bool_field() -> FieldRef {
    // Non-system field name so BoolCheck treats the poly as data.
    Arc::new(Field::new("data", DataType::Boolean, false))
}

/// Composite gadget node for the Length Filtering relation.
pub struct GadgetNode<B: SnarkBackend> {
    threshold: u64,
    bool_ah_prime: Arc<Node<B>>,
    bool_ac_prime: Arc<Node<B>>,
    activator_consistency: Arc<Node<B>>,
    neg_sign: Arc<Node<B>>,
    nonneg_sign: Arc<Node<B>>,
    _phantom: PhantomData<B>,
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(threshold: u64) -> Self {
        let bool_ah_prime = Arc::new(Node::<B>::Gadget(Arc::new(bool_check::GadgetNode::new())));
        let bool_ac_prime = Arc::new(Node::<B>::Gadget(Arc::new(bool_check::GadgetNode::new())));
        let activator_consistency = Arc::new(Node::<B>::Gadget(Arc::new(
            activator_consistency_check::GadgetNode::new(),
        )));
        let neg_sign = Arc::new(Node::<B>::Gadget(Arc::new(sign::SignNode::new(
            sign::SignConfig::Uniform(sign::Sign::Negative),
        ))));
        let nonneg_sign = Arc::new(Node::<B>::Gadget(Arc::new(sign::SignNode::new(
            sign::SignConfig::Uniform(sign::Sign::NonNegative),
        ))));
        Self {
            threshold,
            bool_ah_prime,
            bool_ac_prime,
            activator_consistency,
            neg_sign,
            nonneg_sign,
            _phantom: PhantomData,
        }
    }

    pub fn threshold(&self) -> u64 {
        self.threshold
    }
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "LengthFilteringCheck".to_string()
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
            self.bool_ah_prime.clone(),
            self.bool_ac_prime.clone(),
            self.activator_consistency.clone(),
            self.neg_sign.clone(),
            self.nonneg_sign.clone(),
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
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let PayloadInputsProver {
            char_input,
            str_input,
            char_filtered,
            str_filtered,
        } = extract_prover_inputs(virtualized_ir, id);

        let src_col = char_input.tracked_col_by_ind(char_input.data_tracked_polys_indices()[0]);
        let ind_col = str_input.tracked_col_by_ind(str_input.data_tracked_polys_indices()[0]);
        let l_col = str_input.tracked_col_by_ind(str_input.data_tracked_polys_indices()[1]);
        let a_h_prime_col =
            char_filtered.tracked_col_by_ind(char_filtered.data_tracked_polys_indices()[0]);
        let _ = &a_h_prime_col; // name binding for clarity in comments below

        let a_c_prime = char_filtered
            .tracked_col_by_ind(char_filtered.data_tracked_polys_indices()[0])
            .data_tracked_poly();
        let a_h_prime = str_filtered
            .tracked_col_by_ind(str_filtered.data_tracked_polys_indices()[0])
            .data_tracked_poly();

        let l_poly = l_col.data_tracked_poly();
        let ah_poly = str_input
            .activator_tracked_poly()
            .expect("Length Filtering: string input must carry an activator (ah)");
        let _ac_poly = char_input
            .activator_tracked_poly()
            .expect("Length Filtering: char input must carry an activator (ac)");
        // Snapshot domain sizes now (before we start mutably borrowing
        // `virtualized_ir` to write child payloads).
        let str_domain = str_input.log_size();

        // Derived polys used by the sign-check children.
        let k = B::F::from(self.threshold);
        let l_minus_k = l_poly.sub_scalar_poly(k);
        // ah · (1 - a'h). Compute as (1 - a'h) · ah so a'h is on the
        // left; matches the verifier-side ordering (see verify_inner's
        // rationale about verifier `TrackedOracle` size metadata).
        let one_minus_ah_prime = a_h_prime
            .mul_scalar_poly(-B::F::from(1u64))
            .add_scalar_poly(B::F::from(1u64));
        let ah_minus_ah_prime: TrackedPoly<B> = &one_minus_ah_prime * &ah_poly;

        // 1a. Booleanity child payloads: single-column tables of {a'h}, {a'c}.
        set_bool_payload_prover(&self.bool_ah_prime, &a_h_prime, virtualized_ir);
        set_bool_payload_prover(&self.bool_ac_prime, &a_c_prime, virtualized_ir);

        // 1b. Activator Consistency child payload: LHS = char table with
        //     src activated by a'c; RHS = string table with (ind, l)
        //     activated by a'h.
        set_ac_payload_prover(
            &self.activator_consistency,
            &src_col,
            &a_c_prime,
            &ind_col,
            &l_col,
            &a_h_prime,
            virtualized_ir,
        );

        // 3. Negative sign check on (l - k) with activator ah · (1 - a'h).
        //    Sanitize derived polys to the string domain size before
        //    handing them to child tables.
        let l_minus_k_str = resize_poly(&l_minus_k, str_domain);
        let ah_minus_ah_prime_str = resize_poly(&ah_minus_ah_prime, str_domain);
        let a_h_prime_str = resize_poly(&a_h_prime, str_domain);
        set_sign_payload_prover(
            &self.neg_sign,
            &l_minus_k_str,
            &ah_minus_ah_prime_str,
            str_domain,
            virtualized_ir,
        );

        // 4. Non-negative sign check on (l - k) with activator a'h.
        set_sign_payload_prover(
            &self.nonneg_sign,
            &l_minus_k_str,
            &a_h_prime_str,
            str_domain,
            virtualized_ir,
        );

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
        let PayloadInputsVerifier {
            char_input,
            str_input,
            char_filtered,
            str_filtered,
        } = extract_verifier_inputs(virtualized_ir, id);

        let src_col = char_input.tracked_col_oracle_by_ind(char_input.data_tracked_oracles_indices()[0]);
        let ind_col = str_input.tracked_col_oracle_by_ind(str_input.data_tracked_oracles_indices()[0]);
        let l_col = str_input.tracked_col_oracle_by_ind(str_input.data_tracked_oracles_indices()[1]);
        let a_c_prime = char_filtered
            .tracked_col_oracle_by_ind(char_filtered.data_tracked_oracles_indices()[0])
            .data_tracked_oracle();
        let a_h_prime = str_filtered
            .tracked_col_oracle_by_ind(str_filtered.data_tracked_oracles_indices()[0])
            .data_tracked_oracle();

        let l_oracle = l_col.data_tracked_oracle();
        let ah_oracle = str_input
            .activator_tracked_poly()
            .expect("Length Filtering: string input must carry an activator (ah)");
        let _ac_oracle = char_input
            .activator_tracked_poly()
            .expect("Length Filtering: char input must carry an activator (ac)");
        let str_domain = str_input.log_size();

        let k = B::F::from(self.threshold);
        let l_minus_k = l_oracle.sub_scalar_oracle(k);
        // Compute ah * (1 - a'h) as (1 - a'h) * ah so a'h is on the left
        // and the result inherits its log_size. Verifier-side arithmetic
        // takes self.log_size verbatim (unlike the prover-side which
        // combines sizes), so putting a possibly-non-constant operand
        // first keeps the size metadata honest when the other side is a
        // folded constant.
        let one_minus_ah_prime = a_h_prime
            .mul_scalar_oracle(-B::F::from(1u64))
            .add_scalar_oracle(B::F::from(1u64));
        let ah_minus_ah_prime: TrackedOracle<B> = &one_minus_ah_prime * &ah_oracle;

        set_bool_payload_verifier(&self.bool_ah_prime, &a_h_prime, virtualized_ir);
        set_bool_payload_verifier(&self.bool_ac_prime, &a_c_prime, virtualized_ir);

        set_ac_payload_verifier(
            &self.activator_consistency,
            &src_col,
            &a_c_prime,
            &ind_col,
            &l_col,
            &a_h_prime,
            virtualized_ir,
        );

        let l_minus_k_str = resize_oracle(&l_minus_k, str_domain);
        let ah_minus_ah_prime_str = resize_oracle(&ah_minus_ah_prime, str_domain);
        let a_h_prime_str = resize_oracle(&a_h_prime, str_domain);
        set_sign_payload_verifier(
            &self.neg_sign,
            &l_minus_k_str,
            &ah_minus_ah_prime_str,
            str_domain,
            virtualized_ir,
        );

        set_sign_payload_verifier(
            &self.nonneg_sign,
            &l_minus_k_str,
            &a_h_prime_str,
            str_domain,
            virtualized_ir,
        );

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
        // Containment: a'h · (1 - ah) = 0. Every string kept must have
        // been active in the input.
        let PayloadInputsProver {
            str_input,
            str_filtered,
            ..
        } = extract_prover_inputs(gadget_ready_ir, id);
        let ah = str_input
            .activator_tracked_poly()
            .expect("Length Filtering: string input must carry an activator (ah)");
        let a_h_prime = str_filtered
            .tracked_col_by_ind(str_filtered.data_tracked_polys_indices()[0])
            .data_tracked_poly();
        // Compute a'h · (1 - ah) with a'h on the left — keeps log_size
        // metadata correct when `ah` is committed as a folded constant.
        let one_minus_ah = ah
            .mul_scalar_poly(-B::F::from(1u64))
            .add_scalar_poly(B::F::from(1u64));
        let containment = &a_h_prime * &one_minus_ah;
        prover.add_mv_zerocheck_claim(containment.id())?;
        Ok(())
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: NodeId,
    ) -> SnarkResult<()> {
        // The composed children each carry their own honest checks; the
        // containment relation is enforced by the zerocheck emitted in
        // `prove`. Nothing extra here.
        Ok(())
    }

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        let PayloadInputsVerifier {
            str_input,
            str_filtered,
            ..
        } = extract_verifier_inputs(gadget_ready_ir, id);
        let ah = str_input
            .activator_tracked_poly()
            .expect("Length Filtering: string input must carry an activator (ah)");
        let a_h_prime = str_filtered
            .tracked_col_oracle_by_ind(str_filtered.data_tracked_oracles_indices()[0])
            .data_tracked_oracle();
        // Mirror prover-side ordering: a'h * (1 - ah).
        let one_minus_ah = ah
            .mul_scalar_oracle(-B::F::from(1u64))
            .add_scalar_oracle(B::F::from(1u64));
        let containment = &a_h_prime * &one_minus_ah;
        verifier.add_mv_zerocheck_claim(containment.id());
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
    char_input: &'a TrackedTable<B>,
    str_input: &'a TrackedTable<B>,
    char_filtered: &'a TrackedTable<B>,
    str_filtered: &'a TrackedTable<B>,
}

struct PayloadInputsVerifier<'a, B: SnarkBackend> {
    char_input: &'a TrackedTableOracle<B>,
    str_input: &'a TrackedTableOracle<B>,
    char_filtered: &'a TrackedTableOracle<B>,
    str_filtered: &'a TrackedTableOracle<B>,
}

fn extract_prover_inputs<B: SnarkBackend>(
    ir: &GadgetReadyIr<B>,
    id: NodeId,
) -> PayloadInputsProver<'_, B> {
    let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
        panic!("LengthFilteringCheck: missing gadget payload");
    };
    PayloadInputsProver {
        char_input: payload.get(CHAR_INPUT_LABEL).expect("missing CHAR_INPUT"),
        str_input: payload.get(STR_INPUT_LABEL).expect("missing STR_INPUT"),
        char_filtered: payload.get(CHAR_FILTERED_LABEL).expect("missing CHAR_FILTERED"),
        str_filtered: payload.get(STR_FILTERED_LABEL).expect("missing STR_FILTERED"),
    }
}

fn extract_verifier_inputs<B: SnarkBackend>(
    ir: &VerifierGadgetReadyIr<B>,
    id: NodeId,
) -> PayloadInputsVerifier<'_, B> {
    let Some(PayloadStructure::GadgetPayload(payload)) = ir.payload_for_node(&id) else {
        panic!("LengthFilteringCheck: missing gadget payload");
    };
    PayloadInputsVerifier {
        char_input: payload.get(CHAR_INPUT_LABEL).expect("missing CHAR_INPUT"),
        str_input: payload.get(STR_INPUT_LABEL).expect("missing STR_INPUT"),
        char_filtered: payload.get(CHAR_FILTERED_LABEL).expect("missing CHAR_FILTERED"),
        str_filtered: payload.get(STR_FILTERED_LABEL).expect("missing STR_FILTERED"),
    }
}

fn set_bool_payload_prover<B: SnarkBackend>(
    bool_node: &Arc<Node<B>>,
    data: &TrackedPoly<B>,
    ir: &mut GadgetReadyIr<B>,
) {
    let mut polys = IndexMap::new();
    polys.insert(bool_field(), data.clone());
    let schema = Schema::new(vec![bool_field().as_ref().clone()]);
    let table = TrackedTable::new(Some(schema), polys, data.log_size());
    let mut payload = IndexMap::new();
    payload.insert(bool_check::TABLE_LABEL.to_string(), table);
    ir.set_payload_for_node(
        bool_node.id(),
        Some(PayloadStructure::GadgetPayload(payload)),
    );
}

fn set_bool_payload_verifier<B: SnarkBackend>(
    bool_node: &Arc<Node<B>>,
    data: &TrackedOracle<B>,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let mut oracles = IndexMap::new();
    oracles.insert(bool_field(), data.clone());
    let schema = Schema::new(vec![bool_field().as_ref().clone()]);
    let table = TrackedTableOracle::new(Some(schema), oracles, data.log_size());
    let mut payload = IndexMap::new();
    payload.insert(bool_check::TABLE_LABEL.to_string(), table);
    ir.set_payload_for_node(
        bool_node.id(),
        Some(PayloadStructure::GadgetPayload(payload)),
    );
}

#[allow(clippy::too_many_arguments)]
fn set_ac_payload_prover<B: SnarkBackend>(
    ac_node: &Arc<Node<B>>,
    src_col: &TrackedCol<B>,
    a_c_prime: &TrackedPoly<B>,
    ind_col: &TrackedCol<B>,
    l_col: &TrackedCol<B>,
    a_h_prime: &TrackedPoly<B>,
    ir: &mut GadgetReadyIr<B>,
) {
    let src_field = src_col.field_ref().expect("src must have a field ref");
    let ind_field = ind_col.field_ref().expect("ind must have a field ref");
    let l_field = l_col.field_ref().expect("l must have a field ref");

    // LHS: char table with src (as data), activator = a'c.
    // Use a'c's domain size (it's a caller-supplied filtered activator
    // with a well-defined log_size); src's log_size can be 0 if src
    // folds to a constant, which would be wrong for the table.
    let char_domain = a_c_prime.log_size().max(src_col.log_size());
    let mut lhs_polys = IndexMap::new();
    lhs_polys.insert(src_field.clone(), src_col.data_tracked_poly());
    lhs_polys.insert(ACTIVATOR_FIELD.clone(), a_c_prime.clone());
    let lhs_schema = Schema::new(vec![src_field.as_ref().clone()]);
    let lhs = TrackedTable::new(Some(lhs_schema), lhs_polys, char_domain);

    // RHS: string table with (ind, l) as data, activator = a'h.
    let str_domain = a_h_prime
        .log_size()
        .max(ind_col.log_size())
        .max(l_col.log_size());
    let mut rhs_polys = IndexMap::new();
    rhs_polys.insert(ind_field.clone(), ind_col.data_tracked_poly());
    rhs_polys.insert(l_field.clone(), l_col.data_tracked_poly());
    rhs_polys.insert(ACTIVATOR_FIELD.clone(), a_h_prime.clone());
    let rhs_schema = Schema::new(vec![ind_field.as_ref().clone(), l_field.as_ref().clone()]);
    let rhs = TrackedTable::new(Some(rhs_schema), rhs_polys, str_domain);

    let mut payload = IndexMap::new();
    payload.insert(activator_consistency_check::LHS_LABEL.to_string(), lhs);
    payload.insert(activator_consistency_check::RHS_LABEL.to_string(), rhs);
    ir.set_payload_for_node(ac_node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

#[allow(clippy::too_many_arguments)]
fn set_ac_payload_verifier<B: SnarkBackend>(
    ac_node: &Arc<Node<B>>,
    src_col: &TrackedColOracle<B>,
    a_c_prime: &TrackedOracle<B>,
    ind_col: &TrackedColOracle<B>,
    l_col: &TrackedColOracle<B>,
    a_h_prime: &TrackedOracle<B>,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let src_field = src_col.field_ref().expect("src must have a field ref");
    let ind_field = ind_col.field_ref().expect("ind must have a field ref");
    let l_field = l_col.field_ref().expect("l must have a field ref");

    let char_domain = a_c_prime.log_size().max(src_col.log_size());
    let mut lhs_oracles = IndexMap::new();
    lhs_oracles.insert(src_field.clone(), src_col.data_tracked_oracle());
    lhs_oracles.insert(ACTIVATOR_FIELD.clone(), a_c_prime.clone());
    let lhs_schema = Schema::new(vec![src_field.as_ref().clone()]);
    let lhs = TrackedTableOracle::new(Some(lhs_schema), lhs_oracles, char_domain);

    let str_domain = a_h_prime
        .log_size()
        .max(ind_col.log_size())
        .max(l_col.log_size());
    let mut rhs_oracles = IndexMap::new();
    rhs_oracles.insert(ind_field.clone(), ind_col.data_tracked_oracle());
    rhs_oracles.insert(l_field.clone(), l_col.data_tracked_oracle());
    rhs_oracles.insert(ACTIVATOR_FIELD.clone(), a_h_prime.clone());
    let rhs_schema = Schema::new(vec![ind_field.as_ref().clone(), l_field.as_ref().clone()]);
    let rhs = TrackedTableOracle::new(Some(rhs_schema), rhs_oracles, str_domain);

    let mut payload = IndexMap::new();
    payload.insert(activator_consistency_check::LHS_LABEL.to_string(), lhs);
    payload.insert(activator_consistency_check::RHS_LABEL.to_string(), rhs);
    ir.set_payload_for_node(ac_node.id(), Some(PayloadStructure::GadgetPayload(payload)));
}

fn set_sign_payload_prover<B: SnarkBackend>(
    sign_node: &Arc<Node<B>>,
    l_minus_k: &TrackedPoly<B>,
    activator: &TrackedPoly<B>,
    log_size: usize,
    ir: &mut GadgetReadyIr<B>,
) {
    let field = l_minus_k_field();
    let mut polys = IndexMap::new();
    polys.insert(field.clone(), l_minus_k.clone());
    polys.insert(ACTIVATOR_FIELD.clone(), activator.clone());
    let schema = Schema::new(vec![field.as_ref().clone()]);
    let table = TrackedTable::new(Some(schema), polys, log_size);
    let mut payload = IndexMap::new();
    payload.insert(sign::INPUT_LABEL.to_string(), table);
    ir.set_payload_for_node(
        sign_node.id(),
        Some(PayloadStructure::GadgetPayload(payload)),
    );
}

fn set_sign_payload_verifier<B: SnarkBackend>(
    sign_node: &Arc<Node<B>>,
    l_minus_k: &TrackedOracle<B>,
    activator: &TrackedOracle<B>,
    log_size: usize,
    ir: &mut VerifierGadgetReadyIr<B>,
) {
    let field = l_minus_k_field();
    let mut oracles = IndexMap::new();
    oracles.insert(field.clone(), l_minus_k.clone());
    oracles.insert(ACTIVATOR_FIELD.clone(), activator.clone());
    let schema = Schema::new(vec![field.as_ref().clone()]);
    let table = TrackedTableOracle::new(Some(schema), oracles, log_size);
    let mut payload = IndexMap::new();
    payload.insert(sign::INPUT_LABEL.to_string(), table);
    ir.set_payload_for_node(
        sign_node.id(),
        Some(PayloadStructure::GadgetPayload(payload)),
    );
}

#[cfg(test)]
mod tests;
