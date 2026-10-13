//! Length Filtering Check (paper §5.3, PIOP 5).
//!
//! Given `src, ind, l, ah, ac`, a threshold `k` and the prover's filtered
//! activators `a'h, a'c`, proves that
//!
//!   a'h[i] = 1  iff  ah[i] = 1 and l[i] >= k
//!
//! and that `a'c` is the matching char-level activator.
//!
//! 1. Activator validity: Data-Preserving Update Check on
//!    `(a'c, a'h, src, ind, l)`.
//! 2. Containment: zerocheck on `a'h · (1 - ah)`.
//! 3. False negatives: Negative Sign Check on `l - k` under `ah · (1 - a'h)`.
//! 4. False positives: Non-Negative Sign Check on `l - k` under `a'h`.
use crate::irs::nodes::utils::{resize_oracle, resize_poly};
use std::marker::PhantomData;
use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_FIELD, col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
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
            utils::{data_preserving_update_check, sign},
        },
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

/// `{ src }` under `ac`.
pub const CHAR_INPUT_LABEL: &str = "__char_input__";
/// `{ ind, l }` under `ah`. `l` must carry an integer type the Sign gadget
/// understands.
pub const STR_INPUT_LABEL: &str = "__str_input__";
/// `{ a'c }`.
pub const CHAR_FILTERED_LABEL: &str = "__char_filtered__";
/// `{ a'h }`.
pub const STR_FILTERED_LABEL: &str = "__str_filtered__";

/// The `l - k` column of the two sign checks. Int32 covers realistic string
/// lengths.
fn l_minus_k_field() -> FieldRef {
    Arc::new(Field::new("__l_minus_k__", DataType::Int32, false))
}

pub struct GadgetNode<B: SnarkBackend> {
    threshold: u64,
    data_preserving: Arc<Node<B>>,
    neg_sign: Arc<Node<B>>,
    nonneg_sign: Arc<Node<B>>,
    _phantom: PhantomData<B>,
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(threshold: u64) -> Self {
        let data_preserving = Arc::new(Node::<B>::Gadget(Arc::new(
            data_preserving_update_check::GadgetNode::new(),
        )));
        let neg_sign = Arc::new(Node::<B>::Gadget(Arc::new(sign::SignNode::new(
            sign::SignConfig::Uniform(sign::Sign::Negative),
        ))));
        let nonneg_sign = Arc::new(Node::<B>::Gadget(Arc::new(sign::SignNode::new(
            sign::SignConfig::Uniform(sign::Sign::NonNegative),
        ))));
        Self {
            threshold,
            data_preserving,
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
            self.data_preserving.clone(),
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
        let _ = &a_h_prime_col;

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
        let str_domain = str_input.log_size();

        let k = B::F::from(self.threshold);
        let l_minus_k = l_poly.sub_scalar_poly(k);
        // ah · (1 - a'h), with a'h on the left to match the verifier's
        // operand order (see the verifier's `initialize_gadgets`).
        let one_minus_ah_prime = a_h_prime
            .mul_scalar_poly(-B::F::from(1u64))
            .add_scalar_poly(B::F::from(1u64));
        let ah_minus_ah_prime: TrackedPoly<B> = &one_minus_ah_prime * &ah_poly;

        // Step 1.
        set_dpuc_payload_prover(
            &self.data_preserving,
            &src_col,
            &a_c_prime,
            &ind_col,
            &l_col,
            &a_h_prime,
            virtualized_ir,
        );

        // Step 3: negative sign check on l - k under ah · (1 - a'h).
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

        // Step 4: non-negative sign check on l - k under a'h.
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

        let src_col =
            char_input.tracked_col_oracle_by_ind(char_input.data_tracked_oracles_indices()[0]);
        let ind_col =
            str_input.tracked_col_oracle_by_ind(str_input.data_tracked_oracles_indices()[0]);
        let l_col =
            str_input.tracked_col_oracle_by_ind(str_input.data_tracked_oracles_indices()[1]);
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
        // ah · (1 - a'h) with a'h on the left. Verifier-side arithmetic takes
        // the left operand's log_size (the prover side combines both), and
        // `ah` may be a folded constant of log_size 0.
        let one_minus_ah_prime = a_h_prime
            .mul_scalar_oracle(-B::F::from(1u64))
            .add_scalar_oracle(B::F::from(1u64));
        let ah_minus_ah_prime: TrackedOracle<B> = &one_minus_ah_prime * &ah_oracle;

        set_dpuc_payload_verifier(
            &self.data_preserving,
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
        // Step 2: a'h · (1 - ah) = 0, i.e. every kept string was active.
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
        // a'h on the left keeps the log_size right when `ah` is a folded
        // constant.
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
        // The children carry their own honest checks.
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
        char_filtered: payload
            .get(CHAR_FILTERED_LABEL)
            .expect("missing CHAR_FILTERED"),
        str_filtered: payload
            .get(STR_FILTERED_LABEL)
            .expect("missing STR_FILTERED"),
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
        char_filtered: payload
            .get(CHAR_FILTERED_LABEL)
            .expect("missing CHAR_FILTERED"),
        str_filtered: payload
            .get(STR_FILTERED_LABEL)
            .expect("missing STR_FILTERED"),
    }
}

#[allow(clippy::too_many_arguments)]
fn set_dpuc_payload_prover<B: SnarkBackend>(
    dpuc_node: &Arc<Node<B>>,
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

    // The table takes a'c's log_size: src's can be 0 when src folds to a
    // constant.
    let char_domain = a_c_prime.log_size().max(src_col.log_size());
    let mut lhs_polys = IndexMap::new();
    lhs_polys.insert(src_field.clone(), src_col.data_tracked_poly());
    lhs_polys.insert(ACTIVATOR_FIELD.clone(), a_c_prime.clone());
    let lhs_schema = Schema::new(vec![src_field.as_ref().clone()]);
    let lhs = TrackedTable::new(Some(lhs_schema), lhs_polys, char_domain);

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
    payload.insert(data_preserving_update_check::LHS_LABEL.to_string(), lhs);
    payload.insert(data_preserving_update_check::RHS_LABEL.to_string(), rhs);
    ir.set_payload_for_node(
        dpuc_node.id(),
        Some(PayloadStructure::GadgetPayload(payload)),
    );
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
