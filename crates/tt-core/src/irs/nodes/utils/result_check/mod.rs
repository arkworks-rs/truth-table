use std::{collections::HashMap, sync::Arc};

use arithmetic::{ACTIVATOR_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    prover::ArgProver,
    prover::structs::polynomial::{TrackedPoly, get_or_insert_shift_poly},
    verifier::ArgVerifier,
    verifier::structs::oracle::{TrackedOracle, get_or_insert_shift_oracle},
};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub const INPUT_LABEL: &str = "__input__";
pub const OUTPUT_LABEL: &str = "__output__";
/// Statistical-security margin required of ResultCheck's random projection and pole.
pub const RESULT_CHECK_SECURITY_BITS: usize = 128;
/// Largest field covered by ark-piop's documented 128-bit challenge-uniformity profile.
pub const RESULT_CHECK_MAX_CHALLENGE_FIELD_BITS: usize = 384;

/// Relation proved between the committed query result and the public result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResultCheckMode {
    /// Active rows agree as a multiset; their physical order is irrelevant.
    Bag,
    /// Active rows occupy the same prefix and agree at every physical rank.
    Ordered,
}

impl ResultCheckMode {
    fn digest_domain(self) -> &'static [u8] {
        match self {
            Self::Bag => b"truth-table/result-check/bag/v2",
            Self::Ordered => b"truth-table/result-check/ordered/v1",
        }
    }

    fn fold_challenge_label(self) -> &'static [u8] {
        match self {
            Self::Bag => b"result_check_fold",
            Self::Ordered => b"result_check_ordered_fold",
        }
    }

    fn index_challenge_label(self) -> Option<&'static [u8]> {
        match self {
            Self::Bag => None,
            Self::Ordered => Some(b"result_check_ordered_index"),
        }
    }

    fn pole_challenge_label(self) -> &'static [u8] {
        match self {
            Self::Bag => b"result_check_bag",
            Self::Ordered => b"result_check_ordered_pole",
        }
    }
}

/// Final-result gadget binding a verifier-owned public table to the proof.
pub struct GadgetNode<B: SnarkBackend> {
    mode: ResultCheckMode,
    _backend: std::marker::PhantomData<B>,
}

impl<B: SnarkBackend> Default for GadgetNode<B> {
    fn default() -> Self {
        Self::new(ResultCheckMode::Bag)
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(mode: ResultCheckMode) -> Self {
        Self {
            mode,
            _backend: std::marker::PhantomData,
        }
    }

    pub fn mode(&self) -> ResultCheckMode {
        self.mode
    }
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "ResultCheck".to_string()
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

    fn children(&self) -> Vec<Arc<Node<B>>> {
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
            return Err(result_error("gadget payload missing"));
        };
        let Some(t_table) = payload.get(INPUT_LABEL) else {
            return Err(result_error("internal result payload missing"));
        };
        let Some(res_table) = payload.get(OUTPUT_LABEL) else {
            return Err(result_error("public result payload missing"));
        };
        prove_result_check(prover, t_table, res_table, self.mode)
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
        let Some(t_table) = payload.get(INPUT_LABEL) else {
            return Ok(());
        };
        let Some(r_table) = payload.get(OUTPUT_LABEL) else {
            return Ok(());
        };
        let matches = match self.mode {
            ResultCheckMode::Bag => active_row_multiset(t_table)? == active_row_multiset(r_table)?,
            ResultCheckMode::Ordered => {
                has_contiguous_boolean_activator(t_table)?
                    && has_contiguous_boolean_activator(r_table)?
                    && active_row_sequence(t_table)? == active_row_sequence(r_table)?
            }
        };
        if matches { Ok(()) } else { Err(false_claim()) }
    }

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Err(result_error("required verifier payload missing"));
        };
        let Some(t_table) = payload.get(INPUT_LABEL) else {
            return Err(result_error("required verifier payload missing"));
        };
        let Some(r_table) = payload.get(OUTPUT_LABEL) else {
            return Err(result_error("required verifier payload missing"));
        };
        verify_result_check(verifier, t_table, r_table, self.mode).map_err(|err| {
            SnarkError::VerifierError(
                ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(format!(
                    "ResultCheck failed during final verifier checks: {err:?}"
                )),
            )
        })
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

/// Bind the internal result to the verifier's plaintext table.
///
/// The public rows themselves, not fresh prover-selected "result" commitments,
/// determine the right-hand side. [`ResultCheckMode::Bag`] proves multiset
/// equality and deliberately ignores row order. [`ResultCheckMode::Ordered`]
/// folds a canonical physical index into every row fingerprint. Its public
/// activator must be a contiguous prefix, so index-tagged multiset equality
/// forces the committed internal table to have the same active prefix and the
/// same row at each rank, even when the two tables have different capacities.
/// Ordered mode rejects nullable columns until validity bits are authenticated.
fn prove_result_check<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    t_table: &TrackedTable<B>,
    r_table: &TrackedTable<B>,
    mode: ResultCheckMode,
) -> SnarkResult<()> {
    let t_act = t_table
        .activator_tracked_poly()
        .ok_or_else(|| result_error("internal activator missing"))?;
    let r_act = r_table
        .activator_tracked_poly()
        .ok_or_else(|| result_error("public activator missing"))?;
    let t_cols: Vec<_> = t_table
        .data_tracked_polys_indices()
        .into_iter()
        .map(|idx| t_table.tracked_col_by_ind(idx).data_tracked_poly())
        .collect();
    let r_cols: Vec<_> = r_table
        .data_tracked_polys_indices()
        .into_iter()
        .map(|idx| r_table.tracked_col_by_ind(idx).data_tracked_poly())
        .collect();
    check_result_shape::<B>(
        t_table.log_size(),
        r_table.log_size(),
        t_cols.len(),
        r_cols.len(),
        mode,
    )?;
    validate_mode_schema(mode, t_table.schema_ref(), r_table.schema_ref())?;
    let public_active = r_act.evaluations();
    let public_data: Vec<_> = r_cols.iter().map(|col| col.evaluations()).collect();
    validate_public_activator(mode, &public_active)?;
    let digest = public_result_digest::<B::F>(mode, &public_active, &public_data)?;
    // The existing constant-commitment API transcript-binds these PUBLIC hash
    // limbs. No private row positions or activators are disclosed.
    for limb in digest {
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(0, vec![limb]))?;
    }
    let challenges: Vec<B::F> = (0..t_cols.len())
        .map(|_| prover.get_and_append_challenge(mode.fold_challenge_label()))
        .collect::<SnarkResult<_>>()?;
    let mut folded_t = if t_cols.is_empty() {
        t_act.mul_scalar_poly(B::F::zero())
    } else {
        fold_polys(&t_cols, &challenges)
    };
    let index_challenge = match mode.index_challenge_label() {
        Some(label) => {
            let challenge = prover.get_and_append_challenge(label)?;
            let index = get_or_insert_shift_poly(prover, t_table.log_size(), 0, true);
            folded_t += &index.mul_scalar_poly(challenge);
            Some(challenge)
        }
        None => None,
    };
    let gamma = prover.get_and_append_challenge(mode.pole_challenge_label())?;
    let target = public_result_sum(
        mode,
        &public_active,
        &public_data,
        &challenges,
        index_challenge,
        gamma,
    )?;
    let needs_boolean_check = match t_act.as_constant() {
        Some(value) if value.is_zero() => {
            // An all-inactive internal table contributes the known zero
            // log-derivative sum. Avoid materializing redundant constant-zero
            // inverse claims. The argument backend currently requires at least
            // one PCS-backed sumcheck claim, so add an independent
            // compatibility anchor on this otherwise local-only path.
            add_sumcheck_compatibility_anchor_prover(prover)?;
            return if target.is_zero() {
                Ok(())
            } else {
                Err(false_claim())
            };
        }
        Some(value) if value.is_one() => false,
        Some(_) => return Err(false_claim()),
        None => true,
    };
    if !needs_boolean_check && let Some(fingerprint) = folded_t.as_constant() {
        add_sumcheck_compatibility_anchor_prover(prover)?;
        let expected = constant_active_result_sum::<B>(fingerprint, gamma, t_table.log_size())?;
        return if target == expected {
            Ok(())
        } else {
            Err(false_claim())
        };
    }
    let denominator = folded_t - gamma;
    let mut inverses = denominator.evaluations();
    ark_ff::batch_inversion(&mut inverses);
    let inverse = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(t_table.log_size(), inverses))?;
    let inverse_check = &t_act * &((&denominator * &inverse) - B::F::one());
    let sum = &t_act * &inverse;
    if needs_boolean_check {
        let boolean_check = &t_act * &(t_act.clone() - B::F::one());
        prover.add_mv_zerocheck_claim(boolean_check.id())?;
    }
    prover.add_mv_zerocheck_claim(inverse_check.id())?;
    prover.add_mv_sumcheck_claim(sum.id(), target)?;
    Ok(())
}

fn verify_result_check<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    t_table: &TrackedTableOracle<B>,
    r_table: &TrackedTableOracle<B>,
    mode: ResultCheckMode,
) -> SnarkResult<()> {
    let t_act = t_table
        .activator_tracked_poly()
        .ok_or_else(|| result_error("internal activator missing"))?;
    let r_act = r_table
        .activator_tracked_poly()
        .ok_or_else(|| result_error("public activator missing"))?;
    let t_cols: Vec<_> = t_table
        .data_tracked_oracles_indices()
        .into_iter()
        .map(|idx| t_table.tracked_col_oracle_by_ind(idx).data_tracked_oracle())
        .collect();
    let r_cols: Vec<_> = r_table
        .data_tracked_oracles_indices()
        .into_iter()
        .map(|idx| r_table.tracked_col_oracle_by_ind(idx).data_tracked_oracle())
        .collect();
    check_result_shape::<B>(
        t_table.log_size(),
        r_table.log_size(),
        t_cols.len(),
        r_cols.len(),
        mode,
    )?;
    validate_mode_schema(mode, t_table.schema_ref(), r_table.schema_ref())?;
    // These queries are only to the locally arithmetized PUBLIC result.
    // A proof-owned commitment cannot substitute for an evaluable public oracle.
    let public_active = public_evaluations(&r_act, r_table.log_size())?;
    let public_data: Vec<_> = r_cols
        .iter()
        .map(|col| public_evaluations(col, r_table.log_size()))
        .collect::<SnarkResult<_>>()?;
    validate_public_activator(mode, &public_active)?;
    let digest = public_result_digest::<B::F>(mode, &public_active, &public_data)?;
    for expected in digest {
        let claimed = verifier.track_next_mv_com()?;
        if claimed.log_size() != 0 || claimed.as_constant() != Some(expected) {
            return Err(result_error("plaintext result is not transcript-bound"));
        }
    }
    let challenges: Vec<B::F> = (0..t_cols.len())
        .map(|_| verifier.get_and_append_challenge(mode.fold_challenge_label()))
        .collect::<SnarkResult<_>>()?;
    let mut folded_t = if t_cols.is_empty() {
        t_act.mul_scalar_oracle(B::F::zero())
    } else {
        fold_oracles(&t_cols, &challenges)
    };
    let index_challenge = match mode.index_challenge_label() {
        Some(label) => {
            let challenge = verifier.get_and_append_challenge(label)?;
            let index = get_or_insert_shift_oracle(verifier, t_table.log_size(), 0, true);
            folded_t += &index.mul_scalar_oracle(challenge);
            Some(challenge)
        }
        None => None,
    };
    let gamma = verifier.get_and_append_challenge(mode.pole_challenge_label())?;
    let target = public_result_sum(
        mode,
        &public_active,
        &public_data,
        &challenges,
        index_challenge,
        gamma,
    )?;
    let needs_boolean_check = match t_act.as_constant() {
        Some(value) if value.is_zero() => {
            add_sumcheck_compatibility_anchor_verifier(verifier)?;
            return if target.is_zero() {
                Ok(())
            } else {
                Err(result_error(
                    "empty internal result does not match the public result",
                ))
            };
        }
        Some(value) if value.is_one() => false,
        Some(_) => return Err(result_error("internal activator is not Boolean")),
        None => true,
    };
    if !needs_boolean_check && let Some(fingerprint) = folded_t.as_constant() {
        add_sumcheck_compatibility_anchor_verifier(verifier)?;
        let expected = constant_active_result_sum::<B>(fingerprint, gamma, t_table.log_size())?;
        return if target == expected {
            Ok(())
        } else {
            Err(result_error(
                "constant internal result does not match the public result",
            ))
        };
    }
    let denominator = folded_t - gamma;
    let inverse = verifier.track_next_mv_com()?;
    let inverse_check = &t_act * &((&denominator * &inverse) - B::F::one());
    let sum = &t_act * &inverse;
    if needs_boolean_check {
        let boolean_check = &t_act * &(t_act.clone() - B::F::one());
        verifier.add_mv_zerocheck_claim(boolean_check.id());
    }
    verifier.add_mv_zerocheck_claim(inverse_check.id());
    // The verifier computes this target itself; it never trusts a supplied sum.
    verifier.add_mv_sumcheck_claim(sum.id(), target);
    Ok(())
}

/// Add a semantically independent sumcheck required by the argument backend.
///
/// Degenerate empty or all-constant ResultCheck branches need no algebraic
/// witness after the verifier checks their log-derivative target directly.
/// ark-piop nevertheless currently requires a sumcheck with at least one PCS-
/// openable polynomial. The honest prover therefore commits to `[0, 1]` and
/// proves that its sum is one. A malicious prover may substitute any
/// nonconstant polynomial with the same sum, but this anchor is added after
/// and does not occur in the ResultCheck relation or any of its challenges, so
/// that freedom cannot affect the verified public-result statement.
fn add_sumcheck_compatibility_anchor_prover<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
) -> SnarkResult<()> {
    let anchor = prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
        1,
        vec![B::F::zero(), B::F::one()],
    ))?;
    prover.add_mv_sumcheck_claim(anchor.id(), B::F::one())
}

fn add_sumcheck_compatibility_anchor_verifier<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
) -> SnarkResult<()> {
    let anchor = verifier.track_next_mv_com()?;
    if anchor.log_size() != 1 || anchor.as_constant().is_some() {
        return Err(result_error("malformed compatibility anchor"));
    }
    verifier.add_mv_sumcheck_claim(anchor.id(), B::F::one());
    Ok(())
}

/// Log-derivative sum for an all-active table with one constant fingerprint.
fn constant_active_result_sum<B: SnarkBackend>(
    fingerprint: B::F,
    gamma: B::F,
    nv: usize,
) -> SnarkResult<B::F> {
    let count = B::F::from((1usize << nv) as u64);
    let inverse = (fingerprint - gamma)
        .inverse()
        .ok_or_else(|| result_error("result-check challenge hits the internal row"))?;
    Ok(count * inverse)
}

/// Bound both ResultCheck bad-event terms by 2^-128 and avoid wraparound.
///
/// If `k` is the larger table log-capacity, both capacities sum to at most
/// `2^(k+1)`. Accounting for tuple-projection and log-derivative/pole failure
/// contributes one further factor of two. Since a `b`-bit prime is at least
/// `2^(b-1)`, requiring `k + 128 + 2 < b` gives the desired conservative
/// margin. It also makes each 64-bit public digest limb injective in the field.
/// ark-piop's current 64-byte challenge derivation documents this statistical
/// profile only for fields below 2^384, so ResultCheck conservatively rejects
/// larger moduli rather than silently relying on an unproved sampling bound.
fn check_result_shape<B: SnarkBackend>(
    input_nv: usize,
    public_nv: usize,
    input_cols: usize,
    public_cols: usize,
    mode: ResultCheckMode,
) -> SnarkResult<()> {
    if input_cols != public_cols {
        return Err(result_error("result column count mismatch"));
    }
    if input_nv >= usize::BITS as usize || public_nv >= usize::BITS as usize {
        return Err(result_error("unsupported field or result capacity"));
    }
    if !has_result_check_security_margin(B::F::MODULUS_BIT_SIZE as usize, input_nv, public_nv) {
        return Err(result_error(
            "field/capacity is outside ResultCheck's documented 128-bit challenge profile",
        ));
    }
    if mode == ResultCheckMode::Ordered
        && !has_injective_ordered_index_encoding::<B::F>(input_nv, public_nv)
    {
        return Err(result_error(
            "ordered-result indices are not injectively representable in the field",
        ));
    }
    Ok(())
}

/// Ordered ResultCheck tags each row by its physical rank cast into the field.
///
/// A `k`-variable table has indices below `2^k`. The cast is injective when
/// `k` is smaller than the field modulus bit length. The separate `u64` bound
/// ensures the integer conversion itself cannot truncate. These conditions are
/// implied by ResultCheck's stronger statistical-security margin today, but
/// keeping the representation boundary explicit prevents that fact from being
/// lost if the security calculation is refactored later.
fn has_injective_ordered_index_encoding<F: PrimeField>(input_nv: usize, public_nv: usize) -> bool {
    let max_nv = input_nv.max(public_nv);
    max_nv < u64::BITS as usize && max_nv < F::MODULUS_BIT_SIZE as usize
}

fn has_result_check_security_margin(
    modulus_bits: usize,
    input_nv: usize,
    public_nv: usize,
) -> bool {
    modulus_bits <= RESULT_CHECK_MAX_CHALLENGE_FIELD_BITS
        && input_nv
            .max(public_nv)
            .checked_add(RESULT_CHECK_SECURITY_BITS)
            .and_then(|bits| bits.checked_add(2))
            .is_some_and(|required| required < modulus_bits)
}

/// Hash the full public statement before sampling fingerprints or a pole.
/// Binding only after those challenges would permit adaptive public results.
fn public_result_digest<F: PrimeField>(
    mode: ResultCheckMode,
    active: &[F],
    data: &[Vec<F>],
) -> SnarkResult<[F; 4]> {
    use ark_serialize::CanonicalSerialize;
    use sha2::{Digest, Sha256};
    let mut bytes = mode.digest_domain().to_vec();
    active.to_vec().serialize_compressed(&mut bytes)?;
    data.to_vec().serialize_compressed(&mut bytes)?;
    let digest = Sha256::digest(bytes);
    Ok(std::array::from_fn(|i| {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&digest[i * 8..(i + 1) * 8]);
        F::from(u64::from_le_bytes(limb))
    }))
}

/// Evaluate a verifier-owned public-result oracle at Boolean-hypercube points.
///
/// Production callers reach this function only through verifier TrackingPass,
/// which constructs local base oracles from the validated plaintext table. A
/// direct proof commitment is rejected defensively: otherwise a low-level
/// caller could label prover-chosen data as `OUTPUT` and make the purportedly
/// public side of the relation private. Manually assembled virtual-oracle
/// payloads are not a supported public-input API; provenance is guaranteed by
/// the sealed production preparation/tracking path.
fn public_evaluations<B: SnarkBackend>(
    oracle: &TrackedOracle<B>,
    nv: usize,
) -> SnarkResult<Vec<B::F>> {
    if oracle.as_constant().is_some() {
        return Err(result_error(
            "public result must use a verifier-owned evaluable oracle",
        ));
    }
    let tracker = oracle.tracker();
    if tracker.borrow().mv_commitment(oracle.id()).is_some() {
        return Err(result_error(
            "public result must not use a proof-owned commitment",
        ));
    }
    (0..1usize << nv)
        .map(|slot| {
            let point = (0..nv)
                .map(|bit| B::F::from(((slot >> bit) & 1) as u64))
                .collect();
            tracker.borrow().query_mv(oracle.id(), point)
        })
        .collect()
}

/// The log-derivative sum of the active public rows, with tuple fingerprints.
/// A challenge hitting an active row is rejected (negligible completeness error).
fn public_result_sum<F: PrimeField>(
    mode: ResultCheckMode,
    active: &[F],
    data: &[Vec<F>],
    challenges: &[F],
    index_challenge: Option<F>,
    gamma: F,
) -> SnarkResult<F> {
    if data.len() != challenges.len() || data.iter().any(|col| col.len() != active.len()) {
        return Err(result_error("malformed public result"));
    }
    validate_public_activator(mode, active)?;
    let expected_index_challenge = mode == ResultCheckMode::Ordered;
    if index_challenge.is_some() != expected_index_challenge {
        return Err(result_error("malformed ordered-result challenge set"));
    }
    let mut sum = F::zero();
    for (slot, activation) in active.iter().enumerate() {
        if activation.is_zero() {
            continue;
        }
        if *activation != F::one() {
            return Err(result_error("public activator is not Boolean"));
        }
        let mut folded: F = data
            .iter()
            .zip(challenges)
            .map(|(col, coeff)| col[slot] * coeff)
            .sum();
        if let Some(coeff) = index_challenge {
            folded += F::from(slot as u64) * coeff;
        }
        sum += (folded - gamma)
            .inverse()
            .ok_or_else(|| result_error("result-check challenge hits an active row"))?;
    }
    Ok(sum)
}

/// Validate the verifier-owned activation vector before using it as a target.
///
/// Bag mode permits any Boolean mask. Ordered mode deliberately chooses the
/// unique compact representation `[1, ..., 1, 0, ..., 0]`; together with the
/// index-tagged log-derivative argument this forces the committed internal
/// activator to select exactly the same physical ranks.
fn validate_public_activator<F: PrimeField>(
    mode: ResultCheckMode,
    active: &[F],
) -> SnarkResult<()> {
    let mut inactive_seen = false;
    for activation in active {
        if activation.is_zero() {
            inactive_seen = true;
        } else if *activation != F::one() {
            return Err(result_error("public activator is not Boolean"));
        } else if mode == ResultCheckMode::Ordered && inactive_seen {
            return Err(result_error(
                "ordered public activator is not a contiguous prefix",
            ));
        }
    }
    Ok(())
}

/// Ordered equality currently covers only schemas whose SQL values are fully
/// represented by their field elements. Nullable columns require authenticated
/// validity bits, which ResultCheck does not yet carry, so ordered mode fails
/// closed instead of silently proving equality of payload values alone.
fn validate_mode_schema(
    mode: ResultCheckMode,
    internal: Option<&datafusion::arrow::datatypes::Schema>,
    public: Option<&datafusion::arrow::datatypes::Schema>,
) -> SnarkResult<()> {
    if mode == ResultCheckMode::Bag {
        return Ok(());
    }
    let mut ordered_fields = Vec::new();
    for (side, schema) in [("internal", internal), ("public", public)] {
        let schema =
            schema.ok_or_else(|| result_error(&format!("{side} result schema missing")))?;
        let activators: Vec<_> = schema
            .fields()
            .iter()
            .filter(|field| field.name() == ACTIVATOR_COL_NAME)
            .collect();
        if activators.len() != 1
            || activators[0].data_type() != &datafusion::arrow::datatypes::DataType::Boolean
        {
            return Err(result_error(&format!(
                "ordered {side} result has a malformed activator schema"
            )));
        }
        let fields: Vec<_> = schema
            .fields()
            .iter()
            .filter(|field| field.name() != ACTIVATOR_COL_NAME)
            .collect();
        for (position, field) in fields.iter().enumerate() {
            if field.is_nullable() {
                return Err(result_error(&format!(
                    "ordered {side} result contains an unauthenticated nullable column"
                )));
            }
            if fields[..position]
                .iter()
                .any(|previous| previous.name() == field.name())
            {
                return Err(result_error(&format!(
                    "ordered {side} result contains duplicate column names"
                )));
            }
        }
        ordered_fields.push(fields);
    }
    let [internal_fields, public_fields] = ordered_fields.as_slice() else {
        unreachable!("the two ResultCheck schemas were collected above")
    };
    if internal_fields.len() != public_fields.len()
        || internal_fields
            .iter()
            .zip(public_fields)
            .any(|(left, right)| {
                left.name() != right.name() || left.data_type() != right.data_type()
            })
    {
        return Err(result_error(
            "ordered internal and public result schemas do not match",
        ));
    }
    Ok(())
}

fn result_error(message: &str) -> SnarkError {
    SnarkError::VerifierError(
        ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(format!(
            "ResultCheck: {message}"
        )),
    )
}

fn fold_polys<B: SnarkBackend>(polys: &[TrackedPoly<B>], challenges: &[B::F]) -> TrackedPoly<B> {
    debug_assert!(!polys.is_empty(), "fold_polys requires at least one poly");
    let mut folded = polys[0].mul_scalar_poly(challenges[0]);
    for (poly, &chall) in polys.iter().zip(challenges.iter()).skip(1) {
        folded += &poly.mul_scalar_poly(chall);
    }
    folded
}

fn fold_oracles<B: SnarkBackend>(
    oracles: &[TrackedOracle<B>],
    challenges: &[B::F],
) -> TrackedOracle<B> {
    debug_assert!(
        !oracles.is_empty(),
        "fold_oracles requires at least one oracle"
    );
    let mut folded = oracles[0].mul_scalar_oracle(challenges[0]);
    for (oracle, &chall) in oracles.iter().zip(challenges.iter()).skip(1) {
        folded += &oracle.mul_scalar_oracle(chall);
    }
    folded
}

fn active_positions<F: PrimeField>(evals: &[F]) -> Vec<usize> {
    evals
        .iter()
        .enumerate()
        .filter_map(|(idx, value)| (!value.is_zero()).then_some(idx))
        .collect()
}

fn tracked_row_key<B: SnarkBackend>(
    table: &TrackedTable<B>,
    row_idx: usize,
) -> ark_piop::errors::SnarkResult<String> {
    let schema = table
        .schema_ref()
        .ok_or_else(|| result_error("table schema missing"))?;
    let mut parts = Vec::new();
    for field in schema.fields() {
        if field.name() == ACTIVATOR_COL_NAME {
            continue;
        }
        let value = table
            .tracked_polys_iter()
            .find_map(|(candidate, poly)| {
                (candidate.name() == field.name()).then_some(poly.evaluations())
            })
            .ok_or_else(|| result_error("row field missing"))?;
        if row_idx >= value.len() {
            return Err(result_error("row field has malformed capacity"));
        }
        parts.push(format!("{:?}", value[row_idx]));
    }
    Ok(parts.join("|"))
}

fn active_row_multiset<B: SnarkBackend>(
    table: &TrackedTable<B>,
) -> ark_piop::errors::SnarkResult<HashMap<String, usize>> {
    let activator = table
        .activator_tracked_poly()
        .ok_or_else(|| result_error("table activator missing"))?
        .evaluations();
    let mut counts = HashMap::new();
    for row_idx in active_positions(&activator) {
        let key = tracked_row_key(table, row_idx)?;
        *counts.entry(key).or_insert(0) += 1;
    }
    Ok(counts)
}

fn active_row_sequence<B: SnarkBackend>(
    table: &TrackedTable<B>,
) -> ark_piop::errors::SnarkResult<Vec<String>> {
    let activator = table
        .activator_tracked_poly()
        .ok_or_else(|| result_error("table activator missing"))?
        .evaluations();
    active_positions(&activator)
        .into_iter()
        .map(|row_idx| tracked_row_key(table, row_idx))
        .collect()
}

fn has_contiguous_boolean_activator<B: SnarkBackend>(
    table: &TrackedTable<B>,
) -> ark_piop::errors::SnarkResult<bool> {
    let activator = table
        .activator_tracked_poly()
        .ok_or_else(|| result_error("table activator missing"))?
        .evaluations();
    let mut inactive_seen = false;
    for value in activator {
        if value.is_zero() {
            inactive_seen = true;
        } else if !value.is_one() || inactive_seen {
            return Ok(false);
        }
    }
    Ok(true)
}

fn false_claim() -> ark_piop::errors::SnarkError {
    ark_piop::errors::SnarkError::ProverError(
        ark_piop::prover::errors::ProverError::HonestProverError(
            ark_piop::prover::errors::HonestProverError::FalseClaim,
        ),
    )
}

#[cfg(test)]
mod tests;
