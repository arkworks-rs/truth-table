use std::sync::Arc;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};
use arithmetic::{
    col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::One;
use ark_ff::Zero;
use ark_piop::errors::InputShapeError::InputLengthMismatch;
use ark_piop::verifier::errors::VerifierError::VerifierInputShapeError;
use ark_piop::verifier::structs::oracle::TrackedOracle;
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::SnarkResult,
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::ArgVerifier,
};
use ark_piop::{errors::InputShapeError::EmptyInput, verifier::errors::VerifierError};
use ark_piop::{errors::SnarkError, structs::TrackerID};
use indexmap::IndexMap;
use std::ops::Neg;
pub const FXS_LABEL: &str = "__fxs__";
pub const GXS_LABEL: &str = "__gxs__";
pub const MFXS_LABEL: &str = "__mfxs__";
pub const MGXS_LABEL: &str = "__mgxs__";
#[cfg(test)]
mod tests;

pub struct GadgetNode<B: SnarkBackend> {
    phantom: std::marker::PhantomData<B>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Keyed-Sumcheck".to_string()
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

    fn children(&self) -> Vec<Arc<Node<B>>> {
        Vec::new()
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
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
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
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        <Self as ProverNodeOps<B>>::initialize_gadget_plans(self, id, planned_ir)
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for Keyed-Sumcheck gadget node");
        };

        let (Some(fxs_table), Some(gxs_table)) = (
            payload.get(FXS_LABEL).cloned(),
            payload.get(GXS_LABEL).cloned(),
        ) else {
            panic!("Expected fxs and gxs inputs for Keyed-Sumcheck gadget");
        };

        let fxs = Self::tracked_cols_from_table(&fxs_table);
        let gxs = Self::tracked_cols_from_table(&gxs_table);

        let mfxs = Self::multiplicities_from_table(payload.get(MFXS_LABEL).cloned(), fxs.len());
        let mgxs = Self::multiplicities_from_table(payload.get(MGXS_LABEL).cloned(), gxs.len());

        // Get the challenge gamma for the check -- Gamma appears in the denominator of
        // the sum
        let gamma = prover.get_and_append_challenge(b"gamma")?;
        // iterate over vector elements and generate subclaims:
        for i in 0..fxs.len() {
            Self::prove_generate_subclaims(prover, fxs[i].clone(), mfxs[i].clone(), gamma)?;
        }

        for i in 0..gxs.len() {
            Self::prove_generate_subclaims(prover, gxs[i].clone(), mgxs[i].clone(), gamma)?;
        }
        Ok(())
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn verify(
        &self,
        verifier: &mut ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for Keyed-Sumcheck gadget node");
        };

        let (Some(fxs_table), Some(gxs_table)) = (
            payload.get(FXS_LABEL).cloned(),
            payload.get(GXS_LABEL).cloned(),
        ) else {
            panic!("Expected fxs and gxs inputs for Keyed-Sumcheck gadget");
        };

        let fxs = Self::tracked_cols_from_table_oracle(&fxs_table);
        let gxs = Self::tracked_cols_from_table_oracle(&gxs_table);

        let mfxs =
            Self::multiplicities_from_table_oracle(payload.get(MFXS_LABEL).cloned(), fxs.len());
        let mgxs =
            Self::multiplicities_from_table_oracle(payload.get(MGXS_LABEL).cloned(), gxs.len());

        // check input shapes are correct
        if fxs.is_empty() {
            return Err(SnarkError::VerifierError(VerifierInputShapeError(
                EmptyInput,
            )));
        }
        if fxs.len() != mfxs.len() {
            return Err(SnarkError::VerifierError(VerifierInputShapeError(
                InputLengthMismatch {
                    expected: fxs.len(),
                    actual: mfxs.len(),
                },
            )));
        }
        if gxs.is_empty() {
            return Err(SnarkError::VerifierError(VerifierInputShapeError(
                EmptyInput,
            )));
        }

        if gxs.len() != mgxs.len() {
            return Err(SnarkError::VerifierError(VerifierInputShapeError(
                InputLengthMismatch {
                    expected: gxs.len(),
                    actual: mgxs.len(),
                },
            )));
        }

        // create challenges and comitments in same fashion as prover
        // assumption is that proof inputs are already added to the tracker
        let gamma = verifier.get_and_append_challenge(b"gamma")?;
        // iterate over vector elements and generate subclaims:
        let max_nv_f = fxs.iter().map(|x| x.log_size()).max().unwrap();
        let max_nv_g = gxs.iter().map(|x| x.log_size()).max().unwrap();
        let max_nv = max_nv_f.max(max_nv_g);
        let mut lhs_v: B::F = B::F::zero();
        let mut rhs_v: B::F = B::F::zero();
        for i in 0..fxs.len() {
            let sum_claim_v =
                Self::verify_generate_subclaims(verifier, fxs[i].clone(), mfxs[i].clone(), gamma)?;
            let ratio = 2_usize.pow((max_nv - fxs[i].log_size()) as u32);
            let sum_claim_v_adj = sum_claim_v / B::F::from(ratio as u64);
            lhs_v += sum_claim_v_adj;
        }

        for i in 0..gxs.len() {
            let sum_claim_v =
                Self::verify_generate_subclaims(verifier, gxs[i].clone(), mgxs[i].clone(), gamma)?;
            let ratio = 2_usize.pow((max_nv - gxs[i].log_size()) as u32);
            let sum_claim_v_adj = sum_claim_v / B::F::from(ratio as u64);
            rhs_v += sum_claim_v_adj;
        }

        // check that the values of claimed sums are equal
        if lhs_v != rhs_v {
            let mut err_msg = "LHS and RHS have different sums".to_string();
            err_msg.push_str(&format!(" LHS: {}, RHS: {}", lhs_v, rhs_v));
            return Err(SnarkError::VerifierError(
                VerifierError::VerifierCheckFailed(err_msg),
            ));
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

impl<B: SnarkBackend> Default for GadgetNode<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }

    fn tracked_cols_from_table(table: &TrackedTable<B>) -> Vec<TrackedCol<B>> {
        table
            .data_tracked_polys_indices()
            .into_iter()
            .map(|idx| table.tracked_col_by_ind(idx))
            .collect()
    }

    fn multiplicities_from_table(
        table: Option<TrackedTable<B>>,
        expected_len: usize,
    ) -> Vec<Option<ark_piop::prover::structs::polynomial::TrackedPoly<B>>> {
        match table {
            Some(table) => {
                let data_indices = table.data_tracked_polys_indices();
                if data_indices.is_empty() && expected_len > 0 {
                    // Only system columns present; treat as missing multiplicities.
                    return vec![None; expected_len];
                }
                debug_assert_eq!(
                    data_indices.len(),
                    expected_len,
                    "Keyed-Sumcheck multiplicities must align with inputs."
                );
                data_indices
                    .into_iter()
                    .map(|idx| Some(table.tracked_col_by_ind(idx).data_tracked_poly()))
                    .collect()
            }
            None => vec![None; expected_len],
        }
    }

    fn tracked_cols_from_table_oracle(table: &TrackedTableOracle<B>) -> Vec<TrackedColOracle<B>> {
        table
            .data_tracked_oracles_indices()
            .into_iter()
            .map(|idx| table.tracked_col_oracle_by_ind(idx))
            .collect()
    }

    fn multiplicities_from_table_oracle(
        table: Option<TrackedTableOracle<B>>,
        expected_len: usize,
    ) -> Vec<Option<ark_piop::verifier::structs::oracle::TrackedOracle<B>>> {
        match table {
            Some(table) => {
                let data_indices = table.data_tracked_oracles_indices();
                if data_indices.is_empty() && expected_len > 0 {
                    // Only system columns present; treat as missing multiplicities.
                    return vec![None; expected_len];
                }
                debug_assert_eq!(
                    data_indices.len(),
                    expected_len,
                    "Keyed-Sumcheck multiplicities must align with inputs."
                );
                data_indices
                    .into_iter()
                    .map(|idx| Some(table.tracked_col_oracle_by_ind(idx).data_tracked_oracle()))
                    .collect()
            }
            None => vec![None; expected_len],
        }
    }
}

fn format_tracked_col_oracle_ids<B: SnarkBackend>(cols: &[TrackedColOracle<B>]) -> String {
    let mut out = String::from("[");
    for (i, col) in cols.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        match col.data_tracked_oracle().id_or_const() {
            either::Either::Left(id) => out.push_str(&format!("{:?}", id)),
            either::Either::Right(_c) => out.push_str("const"),
        }
    }
    out.push(']');
    out
}

fn format_tracked_oracle_opt_ids<B: SnarkBackend>(oracles: &[Option<TrackedOracle<B>>]) -> String {
    let mut out = String::from("[");
    for (i, oracle) in oracles.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        match oracle {
            Some(o) => match o.id_or_const() {
                either::Either::Left(id) => out.push_str(&format!("{:?}", id)),
                either::Either::Right(_c) => out.push_str("const"),
            },
            None => out.push_str("none"),
        }
    }
    out.push(']');
    out
}

fn format_table_oracle_fields<B: SnarkBackend>(table: &TrackedTableOracle<B>) -> Vec<String> {
    table
        .tracked_oracles_iter()
        .enumerate()
        .map(|(idx, (field, oracle))| {
            let qualifier = field
                .metadata()
                .get("tt.qualifier")
                .map(String::as_str)
                .unwrap_or("<none>");
            let id_str = match oracle.id_or_const() {
                either::Either::Left(id) => format!("{:?}", id),
                either::Either::Right(_c) => "const".to_string(),
            };
            format!(
                "idx={idx} name={} qual={qualifier} type={:?} id={id_str}",
                field.name(),
                field.data_type()
            )
        })
        .collect()
}

impl<B: SnarkBackend> GadgetNode<B> {
    fn prove_generate_subclaims(
        tracker: &mut ArgProver<B>,
        col: TrackedCol<B>,
        m: Option<TrackedPoly<B>>,
        gamma: B::F,
    ) -> SnarkResult<()> {
        let nv = col.log_size();
        // construct phat = 1/(col.p(x) - gamma), i.e. the denominator of the sum
        let p = col.data_tracked_poly();
        let mut p_evals = p.evaluations().to_vec();
        let mut p_minus_gamma: Vec<B::F> = p_evals.iter_mut().map(|x| *x - gamma).collect();
        let phat_evals = p_minus_gamma.as_mut_slice();
        ark_ff::fields::batch_inversion(phat_evals);
        let phat_mle = MLE::from_evaluations_slice(nv, phat_evals);

        // calculate what the final sum should be
        let mut v = B::F::zero();
        let phat = tracker.track_and_commit_mat_mv_poly(&phat_mle)?;
        let (sumcheck_challenge_poly, v) = match (col.activator_tracked_poly().as_ref(), m) {
            (Some(activator), Some(m)) => {
                let selector_evals = &activator.evaluations();
                let m_evals = m.evaluations();
                for i in 0..2_usize.pow(nv as u32) {
                    v += phat_mle[i] * m_evals[i] * selector_evals[i];
                }
                (&(&phat * &m) * activator, v)
            }
            (None, Some(m)) => {
                let m_evals = m.evaluations();
                for i in 0..2_usize.pow(nv as u32) {
                    v += phat_mle[i] * m_evals[i];
                }
                (&phat * &m, v)
            }
            (Some(activator), None) => {
                let selector_evals = &activator.evaluations();
                for i in 0..2_usize.pow(nv as u32) {
                    v += phat_mle[i] * selector_evals[i];
                }
                (&phat * activator, v)
            }
            (None, None) => {
                for i in 0..2_usize.pow(nv as u32) {
                    v += phat_mle[i];
                }
                (phat.clone(), v)
            }
        };

        // Create Zerocheck claim for proving phat(x) is created correctly,
        // i.e. ZeroCheck [(p(x)-gamma) * phat(x) - 1] = [(p * phat) - gamma * phat - 1]
        let phat_gamma = phat.clone() * gamma;
        let phat_check_poly = (&(&p * &phat) - &phat_gamma) + B::F::one().neg();
        // add the delayed prover claims to the tracker
        tracker.add_mv_sumcheck_claim(sumcheck_challenge_poly.id(), v)?;
        tracker.add_mv_zerocheck_claim(phat_check_poly.id())?;
        Ok(())
    }

    fn verify_generate_subclaims(
        tracker: &mut ArgVerifier<B>,
        col: TrackedColOracle<B>,
        m: Option<TrackedOracle<B>>,
        gamma: B::F,
    ) -> SnarkResult<B::F> {
        let p: TrackedOracle<B> = col.data_tracked_oracle();
        // get phat mat comm from proof and add it to the tracker
        let phat_id: TrackerID = tracker.peek_next_id();
        let phat = tracker.track_mv_com_by_id(phat_id)?;
        // make the virtual comms as prover does
        let sumcheck_challenge_comm = match (col.activator_tracked_oracle().as_ref(), m) {
            (Some(activator), Some(m)) => &(&phat * &m) * activator,
            (None, Some(m)) => &phat * &m,
            (Some(activator), None) => &phat * activator,
            (None, None) => phat.clone(),
        };

        let phat_gamma = phat.clone() * gamma;
        let phat_check_poly = (&(&p * &phat) - &phat_gamma) + B::F::one().neg();
        // add the delayed prover claims to the tracker
        let sum_claim_v = tracker.prover_claimed_sum(sumcheck_challenge_comm.id())?;
        tracker.add_sumcheck_claim(sumcheck_challenge_comm.id(), sum_claim_v);
        tracker.add_zerocheck_claim(phat_check_poly.id());

        Ok(sum_claim_v)
    }
}
