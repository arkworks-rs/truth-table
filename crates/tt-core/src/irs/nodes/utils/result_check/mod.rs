use std::{collections::HashMap, sync::Arc};

use arithmetic::{
    ACTIVATOR_COL_NAME, col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    piop::PIOP,
    prover::ArgProver,
    prover::structs::polynomial::TrackedPoly,
    verifier::ArgVerifier,
    verifier::structs::oracle::TrackedOracle,
};
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

pub const INPUT_LABEL: &str = "__input__";
pub const OUTPUT_LABEL: &str = "__output__";

pub struct GadgetNode<B: SnarkBackend>(std::marker::PhantomData<B>);

impl<B: SnarkBackend> Default for GadgetNode<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new() -> Self {
        Self(std::marker::PhantomData)
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
            return Ok(());
        };
        let t_table = payload
            .get(INPUT_LABEL)
            .unwrap_or_else(|| panic!("ResultCheck gadget missing {}", INPUT_LABEL));
        let res_table = payload
            .get(OUTPUT_LABEL)
            .unwrap_or_else(|| panic!("ResultCheck gadget missing {}", OUTPUT_LABEL));
        prove_result_check(prover, t_table, res_table)
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
        println!("{}", t_table);
        let Some(r_table) = payload.get(OUTPUT_LABEL) else {
            return Ok(());
        };
        println!("{}", r_table);
        if active_row_multiset(t_table)? == active_row_multiset(r_table)? {
            Ok(())
        } else {
            Err(false_claim())
        }
    }

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
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
        verify_result_check(verifier, t_table, r_table).map_err(|err| {
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

/// Proves that the active rows of `t_table`, the query output the plan has
/// proven, are the same multiset as the rows of `r_table`, the result the
/// verifier holds in the clear.
///
/// The claimed result comes from the prover and is not otherwise in the
/// transcript, so it must be fixed before this check draws any challenge;
/// a prover that knew the fold challenges could otherwise pick different
/// rows that fold to the same values. The prover therefore commits the
/// result on its own domain first, and a zerocheck against the verifier's
/// copy ties each commitment to the claimed result. Only then are the fold
/// challenges drawn and the two multisets compared.
fn prove_result_check<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    t_table: &TrackedTable<B>,
    r_table: &TrackedTable<B>,
) -> SnarkResult<()> {
    let t_act = t_table
        .activator_tracked_poly()
        .expect("ResultCheck t_table activator missing");
    let r_act = r_table
        .activator_tracked_poly()
        .expect("ResultCheck r_table activator missing");
    let columns =
        match_columns(data_polys(t_table), data_polys(r_table)).ok_or_else(false_claim)?;

    let r_nv = r_table.log_size();
    let committed_act = commit_claimed_poly(prover, &r_act, r_nv)?;
    let mut t_data = Vec::with_capacity(columns.len());
    let mut r_data = Vec::with_capacity(columns.len());
    for (t_poly, r_poly) in &columns {
        t_data.push(t_poly.clone());
        r_data.push(commit_claimed_poly(prover, r_poly, r_nv)?);
    }

    let mut challenges = Vec::with_capacity(columns.len());
    for _ in 0..columns.len() {
        challenges.push(prover.get_and_append_challenge(b"result_check_fold")?);
    }
    // With no data columns the multisets are equal exactly when the active
    // row counts are, which comparing the activators themselves checks.
    let (t_rows, r_rows) = if columns.is_empty() {
        (t_act.clone(), committed_act.clone())
    } else {
        (
            fold_polys(&t_data, &challenges),
            fold_polys(&r_data, &challenges),
        )
    };
    PermPIOP::<B>::prove(
        prover,
        PermPIOPProverInput {
            left_col: TrackedCol::new(t_rows, Some(t_act), None),
            right_col: TrackedCol::new(r_rows, Some(committed_act), None),
        },
    )?;
    Ok(())
}

/// Commits `public`, a column of the claimed result, and adds the zerocheck
/// that binds the commitment to it.
fn commit_claimed_poly<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    public: &TrackedPoly<B>,
    nv: usize,
) -> SnarkResult<TrackedPoly<B>> {
    let committed = prover
        .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(nv, public.evaluations()))?;
    prover.add_mv_zerocheck_claim((&committed - public).id())?;
    Ok(committed)
}

fn data_polys<B: SnarkBackend>(table: &TrackedTable<B>) -> Vec<(String, TrackedPoly<B>)> {
    let polys = table.tracked_polys();
    table
        .data_tracked_polys_indices()
        .into_iter()
        .map(|idx| {
            let (field, poly) = polys
                .get_index(idx)
                .expect("ResultCheck column index out of bounds");
            (field.name().to_string(), poly.clone())
        })
        .collect()
}

/// Pairs each data column of the proven output with the claimed result's
/// column of the same name, in the output's column order. Returns `None`
/// unless both tables have exactly the same data columns.
fn match_columns<T>(t_data: Vec<(String, T)>, r_data: Vec<(String, T)>) -> Option<Vec<(T, T)>> {
    if t_data.len() != r_data.len() {
        return None;
    }
    let mut r_by_name: HashMap<String, T> = r_data.into_iter().collect();
    if r_by_name.len() != t_data.len() {
        return None;
    }
    t_data
        .into_iter()
        .map(|(name, t)| r_by_name.remove(&name).map(|r| (t, r)))
        .collect()
}

fn verify_result_check<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    t_table: &TrackedTableOracle<B>,
    r_table: &TrackedTableOracle<B>,
) -> SnarkResult<()> {
    let t_act = t_table
        .activator_tracked_poly()
        .expect("ResultCheck t_table activator missing");
    let r_act = r_table
        .activator_tracked_poly()
        .expect("ResultCheck r_table activator missing");
    let columns = match_columns(data_oracles(t_table), data_oracles(r_table)).ok_or_else(|| {
        check_failed("the claimed result's columns differ from the query output's".to_string())
    })?;

    // Mirror the prover: bind the claimed result before drawing challenges.
    let r_nv = r_table.log_size();
    let committed_act = bind_claimed_oracle(verifier, &r_act, r_nv)?;
    let mut t_data = Vec::with_capacity(columns.len());
    let mut r_data = Vec::with_capacity(columns.len());
    for (t_oracle, r_oracle) in &columns {
        t_data.push(t_oracle.clone());
        r_data.push(bind_claimed_oracle(verifier, r_oracle, r_nv)?);
    }

    let mut challenges = Vec::with_capacity(columns.len());
    for _ in 0..columns.len() {
        challenges.push(verifier.get_and_append_challenge(b"result_check_fold")?);
    }
    let (t_rows, r_rows) = if columns.is_empty() {
        (t_act.clone(), committed_act.clone())
    } else {
        (
            fold_oracles(&t_data, &challenges),
            fold_oracles(&r_data, &challenges),
        )
    };
    PermPIOP::<B>::verify(
        verifier,
        PermPIOPVerifierInput {
            left_tracked_col_oracle: TrackedColOracle::new(t_rows, Some(t_act), None),
            right_tracked_col_oracle: TrackedColOracle::new(r_rows, Some(committed_act), None),
        },
    )?;
    Ok(())
}

/// Takes the prover's commitment to `public`, a column of the claimed result,
/// and adds the zerocheck that binds it to the verifier's own copy.
fn bind_claimed_oracle<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    public: &TrackedOracle<B>,
    nv: usize,
) -> SnarkResult<TrackedOracle<B>> {
    let committed = verifier.track_next_mv_com()?;
    if committed.log_size() != nv {
        return Err(check_failed(format!(
            "committed result column has {} variables, the claimed result has {nv}",
            committed.log_size()
        )));
    }
    verifier.add_mv_zerocheck_claim((&committed - public).id());
    Ok(committed)
}

fn data_oracles<B: SnarkBackend>(table: &TrackedTableOracle<B>) -> Vec<(String, TrackedOracle<B>)> {
    let oracles: Vec<_> = table.tracked_oracles_iter().collect();
    table
        .data_tracked_oracles_indices()
        .into_iter()
        .map(|idx| {
            let (field, oracle) = &oracles[idx];
            (field.name().to_string(), oracle.clone())
        })
        .collect()
}

fn check_failed(msg: String) -> SnarkError {
    SnarkError::VerifierError(
        ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(format!(
            "ResultCheck: {msg}"
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
        .expect("ResultCheck table schema missing");
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
            .expect("ResultCheck row field missing");
        parts.push(format!("{:?}", value[row_idx]));
    }
    Ok(parts.join("|"))
}

fn active_row_multiset<B: SnarkBackend>(
    table: &TrackedTable<B>,
) -> ark_piop::errors::SnarkResult<HashMap<String, usize>> {
    let activator = table
        .activator_tracked_poly()
        .expect("ResultCheck table activator missing")
        .evaluations();
    let mut counts = HashMap::new();
    for row_idx in active_positions(&activator) {
        let key = tracked_row_key(table, row_idx)?;
        *counts.entry(key).or_insert(0) += 1;
    }
    Ok(counts)
}

fn false_claim() -> ark_piop::errors::SnarkError {
    ark_piop::errors::SnarkError::ProverError(
        ark_piop::prover::errors::ProverError::HonestProverError(
            ark_piop::prover::errors::HonestProverError::FalseClaim,
        ),
    )
}
