use std::{collections::HashMap, sync::Arc};

use arithmetic::{ACTIVATOR_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::{PrimeField, Zero};
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    piop::keyed_sumcheck::{KeyedSumcheckProverInput, KeyedSumcheckVerifierInput},
    prover::ArgProver,
    prover::structs::polynomial::TrackedPoly,
    verifier::ArgVerifier,
    verifier::structs::oracle::{Oracle, TrackedOracle},
};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::{irs::GadgetReadyIr as VerifierGadgetReadyIr, passes::tracking::eval_mle_at_point},
};

#[cfg(test)]
mod tests;

pub const INPUT_LABEL: &str = "__input__";
pub const OUTPUT_LABEL: &str = "__output__";
const RESULT_LABEL: &[u8] = b"result_check_result";

pub struct GadgetNode<B: SnarkBackend> {
    /// Compare the rows in order, not as a multiset (paper PIOP 20, step 2):
    /// set when the query ends in an ORDER BY, whose output is contiguous.
    ordered: bool,
    _backend: std::marker::PhantomData<B>,
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(ordered: bool) -> Self {
        Self {
            ordered,
            _backend: std::marker::PhantomData,
        }
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
        prove_result_check(prover, t_table, res_table, self.ordered)
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
        let matches = if self.ordered {
            active_rows_in_order(t_table)? == active_rows_in_order(r_table)?
        } else {
            active_row_multiset(t_table)? == active_row_multiset(r_table)?
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
            return Ok(());
        };
        let Some(t_table) = payload.get(INPUT_LABEL) else {
            return Ok(());
        };
        let Some(r_table) = payload.get(OUTPUT_LABEL) else {
            return Ok(());
        };
        verify_result_check(verifier, t_table, r_table, self.ordered).map_err(|err| {
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

/// Proves that `r_table`, the result the verifier holds in the clear, is
/// `t_table`, the query output the plan has proven (paper PIOP 20).
///
/// The result is the prover's to choose, so a digest of it enters the
/// transcript before this check draws a challenge: a prover that knew the
/// challenges could pick rows that pass. When `ordered`, the output of the
/// ORDER BY is contiguous and the rows must agree in order: the output's
/// activator is the result's, laid out on the output's domain, and so are
/// its columns on the active rows (step 2). Otherwise the folded active rows
/// of the output must be the folded rows of the result as a multiset
/// (step 3), a LogUp whose result side the verifier sums itself.
fn prove_result_check<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    t_table: &TrackedTable<B>,
    r_table: &TrackedTable<B>,
    ordered: bool,
) -> SnarkResult<()> {
    let t_act = t_table
        .activator_tracked_poly()
        .expect("ResultCheck t_table activator missing");
    let r_act = r_table
        .activator_tracked_poly()
        .expect("ResultCheck r_table activator missing")
        .evaluations();
    let columns =
        match_columns(data_polys(t_table), data_polys(r_table)).ok_or_else(false_claim)?;
    let r_cols: Vec<Vec<B::F>> = columns.iter().map(|(_, r)| r.evaluations()).collect();
    prover.append_statement(RESULT_LABEL, &result_digest(&r_cols, &r_act))?;
    // The first column is folded in with coefficient 1.
    let mut challenges = Vec::with_capacity(columns.len());
    for _ in 1..columns.len() {
        challenges.push(prover.get_and_append_challenge(b"result_check_fold")?);
    }
    let t_data: Vec<TrackedPoly<B>> = columns.into_iter().map(|(t, _)| t).collect();

    if ordered {
        let nv = t_table.log_size();
        let laid_out = |values: &[B::F]| {
            lay_out(values, &r_act, nv)
                .map(|values| MLE::from_evaluations_vec(nv, values))
                .ok_or_else(false_claim)
        };
        let r_act_ext = prover.track_mat_mv_poly(laid_out(&r_act)?);
        prover.add_mv_zerocheck_claim((&t_act - &r_act_ext).id())?;
        if !t_data.is_empty() {
            let r_rows = prover.track_mat_mv_poly(laid_out(&fold_rows(&r_cols, &challenges))?);
            let diff = &fold_polys(&t_data, &challenges) - &r_rows;
            prover.add_mv_zerocheck_claim((&t_act * &diff).id())?;
        }
        return Ok(());
    }

    // With no data columns the multisets are equal exactly when the active
    // row counts are: every active row is the key 1.
    let t_rows = if t_data.is_empty() {
        t_act.clone()
    } else {
        fold_polys(&t_data, &challenges)
    };
    prover.add_mv_keyed_sum_claim_with_public(
        KeyedSumcheckProverInput {
            fxs: vec![t_rows],
            mfxs: vec![Some(t_act)],
            gxs: Vec::new(),
            mgxs: Vec::new(),
        },
        [Vec::new(), vec![active_keys(&r_cols, &r_act, &challenges)]],
    )
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
    ordered: bool,
) -> SnarkResult<()> {
    let t_act = t_table
        .activator_tracked_poly()
        .expect("ResultCheck t_table activator missing");
    let r_act = public_evaluations(
        &r_table
            .activator_tracked_poly()
            .expect("ResultCheck r_table activator missing"),
    )?;
    let columns = match_columns(data_oracles(t_table), data_oracles(r_table)).ok_or_else(|| {
        check_failed("the claimed result's columns differ from the query output's".to_string())
    })?;
    let r_cols = columns
        .iter()
        .map(|(_, r)| public_evaluations(r))
        .collect::<SnarkResult<Vec<_>>>()?;
    verifier.append_statement(RESULT_LABEL, &result_digest(&r_cols, &r_act))?;
    // The first column is folded in with coefficient 1.
    let mut challenges = Vec::with_capacity(columns.len());
    for _ in 1..columns.len() {
        challenges.push(verifier.get_and_append_challenge(b"result_check_fold")?);
    }
    let t_data: Vec<TrackedOracle<B>> = columns.into_iter().map(|(t, _)| t).collect();

    if ordered {
        let nv = t_table.log_size();
        let laid_out = |verifier: &ArgVerifier<B>, values: &[B::F]| {
            let values = lay_out(values, &r_act, nv).ok_or_else(|| {
                check_failed("the claimed result has more rows than the output".to_string())
            })?;
            Ok::<_, SnarkError>(verifier.track_base_oracle(prefix_oracle(values, nv)))
        };
        let r_act_ext = laid_out(verifier, &r_act)?;
        verifier.add_mv_zerocheck_claim((&t_act - &r_act_ext).id());
        if !t_data.is_empty() {
            let r_rows = laid_out(verifier, &fold_rows(&r_cols, &challenges))?;
            let diff = &fold_oracles(&t_data, &challenges) - &r_rows;
            verifier.add_mv_zerocheck_claim((&t_act * &diff).id());
        }
        return Ok(());
    }

    let t_rows = if t_data.is_empty() {
        t_act.clone()
    } else {
        fold_oracles(&t_data, &challenges)
    };
    verifier.add_mv_keyed_sum_claim_with_public(
        KeyedSumcheckVerifierInput {
            fxs: vec![t_rows],
            mfxs: vec![Some(t_act)],
            gxs: Vec::new(),
            mgxs: Vec::new(),
        },
        [Vec::new(), vec![active_keys(&r_cols, &r_act, &challenges)]],
    )
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

fn public_evaluations<B: SnarkBackend>(oracle: &TrackedOracle<B>) -> SnarkResult<Arc<[B::F]>> {
    oracle
        .evaluations()
        .ok_or_else(|| check_failed("the claimed result is not held in the clear".to_string()))
}

/// Binds every value of the claimed result, column by column in the
/// output's order, then its activator. The field's `Hash` writes an
/// element's internal representation, which is unique to it, so the values
/// are bound without converting each one out of it.
fn result_digest<F: PrimeField>(cols: &[impl AsRef<[F]>], act: &[F]) -> [u8; 32] {
    /// Feeds blake3 in large blocks: `Hash` writes each element on its own.
    struct Digest {
        hasher: blake3::Hasher,
        buffer: Vec<u8>,
    }
    impl std::hash::Hasher for Digest {
        fn write(&mut self, bytes: &[u8]) {
            self.buffer.extend_from_slice(bytes);
            if self.buffer.len() >= 1 << 16 {
                self.hasher.update(&self.buffer);
                self.buffer.clear();
            }
        }

        fn finish(&self) -> u64 {
            unreachable!("the digest is read with `finalize`")
        }
    }
    let mut digest = Digest {
        hasher: blake3::Hasher::new(),
        buffer: Vec::with_capacity(1 << 17),
    };
    for values in cols.iter().map(AsRef::as_ref).chain([act]) {
        std::hash::Hash::hash(values, &mut digest);
    }
    digest.hasher.update(&digest.buffer);
    *digest.hasher.finalize().as_bytes()
}

/// `cols[0] + sum_i challenges[i]·cols[i + 1]`, row by row.
fn fold_rows<F: PrimeField>(cols: &[impl AsRef<[F]>], challenges: &[F]) -> Vec<F> {
    let Some((first, rest)) = cols.split_first() else {
        return Vec::new();
    };
    let mut folded = first.as_ref().to_vec();
    for (col, chall) in rest.iter().zip(challenges) {
        for (acc, value) in folded.iter_mut().zip(col.as_ref()) {
            *acc += *value * chall;
        }
    }
    folded
}

/// The folded rows of the claimed result where its activator is set, or the
/// key 1 for each when it has no data columns.
fn active_keys<F: PrimeField>(cols: &[impl AsRef<[F]>], act: &[F], challenges: &[F]) -> Arc<[F]> {
    let folded = (!cols.is_empty()).then(|| fold_rows(cols, challenges));
    act.iter()
        .enumerate()
        .filter(|(_, on)| !on.is_zero())
        .map(|(row, _)| folded.as_ref().map_or(F::one(), |folded| folded[row]))
        .collect()
}

/// `values`, a column of the claimed result, on the first rows of a domain
/// of `nv` variables, zero beyond. `None` if an active row of the result
/// falls outside it.
fn lay_out<F: PrimeField>(values: &[F], act: &[F], nv: usize) -> Option<Vec<F>> {
    let rows = 1usize << nv;
    if act.iter().skip(rows).any(|on| !on.is_zero()) {
        return None;
    }
    let mut laid_out = values[..values.len().min(rows)].to_vec();
    laid_out.resize(rows, F::zero());
    Some(laid_out)
}

/// The oracle of a column [`lay_out`] built, evaluated in time linear in its
/// nonzero prefix: past the prefix of `2^k` rows every row is zero, so the
/// MLE is the prefix's at the low variables times `prod (1 - x_j)` over the
/// others. Like every oracle of `nv` variables, it reads only the first `nv`
/// coordinates of a longer point.
fn prefix_oracle<F: PrimeField>(mut values: Vec<F>, nv: usize) -> Oracle<F> {
    let used = values
        .iter()
        .rposition(|v| !v.is_zero())
        .map_or(0, |last| last + 1);
    let k = used.next_power_of_two().trailing_zeros() as usize;
    values.truncate(1 << k);
    Oracle::new_multivariate(nv, move |point: Vec<F>| {
        let prefix = eval_mle_at_point(&values, k, &point[..k]);
        Ok(point[k..nv]
            .iter()
            .fold(prefix, |acc, x| acc * (F::one() - x)))
    })
}

fn check_failed(msg: String) -> SnarkError {
    SnarkError::VerifierError(
        ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(format!(
            "ResultCheck: {msg}"
        )),
    )
}

/// `polys[0] + sum_i challenges[i]·polys[i + 1]`.
fn fold_polys<B: SnarkBackend>(polys: &[TrackedPoly<B>], challenges: &[B::F]) -> TrackedPoly<B> {
    let mut folded = polys[0].clone();
    for (poly, &chall) in polys[1..].iter().zip(challenges) {
        folded += &poly.mul_scalar_poly(chall);
    }
    folded
}

/// `oracles[0] + sum_i challenges[i]·oracles[i + 1]`.
fn fold_oracles<B: SnarkBackend>(
    oracles: &[TrackedOracle<B>],
    challenges: &[B::F],
) -> TrackedOracle<B> {
    let mut folded = oracles[0].clone();
    for (oracle, &chall) in oracles[1..].iter().zip(challenges) {
        folded += &oracle.mul_scalar_oracle(chall);
    }
    folded
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

fn active_rows_in_order<B: SnarkBackend>(
    table: &TrackedTable<B>,
) -> ark_piop::errors::SnarkResult<Vec<String>> {
    let activator = table
        .activator_tracked_poly()
        .expect("ResultCheck table activator missing")
        .evaluations();
    let mut rows = Vec::new();
    for (row_idx, value) in activator.iter().enumerate() {
        if !value.is_zero() {
            rows.push(tracked_row_key(table, row_idx)?);
        }
    }
    Ok(rows)
}

fn active_row_multiset<B: SnarkBackend>(
    table: &TrackedTable<B>,
) -> ark_piop::errors::SnarkResult<HashMap<String, usize>> {
    let activator = table
        .activator_tracked_poly()
        .expect("ResultCheck table activator missing")
        .evaluations();
    let mut counts = HashMap::new();
    for (row_idx, value) in activator.iter().enumerate() {
        if value.is_zero() {
            continue;
        }
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
