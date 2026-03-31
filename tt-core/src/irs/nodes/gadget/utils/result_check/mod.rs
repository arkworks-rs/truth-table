use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use arithmetic::{
    table::TrackedTable, table_oracle::TrackedTableOracle, ACTIVATOR_COL_NAME,
};
use ark_ff::{PrimeField, Zero};
use ark_piop::{
    arithmetic::mat_poly::mle::MLE,
    structs::TrackerID,
    verifier::structs::oracle::{Oracle, TrackedOracle},
    SnarkBackend,
};
use either::Either;
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
const RESULT_CHECK_SRC_POLY_ID_PREFIX: &str = "result_check_src_poly_id";

pub struct GadgetNode<B: SnarkBackend>(std::marker::PhantomData<B>);

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
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id) else {
            return Ok(());
        };
        let t_table = payload
            .get(INPUT_LABEL)
            .unwrap_or_else(|| panic!("ResultCheck gadget missing {}", INPUT_LABEL));
        let compact_r = payload
            .get(OUTPUT_LABEL)
            .unwrap_or_else(|| panic!("ResultCheck gadget missing {}", OUTPUT_LABEL));

        let support_positions = match_compact_rows_to_sparse_positions(t_table, compact_r)?;
        let src_poly =
            build_result_check_src_poly::<B::F>(1usize << t_table.log_size(), &support_positions);
        let tracked_src = prover.track_and_send_mat_mv_poly(&src_poly)?;
        let tracker_rc = t_table
            .activator_tracked_poly()
            .map(|poly| poly.tracker())
            .or_else(|| t_table.tracked_polys_iter().next().map(|(_, poly)| poly.tracker()))
            .expect("ResultCheck aligned tracker missing");
        tracker_rc.borrow_mut().insert_miscellaneous_field(
            result_check_src_poly_key(id),
            B::F::from(tracked_src.id().to_int() as u64),
        );

        let sparse_r = scatter_compact_prover_table_to_support(compact_r, t_table, &support_positions)?;
        prove_result_check(prover, t_table, &sparse_r)
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id) else {
            panic!("ResultCheck honest prover check missing payload");
        };
        let t_table = payload
            .get(INPUT_LABEL)
            .unwrap_or_else(|| panic!("ResultCheck gadget missing {}", INPUT_LABEL));
        let compact_r = payload
            .get(OUTPUT_LABEL)
            .unwrap_or_else(|| panic!("ResultCheck gadget missing {}", OUTPUT_LABEL));
        let t_active = active_count(t_table);
        let r_active = active_count(compact_r);
        println!(
            "ResultCheck honest_prover_check T: size={}, active={}",
            t_table.size(),
            t_active
        );
        println!("ResultCheck honest_prover_check T:\n{}", t_table.pretty_string());
        if let Some(activator) = t_table.activator_tracked_poly() {
            for row_idx in active_positions(&activator.evaluations()) {
                println!(
                    "ResultCheck honest_prover_check T active_row[{row_idx}] = {}",
                    tracked_row_key(t_table, row_idx)?
                );
            }
        }
        println!(
            "ResultCheck honest_prover_check R: size={}, active={}",
            compact_r.size(),
            r_active
        );
        println!("ResultCheck honest_prover_check R:\n{}", compact_r.pretty_string());
        if let Some(activator) = compact_r.activator_tracked_poly() {
            for row_idx in active_positions(&activator.evaluations()) {
                println!(
                    "ResultCheck honest_prover_check R active_row[{row_idx}] = {}",
                    tracked_row_key(compact_r, row_idx)?
                );
            }
        }
        if active_row_multiset(t_table)? == active_row_multiset(compact_r)? {
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
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id) else {
            return Ok(());
        };
        let t_table = payload
            .get(INPUT_LABEL)
            .unwrap_or_else(|| panic!("ResultCheck gadget missing {}", INPUT_LABEL));
        let compact_r = payload
            .get(OUTPUT_LABEL)
            .unwrap_or_else(|| panic!("ResultCheck gadget missing {}", OUTPUT_LABEL));
        let src_mle = sent_src_mle(id, compact_r)?;
        let sparse_r = scatter_compact_verifier_table_to_support(compact_r, t_table, &src_mle)?;
        verify_result_check(verifier, t_table, &sparse_r)
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

fn prove_result_check<B: SnarkBackend>(
    prover: &mut ark_piop::prover::ArgProver<B>,
    t_table: &TrackedTable<B>,
    r_table: &TrackedTable<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let t_activator = t_table
        .activator_tracked_poly()
        .expect("ResultCheck expects T to have an activator");
    let r_activator = r_table
        .activator_tracked_poly()
        .expect("ResultCheck expects R to have an activator");

    #[cfg(feature = "honest-prover")]
    {
        let t_act = t_activator.evaluations();
        let r_act = r_activator.evaluations();
        if t_act != r_act {
            let mismatches = t_act
                .iter()
                .zip(r_act.iter())
                .enumerate()
                .filter_map(|(idx, (t, r))| (t != r).then_some(idx))
                .take(8)
                .collect::<Vec<_>>();
            tracing::error!(
                t_rows = t_act.len(),
                r_rows = r_act.len(),
                ?mismatches,
                "ResultCheck activator mismatch"
            );
        }
    }

    prover.add_mv_zerocheck_claim((&t_activator - &r_activator).id())?;

    let num_data_cols = t_table.num_data_tracked_cols();
    debug_assert_eq!(
        num_data_cols,
        r_table.num_data_tracked_cols(),
        "ResultCheck expects T and R to have the same number of data columns",
    );

    if num_data_cols == 0 {
        return Ok(());
    }

    let mut challenges = Vec::with_capacity(num_data_cols);
    for _ in 0..num_data_cols {
        challenges.push(prover.get_and_append_challenge(b"result_check_fold")?);
    }
    let t_fold = t_table.fold_all_data_columns(&challenges);
    let r_fold = r_table.fold_all_data_columns(&challenges);

    #[cfg(feature = "honest-prover")]
    {
        let t_fold_evals = t_fold.data_tracked_poly().evaluations();
        let r_fold_evals = r_fold.data_tracked_poly().evaluations();
        let t_act = t_activator.evaluations();
        let mismatches = t_fold_evals
            .iter()
            .zip(r_fold_evals.iter())
            .zip(t_act.iter())
            .enumerate()
            .filter_map(|(idx, ((t, r), a))| ((*a != B::F::zero()) && (t != r)).then_some(idx))
            .take(8)
            .collect::<Vec<_>>();
        if !mismatches.is_empty() {
            tracing::error!(
                ?mismatches,
                t_schema = ?t_table.schema(),
                r_schema = ?r_table.schema(),
                "ResultCheck folded-data mismatch on active rows"
            );
        }
    }

    let zero_poly =
        &(&t_fold.data_tracked_poly() - &r_fold.data_tracked_poly()) * &t_activator;
    prover.add_mv_zerocheck_claim(zero_poly.id())?;
    Ok(())
}

fn verify_result_check<B: SnarkBackend>(
    verifier: &mut ark_piop::verifier::ArgVerifier<B>,
    t_table: &TrackedTableOracle<B>,
    r_table: &TrackedTableOracle<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let t_activator = t_table
        .activator_tracked_poly()
        .expect("ResultCheck expects T to have an activator");
    let r_activator = r_table
        .activator_tracked_poly()
        .expect("ResultCheck expects R to have an activator");

    verifier.add_zerocheck_claim((&t_activator - &r_activator).id());

    let num_data_cols = t_table.num_data_tracked_col_oracles();
    debug_assert_eq!(
        num_data_cols,
        r_table.num_data_tracked_col_oracles(),
        "ResultCheck expects T and R to have the same number of data columns",
    );

    if num_data_cols == 0 {
        return Ok(());
    }

    let mut challenges = Vec::with_capacity(num_data_cols);
    for _ in 0..num_data_cols {
        challenges.push(verifier.get_and_append_challenge(b"result_check_fold")?);
    }
    let t_fold = t_table.fold_all_data_oracles(&challenges);
    let r_fold = r_table.fold_all_data_oracles(&challenges);
    let zero_oracle =
        &(&t_fold.data_tracked_oracle() - &r_fold.data_tracked_oracle()) * &t_activator;
    verifier.add_zerocheck_claim(zero_oracle.id());
    Ok(())
}

fn build_result_check_src_poly<F: PrimeField>(target_num_rows: usize, support_positions: &[usize]) -> MLE<F> {
    let mut evals = vec![F::zero(); target_num_rows];
    for (rank, &position) in support_positions.iter().enumerate() {
        evals[position] = F::from((rank + 1) as u64);
    }
    MLE::from_evaluations_vec(target_num_rows.trailing_zeros() as usize, evals)
}

fn active_positions<F: PrimeField>(evals: &[F]) -> Vec<usize> {
    evals.iter()
        .enumerate()
        .filter_map(|(idx, value)| (!value.is_zero()).then_some(idx))
        .collect()
}

fn match_compact_rows_to_sparse_positions<B: SnarkBackend>(
    sparse_t: &TrackedTable<B>,
    compact_r: &TrackedTable<B>,
) -> ark_piop::errors::SnarkResult<Vec<usize>> {
    let sparse_activator = sparse_t
        .activator_tracked_poly()
        .expect("ResultCheck sparse activator missing")
        .evaluations();
    let compact_activator = compact_r
        .activator_tracked_poly()
        .expect("ResultCheck compact activator missing")
        .evaluations();

    let mut positions_by_key: HashMap<String, VecDeque<usize>> = HashMap::new();
    for row_idx in active_positions(&sparse_activator) {
        let key = tracked_row_key(sparse_t, row_idx)?;
        positions_by_key.entry(key).or_default().push_back(row_idx);
    }

    let mut positions = Vec::new();
    for row_idx in active_positions(&compact_activator) {
        let key = tracked_row_key(compact_r, row_idx)?;
        let position = positions_by_key
            .get_mut(&key)
            .and_then(VecDeque::pop_front)
            .unwrap_or_else(|| panic!("ResultCheck could not map compact row {} back to sparse input", row_idx));
        positions.push(position);
    }
    Ok(positions)
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
            .find_map(|(candidate, poly)| (candidate.name() == field.name()).then_some(poly.evaluations()))
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

fn active_count<B: SnarkBackend>(table: &TrackedTable<B>) -> usize {
    table.activator_tracked_poly().map_or_else(
        || table.size(),
        |poly| active_positions(&poly.evaluations()).len(),
    )
}

fn scatter_compact_prover_table_to_support<B: SnarkBackend>(
    compact_r: &TrackedTable<B>,
    aligned_t: &TrackedTable<B>,
    support_positions: &[usize],
) -> ark_piop::errors::SnarkResult<TrackedTable<B>> {
    let tracker_rc = compact_r
        .activator_tracked_poly()
        .map(|poly| poly.tracker())
        .or_else(|| compact_r.tracked_polys_iter().next().map(|(_, poly)| poly.tracker()))
        .expect("ResultCheck compact tracker missing");
    let compact_active_positions = active_positions(
        &compact_r
            .activator_tracked_poly()
            .expect("ResultCheck compact activator missing")
            .evaluations(),
    );
    if compact_active_positions.len() != support_positions.len() {
        panic!("ResultCheck compact/support size mismatch");
    }

    let schema = aligned_t
        .schema_ref()
        .expect("ResultCheck aligned schema missing")
        .clone();
    let target_size = 1usize << aligned_t.log_size();
    let mut tracked_polys = IndexMap::new();
    for field in schema.fields() {
        let evals = if field.name() == ACTIVATOR_COL_NAME {
            let mut evals = vec![B::F::zero(); target_size];
            for &position in support_positions {
                evals[position] = B::F::from(1u64);
            }
            evals
        } else {
            let compact_evals = compact_r
                .tracked_polys_iter()
                .find_map(|(candidate, poly)| (candidate.name() == field.name()).then_some(poly.evaluations()))
                .unwrap_or_else(|| panic!("ResultCheck compact column {} missing", field.name()));
            let mut evals = vec![B::F::zero(); target_size];
            for (rank, &position) in support_positions.iter().enumerate() {
                evals[position] = compact_evals[compact_active_positions[rank]];
            }
            evals
        };
        let mle = MLE::from_evaluations_vec(aligned_t.log_size(), evals);
        let poly_id = tracker_rc.borrow_mut().track_mat_mv_poly(mle);
        tracked_polys.insert(
            field.clone(),
            ark_piop::prover::structs::polynomial::TrackedPoly::new(
                Either::Left(poly_id),
                aligned_t.log_size(),
                tracker_rc.clone(),
            ),
        );
    }
    Ok(TrackedTable::new(Some(schema), tracked_polys, aligned_t.log_size()))
}

fn sent_src_mle<B: SnarkBackend>(
    id: crate::irs::nodes::NodeId,
    compact_r: &TrackedTableOracle<B>,
) -> ark_piop::errors::SnarkResult<MLE<B::F>> {
    let tracker_rc = compact_r
        .activator_tracked_poly()
        .map(|oracle| oracle.tracker())
        .or_else(|| compact_r.tracked_oracles_iter().next().map(|(_, oracle)| oracle.tracker()))
        .expect("ResultCheck compact tracker missing");
    let src_poly_id_field = tracker_rc
        .borrow()
        .miscellaneous_field_element(&result_check_src_poly_key(id))?;
    let src_poly_id = TrackerID::from_usize(src_poly_id_field.into_bigint().as_ref()[0] as usize);
    tracker_rc.borrow().sent_mv_poly_by_id(src_poly_id)
}

fn scatter_compact_verifier_table_to_support<B: SnarkBackend>(
    compact_r: &TrackedTableOracle<B>,
    aligned_t: &TrackedTableOracle<B>,
    src_mle: &MLE<B::F>,
) -> ark_piop::errors::SnarkResult<TrackedTableOracle<B>> {
    let tracker_rc = compact_r
        .activator_tracked_poly()
        .map(|oracle| oracle.tracker())
        .or_else(|| compact_r.tracked_oracles_iter().next().map(|(_, oracle)| oracle.tracker()))
        .expect("ResultCheck compact tracker missing");
    let schema = aligned_t
        .schema_ref()
        .expect("ResultCheck aligned schema missing")
        .clone();
    let target_log_size = aligned_t.log_size();
    let compact_log_size = compact_r.log_size();
    let src_evals = src_mle.evaluations();

    let mut tracked_oracles = IndexMap::new();
    for field in schema.fields() {
        let oracle = if field.name() == ACTIVATOR_COL_NAME {
            let src_evals = src_evals.clone();
            Oracle::new_multivariate(target_log_size, move |point| {
                let rank = eval_mle_at_point(&src_evals, target_log_size, &point);
                Ok(if rank.is_zero() { B::F::zero() } else { B::F::from(1u64) })
            })
        } else {
            let compact_oracle = compact_r
                .tracked_oracles_iter()
                .find_map(|(candidate, oracle)| (candidate.name() == field.name()).then_some(oracle.clone()))
                .unwrap_or_else(|| panic!("ResultCheck compact column {} missing", field.name()));
            let compact_evals = (0..(1usize << compact_log_size))
                .map(|idx| {
                    let source_point = boolean_point_from_index::<B::F>(compact_log_size, idx);
                    tracker_rc
                        .borrow()
                        .query_mv(compact_oracle.id(), source_point)
                        .expect("ResultCheck compact oracle evaluation should exist")
                })
                .collect::<Vec<_>>();
            let src_evals = src_evals.clone();
            Oracle::new_multivariate(target_log_size, move |point| {
                let rank = eval_mle_at_point(&src_evals, target_log_size, &point);
                if rank.is_zero() {
                    return Ok(B::F::zero());
                }
                let source_idx = field_to_usize::<B::F>(rank)?.saturating_sub(1);
                Ok(compact_evals[source_idx])
            })
        };
        let oracle_id = tracker_rc.borrow_mut().track_oracle(oracle);
        tracked_oracles.insert(
            field.clone(),
            TrackedOracle::new(Either::Left(oracle_id), tracker_rc.clone(), target_log_size),
        );
    }
    Ok(TrackedTableOracle::new(
        Some(schema),
        tracked_oracles,
        target_log_size,
    ))
}

fn result_check_src_poly_key(id: crate::irs::nodes::NodeId) -> String {
    format!("{RESULT_CHECK_SRC_POLY_ID_PREFIX}_{id}")
}

fn field_to_usize<F: PrimeField>(value: F) -> ark_piop::errors::SnarkResult<usize> {
    let repr = value.into_bigint();
    let limbs = repr.as_ref();
    let Some(first) = limbs.first() else {
        panic!("ResultCheck field conversion failed");
    };
    Ok(*first as usize)
}

fn boolean_point_from_index<F: PrimeField>(log_size: usize, idx: usize) -> Vec<F> {
    (0..log_size)
        .map(|bit| if ((idx >> bit) & 1) == 1 { F::from(1u64) } else { F::zero() })
        .collect()
}

fn eval_mle_at_point<F: PrimeField>(evaluations: &[F], num_vars: usize, point: &[F]) -> F {
    if num_vars == 0 {
        return evaluations.first().copied().unwrap_or_else(F::zero);
    }
    let mut layer = evaluations.to_vec();
    let one = F::from(1u64);
    for i in 0..num_vars {
        let x = point.get(i).copied().unwrap_or_else(F::zero);
        let mut next = Vec::with_capacity(layer.len() / 2);
        for chunk in layer.chunks_exact(2) {
            next.push(chunk[0] * (one - x) + chunk[1] * x);
        }
        layer = next;
    }
    layer[0]
}

fn false_claim() -> ark_piop::errors::SnarkError {
    ark_piop::errors::SnarkError::ProverError(
        ark_piop::prover::errors::ProverError::HonestProverError(
            ark_piop::prover::errors::HonestProverError::FalseClaim,
        ),
    )
}
