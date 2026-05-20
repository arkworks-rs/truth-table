use std::{collections::HashMap, sync::Arc};

use arithmetic::{
    ACTIVATOR_COL_NAME,
    table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::{One, PrimeField, Zero};
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    prover::ArgProver,
    prover::structs::polynomial::TrackedPoly,
    verifier::ArgVerifier,
    verifier::structs::oracle::TrackedOracle,
};
use ark_poly::evaluations::multivariate::multilinear::SparseMultilinearExtension;
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
const SRC_KEY: &str = "result_check_src";

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

fn prove_result_check<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    t_table: &TrackedTable<B>,
    r_table: &TrackedTable<B>,
) -> SnarkResult<()> {
    let t_act = t_table
        .activator_tracked_poly()
        .expect("ResultCheck t_table activator missing");
    let mu_t = t_table.log_size();
    let n_t = 1usize << mu_t;

    // src[i] = the t_table active hypercube position whose row content matches
    // r_table's i-th row. Constructing src this way (rather than just
    // enumerating active positions in increasing index order) is what lets
    // ZC2 (`t_act * (fp_T - fp_R) == 0`) vanish even when the IR's tracked
    // execution and datafusion's execution emit the same multiset of rows in
    // different orders (e.g. plain joins without ORDER BY). ZC1 still enforces
    // that src is a permutation of t_table's active positions: the sparse MLE
    // built from src must equal t_act on the whole hypercube, so duplicates
    // collapse and gaps surface as a non-zero zerocheck.
    let src = compute_src_by_row_matching::<B>(t_table, r_table)?;

    // Send src to the verifier.
    let src_field: Vec<B::F> = src.iter().map(|&i| B::F::from(i as u64)).collect();
    prover.add_miscellaneous_field_vector(SRC_KEY.to_string(), src_field)?;

    // Build R.a's MLE in t_table's hypercube.
    let mut r_a_evals = vec![B::F::zero(); n_t];
    for &idx in &src {
        r_a_evals[idx] = B::F::one();
    }
    let r_a_tracked = prover.track_mat_mv_poly(MLE::from_evaluations_vec(mu_t, r_a_evals));

    // For each data column shared by t_table and r_table, build R.dj's MLE in
    // t_table's hypercube by scattering r_table's contiguous data values to the
    // active positions of t_table.
    let data_indices = t_table.data_tracked_polys_indices();
    let n_data = data_indices.len();
    let mut t_data_polys: Vec<TrackedPoly<B>> = Vec::with_capacity(n_data);
    let mut r_d_tracked: Vec<TrackedPoly<B>> = Vec::with_capacity(n_data);
    for &t_idx in &data_indices {
        let (field_ref, t_poly) = t_table
            .tracked_polys()
            .get_index(t_idx)
            .map(|(f, p)| (f.clone(), p.clone()))
            .expect("ResultCheck t_table column index out of bounds");
        t_data_polys.push(t_poly);

        let r_poly = r_table
            .tracked_polys_iter()
            .find_map(|(f, p)| (f.name() == field_ref.name()).then_some(p.clone()))
            .unwrap_or_else(|| {
                panic!(
                    "ResultCheck r_table missing column {} matching t_table",
                    field_ref.name()
                )
            });
        let r_evals = r_poly.evaluations();

        let mut r_d_evals = vec![B::F::zero(); n_t];
        for (i, &idx) in src.iter().enumerate() {
            r_d_evals[idx] = r_evals[i];
        }
        r_d_tracked
            .push(prover.track_mat_mv_poly(MLE::from_evaluations_vec(mu_t, r_d_evals)));
    }

    // Fingerprint challenges shared between fp_T and fp_R folds.
    let num_challenges = std::cmp::max(n_data, 1);
    let mut challenges = Vec::with_capacity(num_challenges);
    for _ in 0..num_challenges {
        challenges.push(prover.get_and_append_challenge(b"result_check_fold")?);
    }

    // Zerocheck 1: t_table.a - R.a = 0.
    let zc_act = &t_act - &r_a_tracked;
    prover.add_mv_zerocheck_claim(zc_act.id())?;

    // Zerocheck 2: t_table.a * (fp_T - fp_R) = 0.
    if n_data > 0 {
        let folded_t = fold_polys(&t_data_polys, &challenges);
        let folded_r = fold_polys(&r_d_tracked, &challenges);
        let fp_diff = &folded_t - &folded_r;
        let zc_fp = &t_act * &fp_diff;
        prover.add_mv_zerocheck_claim(zc_fp.id())?;
    }

    Ok(())
}

/// Build src so that `t_table[src[i]]` equals `r_table[i]` row-for-row.
///
/// r_table's actual data lives in its first `k` evaluations (the rest is
/// inactive padding from `append_activator_and_pad_batches`). For each
/// i in 0..k, we find an unmatched t-active position whose data columns
/// equal r_table's i-th row, then set src[i] = that position. Stable
/// matching by content; multiset semantics. Returns Err if the multisets
/// of active rows disagree between t_table and r_table.
fn compute_src_by_row_matching<B: SnarkBackend>(
    t_table: &TrackedTable<B>,
    r_table: &TrackedTable<B>,
) -> SnarkResult<Vec<usize>> {
    let t_act_evals = t_table
        .activator_tracked_poly()
        .expect("ResultCheck t_table activator missing")
        .evaluations();
    let t_active_indices: Vec<usize> = t_act_evals
        .iter()
        .enumerate()
        .filter_map(|(i, v)| (!v.is_zero()).then_some(i))
        .collect();
    let k = t_active_indices.len();
    if k == 0 {
        return Ok(Vec::new());
    }

    // Match on the data columns of r_table's schema (excluding activator).
    // r_table's schema is the user-visible result schema, which is a subset
    // of t_table's columns (post `project_prover_table_for_result_check`).
    let r_schema = r_table
        .schema_ref()
        .expect("ResultCheck r_table schema missing");
    let key_field_names: Vec<String> = r_schema
        .fields()
        .iter()
        .filter(|f| f.name() != ACTIVATOR_COL_NAME)
        .map(|f| f.name().to_string())
        .collect();

    if key_field_names.is_empty() {
        // No data columns to match on: any permutation works. Keep the
        // active-positions-in-order behavior as a degenerate but valid choice.
        return Ok(t_active_indices);
    }

    let mut t_col_evals: Vec<Vec<B::F>> = Vec::with_capacity(key_field_names.len());
    for name in &key_field_names {
        let evals = t_table
            .tracked_polys_iter()
            .find_map(|(f, p)| (f.name() == name).then(|| p.evaluations()))
            .unwrap_or_else(|| {
                panic!(
                    "ResultCheck t_table missing column {} required for row matching",
                    name
                )
            });
        t_col_evals.push(evals);
    }
    let mut r_col_evals: Vec<Vec<B::F>> = Vec::with_capacity(key_field_names.len());
    for name in &key_field_names {
        let evals = r_table
            .tracked_polys_iter()
            .find_map(|(f, p)| (f.name() == name).then(|| p.evaluations()))
            .unwrap_or_else(|| {
                panic!(
                    "ResultCheck r_table missing column {} required for row matching",
                    name
                )
            });
        r_col_evals.push(evals);
    }

    // r_table's first k rows hold the actual rows.
    let r_min_len = r_col_evals.iter().map(|c| c.len()).min().unwrap_or(0);
    if r_min_len < k {
        return Err(SnarkError::ProverError(
            ark_piop::prover::errors::ProverError::HonestProverError(
                ark_piop::prover::errors::HonestProverError::FalseClaim,
            ),
        ));
    }

    // Bucket t-active positions by row-content key; iterate in reverse so
    // popping yields ascending positions first when multiple rows match.
    let mut buckets: HashMap<Vec<B::F>, Vec<usize>> = HashMap::with_capacity(k);
    for &p in t_active_indices.iter().rev() {
        let key: Vec<B::F> = t_col_evals.iter().map(|col| col[p]).collect();
        buckets.entry(key).or_default().push(p);
    }
    let mut src = Vec::with_capacity(k);
    for i in 0..k {
        let r_key: Vec<B::F> = r_col_evals.iter().map(|col| col[i]).collect();
        let p = buckets
            .get_mut(&r_key)
            .and_then(|v| v.pop())
            .ok_or_else(false_claim)?;
        src.push(p);
    }
    Ok(src)
}

fn verify_result_check<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    t_table: &TrackedTableOracle<B>,
    r_table: &TrackedTableOracle<B>,
) -> SnarkResult<()> {
    let t_act = t_table
        .activator_tracked_poly()
        .expect("ResultCheck t_table activator missing");
    let mu_t = t_table.log_size();
    let n_t = 1usize << mu_t;

    // Receive src from the prover.
    let src_field = verifier.miscellaneous_field_vector(SRC_KEY)?;
    let src: Vec<usize> = src_field
        .iter()
        .map(|f| field_to_usize::<B::F>(f))
        .collect();

    // Validate src indices and build R.a as a sparse MLE: 1 at each src
    // position, 0 elsewhere on t_table's hypercube.
    let mut r_a_sparse_evals: Vec<(usize, B::F)> = Vec::with_capacity(src.len());
    for &idx in &src {
        if idx >= n_t {
            return Err(SnarkError::VerifierError(
                ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(format!(
                    "ResultCheck src index {} out of bounds for t_table size 2^{}",
                    idx, mu_t
                )),
            ));
        }
        r_a_sparse_evals.push((idx, B::F::one()));
    }
    let r_a_tracked = track_sparse_oracle(
        verifier,
        mu_t,
        SparseMultilinearExtension::from_evaluations(mu_t, &r_a_sparse_evals),
    );

    // For each shared data column, extract res˜ from r_table by querying its
    // tracked oracle at hypercube points and build R.dj as a sparse MLE in
    // t_table's hypercube (one nonzero entry per active row).
    let data_indices = t_table.data_tracked_oracles_indices();
    let n_data = data_indices.len();
    let mu_r = r_table.log_size();
    let mut t_data_oracles: Vec<TrackedOracle<B>> = Vec::with_capacity(n_data);
    let mut r_d_tracked: Vec<TrackedOracle<B>> = Vec::with_capacity(n_data);
    for &t_idx in &data_indices {
        let (field_ref, t_oracle) = t_table
            .tracked_oracles_iter()
            .nth(t_idx)
            .map(|(f, o)| (f.clone(), o.clone()))
            .expect("ResultCheck t_table column index out of bounds");
        t_data_oracles.push(t_oracle);

        let r_oracle = r_table
            .tracked_oracles_iter()
            .find_map(|(f, o)| (f.name() == field_ref.name()).then_some(o.clone()))
            .unwrap_or_else(|| {
                panic!(
                    "ResultCheck r_table missing column {} matching t_table",
                    field_ref.name()
                )
            });
        let r_id = r_oracle.id();

        let mut r_d_sparse_evals: Vec<(usize, B::F)> = Vec::with_capacity(src.len());
        for (i, &idx) in src.iter().enumerate() {
            let mut bin_point = vec![B::F::zero(); mu_r];
            for k in 0..mu_r {
                if (i >> k) & 1 == 1 {
                    bin_point[k] = B::F::one();
                }
            }
            let val = verifier.query_mv(r_id, bin_point)?;
            if !val.is_zero() {
                r_d_sparse_evals.push((idx, val));
            }
        }
        r_d_tracked.push(track_sparse_oracle(
            verifier,
            mu_t,
            SparseMultilinearExtension::from_evaluations(mu_t, &r_d_sparse_evals),
        ));
    }

    // Mirror the prover's fingerprint challenges.
    let num_challenges = std::cmp::max(n_data, 1);
    let mut challenges = Vec::with_capacity(num_challenges);
    for _ in 0..num_challenges {
        challenges.push(verifier.get_and_append_challenge(b"result_check_fold")?);
    }

    // Zerocheck 1: t_table.a - R.a = 0.
    let zc_act = &t_act - &r_a_tracked;
    verifier.add_mv_zerocheck_claim(zc_act.id());

    // Zerocheck 2: t_table.a * (fp_T - fp_R) = 0.
    if n_data > 0 {
        let folded_t = fold_oracles(&t_data_oracles, &challenges);
        let folded_r = fold_oracles(&r_d_tracked, &challenges);
        let fp_diff = &folded_t - &folded_r;
        let zc_fp = &t_act * &fp_diff;
        verifier.add_mv_zerocheck_claim(zc_fp.id());
    }

    Ok(())
}

fn fold_polys<B: SnarkBackend>(
    polys: &[TrackedPoly<B>],
    challenges: &[B::F],
) -> TrackedPoly<B> {
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

fn track_sparse_oracle<B: SnarkBackend>(
    verifier: &ArgVerifier<B>,
    nv: usize,
    sparse: SparseMultilinearExtension<B::F>,
) -> TrackedOracle<B> {
    use ark_piop::verifier::structs::oracle::Oracle;
    use ark_poly::Polynomial;

    let sparse = Arc::new(sparse);
    let oracle_poly = sparse.clone();
    let oracle = Oracle::new_multivariate(nv, move |mut point: Vec<B::F>| {
        if point.len() > nv {
            point.truncate(nv);
        } else if point.len() < nv {
            point.resize(nv, B::F::zero());
        }
        Ok(oracle_poly.evaluate(&point))
    });
    verifier.track_base_oracle(oracle)
}

fn field_to_usize<F: PrimeField>(value: &F) -> usize {
    let bigint = value.into_bigint();
    let limbs = bigint.as_ref();
    let mut acc: u128 = 0;
    for (i, limb) in limbs.iter().enumerate() {
        if i >= 2 {
            // We never expect indices larger than 2^128; treat extra limbs as zero.
            assert!(*limb == 0, "ResultCheck src index too large for usize");
            continue;
        }
        acc |= (*limb as u128) << (64 * i);
    }
    usize::try_from(acc).expect("ResultCheck src index does not fit in usize")
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
