//! Fingerprint pre-filter (paper §6.2, PIOP 8) as a plan-level predicate.
//!
//! The static pre-filter pass (tt-proof-planner) rewrites
//! `Filter(col LIKE pattern)` over a table scan into
//! `Filter(col LIKE pattern) ∘ Filter(tt_prefilter(col, pattern, bins))`, so
//! the fingerprint subset test runs — and is proven — *before* the
//! expensive MCPM machinery. The data-dependent pre-filter rule then picks
//! which of the pattern's bins the pre-filter tests (the prover's greedy
//! under the cost model), or drops the pre-filter when testing none is
//! cheapest. When the pre-filter drops
//! enough rows the data-dependent `RematerializeRule` wraps this node's
//! Filter in a `Rematerialize`, shrinking both the row and char domains
//! MCPM sees.
//!
//! The predicate is the `tt_prefilter(col, pattern, bins)` scalar UDF
//! defined here: SQL-executable (DataFusion needs to run it for row counts
//! and hint DataFrames) with semantics *identical* to the PIOP witness:
//! `fp(col) & φ == φ` where `fp` is [`FingerprintScheme`] applied to the
//! column bytes and `φ` the pattern fingerprint restricted to `bins`, a
//! subset of the pattern's bins written as a comma-separated literal.
//! NULLs evaluate to `false`, matching SQL LIKE's null semantics.
//!
//! Proof side: this expr node's boolean output `a' (= a_pre)` is proven
//! by a [`pre_filtering_check`] gadget child — one zerocheck
//! `a' = a · ∏ fp_b` over the owner-committed boolean `__fp{b}` columns of
//! the scanned table, for the tested bins only (both sides derive them from
//! the public `φ`). The only witness is `a'`, committed in
//! `add_virtual_witness` so the parent Filter sees it.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use arithmetic::{
    self, ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, ROW_ID_COL_NAME,
    encoding::fingerprint_limb_suffix,
    fingerprint::{self, Bin, FingerprintScheme, FpMask, cost::mask_of, scheme_for_column},
    table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::SnarkResult,
    prover::{structs::polynomial::TrackedPoly, tracker::ProverTracker},
    verifier::{structs::oracle::TrackedOracle, tracker::VerifierTracker},
};
use datafusion::arrow::array::{
    Array, ArrayRef, BooleanArray, LargeStringArray, StringArray, StringViewArray,
};
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use datafusion_common::{DataFusionError, Result as DataFusionResult, ScalarValue, Statistics};
use datafusion_expr::{
    ColumnarValue, Expr, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
    expr::ScalarFunction, lit,
};
use either::Either;
use indexmap::IndexMap;

use crate::irs::{
    nodes::{
        IsExprNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
        utils::{pre_filtering_check, sweep_factors::parse_like_pattern_bytes},
    },
    payloads::PayloadStructure,
    tree::Tree,
};
use crate::prover::irs::VirtualizedIr as ProverVirtualizedIr;
use crate::verifier::irs::VirtualizedIr as VerifierVirtualizedIr;

// -----------------------------------------------------------------------------
// The `tt_prefilter` scalar UDF.
// -----------------------------------------------------------------------------

/// Name the UDF is registered (and codec-resolved) under.
pub const TT_PREFILTER_UDF_NAME: &str = "tt_prefilter";

/// Every bin the pattern sets under the column's scheme, ascending: the
/// OR-fold of its literal factors' fingerprints over the scheme's full
/// width. `None` when the pattern is wildcard-only or unsupported (`_`),
/// or when it sets no bin — there is then nothing to pre-filter on.
pub fn pattern_bins(column: &str, pattern: &str) -> Option<Vec<Bin>> {
    let factors = parse_like_pattern_bytes(pattern).ok()?;
    // `column`'s own rule, as the table was committed. A column the rules do
    // not fingerprint has no limbs to test, so it is never pre-filtered.
    let scheme = scheme_for_column(Some(column))?;
    let phi = scheme.pattern_fingerprint(factors.iter().map(|(seg, _)| seg.as_slice()));
    let bins: Vec<Bin> = (0..fingerprint::NUM_BINS)
        .filter(|&b| fingerprint::has_bin(&phi, b))
        .map(|b| b as Bin)
        .collect();
    (!bins.is_empty()).then_some(bins)
}

/// The pattern fingerprint `φ` the pre-filter tests: exactly `bins`, which
/// must be a non-empty subset of [`pattern_bins`] — the verifier's check on
/// a prover-chosen list. `None` otherwise.
pub fn pattern_fingerprint(column: &str, pattern: &str, bins: &[Bin]) -> Option<FpMask> {
    subset_mask(&pattern_bins(column, pattern)?, bins)
}

/// `bins` as a fingerprint when it is a non-empty subset of `all`
/// (ascending), `None` otherwise.
fn subset_mask(all: &[Bin], bins: &[Bin]) -> Option<FpMask> {
    if bins.is_empty() || !bins.iter().all(|b| all.binary_search(b).is_ok()) {
        return None;
    }
    Some(mask_of(bins))
}

#[derive(Debug)]
struct TTPreFilterUdf {
    signature: Signature,
}

impl TTPreFilterUdf {
    fn new() -> Self {
        Self {
            signature: Signature::any(4, Volatility::Immutable),
        }
    }
}

/// `bins` argument of a `tt_prefilter` call: a Utf8 literal of
/// comma-separated bin indices (see [`bins_literal`]).
fn bins_of_scalar(value: &ScalarValue) -> Option<Vec<Bin>> {
    let text = match value {
        ScalarValue::Utf8(Some(s))
        | ScalarValue::LargeUtf8(Some(s))
        | ScalarValue::Utf8View(Some(s)) => s,
        _ => return None,
    };
    text.split(',')
        .filter(|part| !part.is_empty())
        .map(|part| part.parse::<Bin>().ok())
        .collect()
}

/// The `bins` argument as written in the plan: `"3,17,240"`.
pub fn bins_literal(bins: &[Bin]) -> String {
    bins.iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// The subset test over a string column, fingerprinted in parallel under
/// `scheme` — the rule that column was committed with.
fn prefilter_strings<'a>(
    scheme: &FingerprintScheme,
    phi: &FpMask,
    values: impl Iterator<Item = Option<&'a str>>,
) -> BooleanArray {
    let values: Vec<Option<&str>> = values.collect();
    let bytes: Vec<&[u8]> = values
        .iter()
        .map(|v| v.map(str::as_bytes).unwrap_or_default())
        .collect();
    let fps = scheme.fingerprint_all(&bytes);
    values
        .iter()
        .zip(&fps)
        .map(|(v, fp)| Some(v.is_some() && fingerprint::is_subset(phi, fp)))
        .collect()
}

impl ScalarUDFImpl for TTPreFilterUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        TT_PREFILTER_UDF_NAME
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DataFusionResult<DataType> {
        Ok(DataType::Boolean)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DataFusionResult<ColumnarValue> {
        let pattern = match &args.args[1] {
            ColumnarValue::Scalar(ScalarValue::Utf8(Some(s)))
            | ColumnarValue::Scalar(ScalarValue::LargeUtf8(Some(s)))
            | ColumnarValue::Scalar(ScalarValue::Utf8View(Some(s))) => s.clone(),
            other => {
                return Err(DataFusionError::Execution(format!(
                    "tt_prefilter: pattern must be a Utf8 literal, got {other:?}"
                )));
            }
        };
        let bins = match &args.args[2] {
            ColumnarValue::Scalar(value) => bins_of_scalar(value),
            _ => None,
        }
        .ok_or_else(|| {
            DataFusionError::Execution(
                "tt_prefilter: bins must be a comma-separated Utf8 literal of bin indices"
                    .to_string(),
            )
        })?;
        // The column name rides along as the fourth argument, so the rule
        // used here is the one that column was committed under.
        let column = match &args.args[3] {
            ColumnarValue::Scalar(ScalarValue::Utf8(Some(s)))
            | ColumnarValue::Scalar(ScalarValue::LargeUtf8(Some(s)))
            | ColumnarValue::Scalar(ScalarValue::Utf8View(Some(s))) => s.clone(),
            other => {
                return Err(DataFusionError::Execution(format!(
                    "tt_prefilter: column name must be a Utf8 literal, got {other:?}"
                )));
            }
        };
        let scheme = scheme_for_column(Some(&column)).ok_or_else(|| {
            DataFusionError::Execution(format!(
                "tt_prefilter: column '{column}' has no fingerprint rule"
            ))
        })?;
        let phi = pattern_fingerprint(&column, &pattern, &bins).ok_or_else(|| {
            DataFusionError::Execution(format!(
                "tt_prefilter: bins {:?} are not a non-empty subset of the bins pattern '{pattern}' sets",
                bins_literal(&bins)
            ))
        })?;

        let input = args.args[0].clone().into_array(args.number_rows)?;
        let out = match input.data_type() {
            DataType::Utf8 => {
                let arr = input
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .expect("Utf8 array");
                prefilter_strings(&scheme, &phi, arr.iter())
            }
            DataType::LargeUtf8 => {
                let arr = input
                    .as_any()
                    .downcast_ref::<LargeStringArray>()
                    .expect("LargeUtf8 array");
                prefilter_strings(&scheme, &phi, arr.iter())
            }
            DataType::Utf8View => {
                let arr = input
                    .as_any()
                    .downcast_ref::<StringViewArray>()
                    .expect("Utf8View array");
                prefilter_strings(&scheme, &phi, arr.iter())
            }
            other => {
                return Err(DataFusionError::Execution(format!(
                    "tt_prefilter: expected a string column, got {other:?}"
                )));
            }
        };
        let out: ArrayRef = Arc::new(out);
        Ok(ColumnarValue::Array(out))
    }
}

/// Construct the `tt_prefilter` UDF for session registration. Both the
/// prover's and the verifier's `SessionContext` must register it (the
/// codec resolves serialized plans through `ctx.udf(name)`).
pub fn tt_prefilter_udf() -> ScalarUDF {
    ScalarUDF::new_from_impl(TTPreFilterUdf::new())
}

/// `tt_prefilter(col_expr, 'pattern', 'bins')` as a DataFusion expression.
pub fn tt_prefilter_expr(col_expr: Expr, pattern: &str, bins: &[Bin]) -> Expr {
    // The column's name travels with the call: at execution the UDF sees only
    // values, but it needs the name to pick that column's fingerprint rule.
    let column = match &col_expr {
        Expr::Column(c) => c.name.clone(),
        other => panic!("tt_prefilter: first argument must be a column, got {other:?}"),
    };
    Expr::ScalarFunction(ScalarFunction::new_udf(
        Arc::new(tt_prefilter_udf()),
        vec![col_expr, lit(pattern), lit(bins_literal(bins)), lit(column)],
    ))
}

/// The `(column, pattern, bins)` arguments of a `tt_prefilter` call.
pub fn prefilter_args(expr: &Expr) -> Option<(&Expr, String, Vec<Bin>)> {
    let Expr::ScalarFunction(function) = expr else {
        return None;
    };
    if function.name() != TT_PREFILTER_UDF_NAME || function.args.len() != 4 {
        return None;
    }
    let pattern = match &function.args[1] {
        Expr::Literal(ScalarValue::Utf8(Some(s)))
        | Expr::Literal(ScalarValue::LargeUtf8(Some(s)))
        | Expr::Literal(ScalarValue::Utf8View(Some(s))) => s.clone(),
        _ => return None,
    };
    let bins = match &function.args[2] {
        Expr::Literal(value) => bins_of_scalar(value)?,
        _ => return None,
    };
    Some((&function.args[0], pattern, bins))
}

// -----------------------------------------------------------------------------
// Commit helpers (same tracker-direct pattern as `like.rs`).
// -----------------------------------------------------------------------------

fn commit_prover<B: SnarkBackend>(
    tracker_rc: &Rc<RefCell<ProverTracker<B>>>,
    log_size: usize,
    evals: Vec<B::F>,
) -> SnarkResult<TrackedPoly<B>> {
    let mle = MLE::from_evaluations_vec(log_size, evals);
    let num_vars = mle.num_vars();
    let result = tracker_rc
        .borrow_mut()
        .track_and_commit_mat_mv_p(&mle, false)?;
    Ok(match result {
        Either::Left(id) => TrackedPoly::new(Either::Left(id), num_vars, tracker_rc.clone()),
        Either::Right((id, cnst)) => {
            TrackedPoly::new_committed_constant(cnst, id, num_vars, tracker_rc.clone())
        }
    })
}

fn track_next_verifier<B: SnarkBackend>(
    tracker_rc: &Rc<RefCell<VerifierTracker<B>>>,
) -> SnarkResult<TrackedOracle<B>> {
    let id = tracker_rc.borrow_mut().peek_next_id();
    let maybe_cnst = tracker_rc.borrow().proof_mv_constant(id);
    if let Some(cnst) = maybe_cnst {
        let (nv, tid) = tracker_rc.borrow_mut().track_mv_com_by_id(id)?;
        return Ok(TrackedOracle::new_committed_constant(
            cnst,
            tid,
            tracker_rc.clone(),
            nv,
        ));
    }
    let (nv, tid) = tracker_rc.borrow_mut().track_mv_com_by_id(id)?;
    Ok(TrackedOracle::new(
        Either::Left(tid),
        tracker_rc.clone(),
        nv,
    ))
}

fn bool_table<B: SnarkBackend>(poly: TrackedPoly<B>, log_size: usize) -> TrackedTable<B> {
    let field = Arc::new(Field::new("data", DataType::Boolean, false));
    let mut polys = IndexMap::new();
    polys.insert(field.clone(), poly);
    TrackedTable::new(
        Some(Schema::new(vec![field.as_ref().clone()])),
        polys,
        log_size,
    )
}

fn bool_table_oracle<B: SnarkBackend>(
    oracle: TrackedOracle<B>,
    log_size: usize,
) -> TrackedTableOracle<B> {
    let field = Arc::new(Field::new("data", DataType::Boolean, false));
    let mut oracles = IndexMap::new();
    oracles.insert(field.clone(), oracle);
    TrackedTableOracle::new(
        Some(Schema::new(vec![field.as_ref().clone()])),
        oracles,
        log_size,
    )
}

// -----------------------------------------------------------------------------
// Witness computation.
// -----------------------------------------------------------------------------

/// The pre-filter's output `a'`: 1 exactly on the active rows that set
/// every tested bin, read from the committed bin columns.
fn compute_a_pre<F: PrimeField>(fp_bins: &[Vec<F>], a_evals: &[F]) -> Vec<F> {
    (0..a_evals.len())
        .map(|i| {
            let keep = a_evals[i].is_one() && fp_bins.iter().all(|col| col[i].is_one());
            if keep { F::one() } else { F::zero() }
        })
        .collect()
}

// -----------------------------------------------------------------------------
// The expr node.
// -----------------------------------------------------------------------------

pub struct ExprNode<B: SnarkBackend> {
    pub scope: Vec<std::sync::Weak<Node<B>>>,
    pub parent: Option<std::sync::Weak<Node<B>>>,
    pub scalar_function: ScalarFunction,
    pub pattern: String,
    /// Bins the pre-filter tests: the prover's choice among the pattern's.
    pub bins: Vec<Bin>,
    /// `φ` — `None` when `bins` is not a non-empty subset of the pattern's
    /// bins (passthrough; a hint like that never verifies).
    pub phi: Option<FpMask>,
    /// The string-column child expr node.
    pub expr: Arc<Node<B>>,
    /// The PreFilteringCheck gadget child; `None` when `phi` is `None`.
    pub gadget: Option<Arc<Node<B>>>,
    output_data_field_cache: Mutex<Option<FieldRef>>,
}

impl<B: SnarkBackend> ExprNode<B> {
    fn output_field(&self) -> FieldRef {
        if let Some(field) = self
            .output_data_field_cache
            .lock()
            .expect("output_data_field_cache poisoned")
            .as_ref()
            .cloned()
        {
            return field;
        }
        let field: FieldRef = Arc::new(Field::new(
            self.output_field_name(),
            DataType::Boolean,
            true,
        ));
        *self
            .output_data_field_cache
            .lock()
            .expect("output_data_field_cache poisoned") = Some(field.clone());
        field
    }

    fn output_expr(&self) -> Expr {
        Expr::ScalarFunction(self.scalar_function.clone())
    }

    /// The pre-filtered column's name.
    fn column_name(&self) -> String {
        match self.scalar_function.args.first() {
            Some(Expr::Column(c)) => c.name.clone(),
            other => panic!("PreFilter: first argument must be a column, got {other:?}"),
        }
    }

    fn output_field_name(&self) -> String {
        format!(
            "{}_PREFILTER_{}_{}",
            self.column_name(),
            self.pattern,
            bins_literal(&self.bins).replace(',', "-")
        )
    }

    fn needed_limbs(&self) -> Vec<usize> {
        fingerprint::touched_limbs(self.phi.as_ref().expect("PreFilter: non-empty phi"))
    }

    fn limb_field_name(&self, j: usize) -> String {
        format!("{}{}", self.column_name(), fingerprint_limb_suffix(j))
    }

    fn scope_table_prover(&self, virtualized_ir: &ProverVirtualizedIr<B>) -> TrackedTable<B> {
        match virtualized_ir.payload_for_node(&self.expr.id()) {
            Some(PayloadStructure::PlanPayload(t)) => t.clone(),
            _ => panic!("PreFilter: expected PlanPayload on input column child"),
        }
    }

    fn scope_table_verifier(
        &self,
        virtualized_ir: &VerifierVirtualizedIr<B>,
    ) -> TrackedTableOracle<B> {
        match virtualized_ir.payload_for_node(&self.expr.id()) {
            Some(PayloadStructure::PlanPayload(t)) => t.clone(),
            _ => panic!("PreFilter: expected PlanPayload on input column child"),
        }
    }

    /// The committed limb columns `fp_j`, `j ∈ N`, of the scanned table.
    fn fp_limb_polys(&self, scope_table: &TrackedTable<B>) -> Vec<(FieldRef, TrackedPoly<B>)> {
        self.needed_limbs()
            .into_iter()
            .map(|j| {
                let name = self.limb_field_name(j);
                scope_table
                    .tracked_polys_iter()
                    .find(|(f, _)| f.name() == &name)
                    .map(|(f, p)| (f.clone(), p.clone()))
                    .unwrap_or_else(|| {
                        panic!(
                            "PreFilter: scope is missing fingerprint limb column {name} — \
                             the pre-filter must sit directly on a table scan"
                        )
                    })
            })
            .collect()
    }

    fn fp_limb_oracles(
        &self,
        scope_table: &TrackedTableOracle<B>,
    ) -> Vec<(FieldRef, TrackedOracle<B>)> {
        self.needed_limbs()
            .into_iter()
            .map(|j| {
                let name = self.limb_field_name(j);
                scope_table
                    .tracked_oracles_iter()
                    .find(|(f, _)| f.name() == &name)
                    .map(|(f, o)| (f.clone(), o.clone()))
                    .unwrap_or_else(|| {
                        panic!("PreFilter verifier: scope is missing fingerprint limb {name}")
                    })
            })
            .collect()
    }

    /// `a'` from the committed bin columns.
    fn a_pre_prover(&self, scope_table: &TrackedTable<B>) -> Vec<B::F> {
        let fp_bins: Vec<Vec<B::F>> = self
            .fp_limb_polys(scope_table)
            .iter()
            .map(|(_, poly)| poly.evaluations())
            .collect();
        let a_evals = scope_table
            .activator_tracked_poly()
            .expect("PreFilter: scope must carry a string-level activator")
            .evaluations();
        compute_a_pre(&fp_bins, &a_evals)
    }

    fn commit_a_pre_prover(
        &self,
        id: NodeId,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let scope_table = self.scope_table_prover(virtualized_ir);
        let str_domain = scope_table.log_size();
        let activator = scope_table
            .activator_tracked_poly()
            .expect("PreFilter: scope must carry a string-level activator");
        let tracker_rc = activator.tracker();

        let a_pre = commit_prover(&tracker_rc, str_domain, self.a_pre_prover(&scope_table))?;

        // Own PlanPayload = a' + activator + row_id (so Filter sees it).
        let mut merged: IndexMap<FieldRef, TrackedPoly<B>> = IndexMap::new();
        merged.insert(self.output_field(), a_pre);
        merged.insert(ACTIVATOR_FIELD.clone(), activator);
        if let Some((row_id_field, row_id_poly)) = scope_table
            .tracked_polys_iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
        {
            merged.insert(row_id_field.clone(), row_id_poly.clone());
        }
        let fields: Vec<Field> = merged.keys().map(|f| f.as_ref().clone()).collect();
        let schema = Some(Schema::new(fields));
        virtualized_ir.set_payload_for_node(
            id,
            Some(PayloadStructure::PlanPayload(TrackedTable::new(
                schema, merged, str_domain,
            ))),
        );
        Ok(())
    }

    fn commit_and_wire_prover(
        &self,
        id: NodeId,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let gadget_node = self
            .gadget
            .as_ref()
            .expect("PreFilter: non-empty pattern must have a PreFilteringCheck child");
        let scope_table = self.scope_table_prover(virtualized_ir);
        let str_domain = scope_table.log_size();
        let activator = scope_table
            .activator_tracked_poly()
            .expect("PreFilter: scope must carry a string-level activator");

        // `a'` was committed in add_virtual_witness; recover it.
        let own_payload = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(t)) => t.clone(),
            _ => panic!("PreFilter: expected own PlanPayload set by add_virtual_witness"),
        };
        let a_pre = own_payload
            .tracked_polys_iter()
            .find(|(f, _)| f.name() == self.output_field().name())
            .map(|(_, p)| p.clone())
            .expect("PreFilter: a' must be committed by add_virtual_witness");

        let mut payload: IndexMap<String, TrackedTable<B>> = IndexMap::new();
        let fp_limbs = self.fp_limb_polys(&scope_table);
        {
            let schema = Schema::new(
                fp_limbs
                    .iter()
                    .map(|(f, _)| f.as_ref().clone())
                    .collect::<Vec<_>>(),
            );
            let mut polys: IndexMap<FieldRef, TrackedPoly<B>> = fp_limbs.into_iter().collect();
            polys.insert(ACTIVATOR_FIELD.clone(), activator);
            payload.insert(
                pre_filtering_check::STR_INPUT_LABEL.to_string(),
                TrackedTable::new(Some(schema), polys, str_domain),
            );
        }
        payload.insert(
            pre_filtering_check::STR_FILTERED_LABEL.to_string(),
            bool_table(a_pre, str_domain),
        );
        virtualized_ir.set_payload_for_node(
            gadget_node.id(),
            Some(PayloadStructure::GadgetPayload(payload)),
        );
        Ok(())
    }

    fn track_a_pre_verifier(
        &self,
        id: NodeId,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let scope_table = self.scope_table_verifier(virtualized_ir);
        let str_domain = scope_table.log_size();
        let activator = scope_table
            .activator_tracked_poly()
            .expect("PreFilter verifier: scope must carry a string-level activator");
        let tracker_rc = activator.tracker();

        let a_pre = track_next_verifier(&tracker_rc)?;

        let mut merged: IndexMap<FieldRef, TrackedOracle<B>> = IndexMap::new();
        merged.insert(self.output_field(), a_pre);
        merged.insert(ACTIVATOR_FIELD.clone(), activator);
        if let Some((row_id_field, row_id_oracle)) = scope_table
            .tracked_oracles_iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
        {
            merged.insert(row_id_field.clone(), row_id_oracle.clone());
        }
        let fields: Vec<Field> = merged.keys().map(|f| f.as_ref().clone()).collect();
        let schema = Some(Schema::new(fields));
        virtualized_ir.set_payload_for_node(
            id,
            Some(PayloadStructure::PlanPayload(TrackedTableOracle::new(
                schema, merged, str_domain,
            ))),
        );
        Ok(())
    }

    fn track_and_wire_verifier(
        &self,
        id: NodeId,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let gadget_node = self
            .gadget
            .as_ref()
            .expect("PreFilter: non-empty pattern must have a PreFilteringCheck child");
        let scope_table = self.scope_table_verifier(virtualized_ir);
        let str_domain = scope_table.log_size();
        let activator = scope_table
            .activator_tracked_poly()
            .expect("PreFilter verifier: scope must carry a string-level activator");

        // `a'` was tracked in add_virtual_witness; recover it.
        let own_payload = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(t)) => t.clone(),
            _ => panic!("PreFilter verifier: expected own PlanPayload"),
        };
        let a_pre = own_payload
            .tracked_oracles_iter()
            .find(|(f, _)| f.name() == self.output_field().name())
            .map(|(_, p)| p.clone())
            .expect("PreFilter verifier: a' must be tracked by add_virtual_witness");

        let mut payload: IndexMap<String, TrackedTableOracle<B>> = IndexMap::new();
        let fp_limbs = self.fp_limb_oracles(&scope_table);
        {
            let schema = Schema::new(
                fp_limbs
                    .iter()
                    .map(|(f, _)| f.as_ref().clone())
                    .collect::<Vec<_>>(),
            );
            let mut oracles: IndexMap<FieldRef, TrackedOracle<B>> = fp_limbs.into_iter().collect();
            oracles.insert(ACTIVATOR_FIELD.clone(), activator);
            payload.insert(
                pre_filtering_check::STR_INPUT_LABEL.to_string(),
                TrackedTableOracle::new(Some(schema), oracles, str_domain),
            );
        }
        payload.insert(
            pre_filtering_check::STR_FILTERED_LABEL.to_string(),
            bool_table_oracle(a_pre, str_domain),
        );
        virtualized_ir.set_payload_for_node(
            gadget_node.id(),
            Some(PayloadStructure::GadgetPayload(payload)),
        );
        Ok(())
    }
}

impl<B: SnarkBackend> IsNode<B> for ExprNode<B> {
    fn name(&self) -> String {
        "PreFilter".to_string()
    }

    fn display(&self) -> String {
        format!(
            "PreFilter\nInput: {}, pattern: '{}', {} bins",
            self.expr.name(),
            self.pattern,
            self.bins.len(),
        )
    }

    fn cost(
        &self,
        _statistics: Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        let mut kids = vec![self.expr.clone()];
        if let Some(gadget) = &self.gadget {
            kids.push(gadget.clone());
        }
        kids
    }

    fn required_fingerprint_columns(&self) -> Vec<(String, Vec<usize>)> {
        if self.phi.is_none() {
            return Vec::new();
        }
        vec![(self.column_name(), self.needed_limbs())]
    }

    /// The pre-filter reads only fingerprint limbs, but the LIKE above it
    /// reads this column's characters. A `Rematerialize` over the
    /// pre-filter compacts those characters, and decides whether to bind
    /// them (the DPUC) from its input subtree's side columns
    /// ([`crate::irs::nodes::plan::rematerialize::single_side_string_base`]).
    /// Without this declaration that compaction re-emits the characters
    /// unbound.
    fn required_side_columns(&self) -> Vec<String> {
        if self.phi.is_none() {
            return Vec::new();
        }
        vec![self.column_name()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ExprNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        if self.phi.is_none() {
            // Nothing to test — boolean output IS the activator.
            let scope_table = self.scope_table_prover(virtualized_ir);
            let mut polys: IndexMap<FieldRef, TrackedPoly<B>> = IndexMap::new();
            let activator = scope_table
                .activator_tracked_poly()
                .expect("PreFilter: passthrough requires a scope activator");
            polys.insert(self.output_field(), activator.clone());
            polys.insert(ACTIVATOR_FIELD.clone(), activator);
            if let Some((row_id_field, row_id_poly)) = scope_table
                .tracked_polys_iter()
                .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
            {
                polys.insert(row_id_field.clone(), row_id_poly.clone());
            }
            let fields: Vec<Field> = polys.keys().map(|f| f.as_ref().clone()).collect();
            let schema = Some(Schema::new(fields));
            let log_size = scope_table.log_size();
            virtualized_ir.set_payload_for_node(
                id,
                Some(PayloadStructure::PlanPayload(TrackedTable::new(
                    schema, polys, log_size,
                ))),
            );
            return Ok(());
        }
        self.commit_a_pre_prover(id, virtualized_ir)
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        if self.phi.is_none() {
            return Ok(());
        }
        self.commit_and_wire_prover(id, virtualized_ir)
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ExprNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        if self.phi.is_none() {
            let scope_table = self.scope_table_verifier(virtualized_ir);
            let mut oracles: IndexMap<FieldRef, TrackedOracle<B>> = IndexMap::new();
            let activator = scope_table
                .activator_tracked_poly()
                .expect("PreFilter: passthrough requires a scope activator");
            oracles.insert(self.output_field(), activator.clone());
            oracles.insert(ACTIVATOR_FIELD.clone(), activator);
            if let Some((row_id_field, row_id_oracle)) = scope_table
                .tracked_oracles_iter()
                .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
            {
                oracles.insert(row_id_field.clone(), row_id_oracle.clone());
            }
            let fields: Vec<Field> = oracles.keys().map(|f| f.as_ref().clone()).collect();
            let schema = Some(Schema::new(fields));
            let log_size = scope_table.log_size();
            virtualized_ir.set_payload_for_node(
                id,
                Some(PayloadStructure::PlanPayload(TrackedTableOracle::new(
                    schema, oracles, log_size,
                ))),
            );
            return Ok(());
        }
        self.track_a_pre_verifier(id, virtualized_ir)
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        if self.phi.is_none() {
            return Ok(());
        }
        self.track_and_wire_verifier(id, virtualized_ir)
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ExprNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        self.gadget.as_ref().map(|g| g.as_ref().clone())
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsProverPlanNode<B> for ExprNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let scope = self.scope[0]
            .upgrade()
            .expect("PreFilter scope should be available during output");
        let scope_hint_df = match scope.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsProverPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("PreFilter scope cannot be a gadget node"),
        };
        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(scope_hint_df.data_frame().clone())
                .expect("prefilter row-id sort should succeed");
        let mut exprs = vec![self.output_expr()];
        crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut exprs);
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);
        let projected = input_df
            .select(exprs)
            .expect("prefilter projection should succeed");
        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("prefilter output sort should succeed");
        let should_materialize: IndexMap<FieldRef, bool> = projected
            .schema()
            .fields()
            .iter()
            .map(|field| {
                let is_data = field.name() != ACTIVATOR_COL_NAME && field.name() != ROW_ID_COL_NAME;
                (field.clone(), is_data)
            })
            .collect();
        crate::irs::nodes::hints::HintDF::new(projected, should_materialize)
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for ExprNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let scope = self.scope[0]
            .upgrade()
            .expect("PreFilter scope should be available during output");
        let scope_hint_df = match scope.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("PreFilter scope cannot be a gadget node"),
        };
        let input_df = scope_hint_df.data_frame().clone();
        let mut exprs = vec![self.output_expr()];
        crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut exprs);
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);
        let projected = input_df
            .select(exprs)
            .expect("prefilter verifier projection should succeed");
        let should_materialize: IndexMap<FieldRef, bool> = projected
            .schema()
            .fields()
            .iter()
            .map(|field| {
                let is_data = field.name() != ACTIVATOR_COL_NAME && field.name() != ROW_ID_COL_NAME;
                (field.clone(), is_data)
            })
            .collect();
        crate::irs::nodes::hints::HintDF::new(projected, should_materialize)
    }
}

impl<B: SnarkBackend> IsExprNode<B> for ExprNode<B> {
    fn from_expr(
        expr: Expr,
        self_ref: std::sync::Weak<Node<B>>,
        parent: Option<std::sync::Weak<Node<B>>>,
        scope: Vec<std::sync::Weak<Node<B>>>,
    ) -> Self
    where
        Self: Sized,
    {
        let scalar_function = match expr {
            Expr::ScalarFunction(f) => f,
            _ => panic!("PreFilter::from_expr called with non-ScalarFunction expression"),
        };
        assert_eq!(
            scalar_function.name(),
            TT_PREFILTER_UDF_NAME,
            "PreFilter::from_expr called with UDF {:?}",
            scalar_function.name()
        );
        let call = Expr::ScalarFunction(scalar_function.clone());
        let (col_expr, pattern, bins) = prefilter_args(&call).unwrap_or_else(|| {
            panic!("PreFilter: expected (column, 'pattern', bins, 'column') arguments")
        });
        let column = match col_expr {
            Expr::Column(c) => c.name.clone(),
            other => panic!("PreFilter: first argument must be a column, got {other:?}"),
        };
        let phi = pattern_fingerprint(&column, &pattern, &bins);

        let expr_node = Tree::<B>::from_expr(
            &scalar_function.args[0],
            Some(self_ref.clone()),
            scope.clone(),
        )
        .root()
        .clone();
        // Row-only PIOP 8: the plan-level composition never consumes the
        // narrowed char activator (MCPM re-derives its own consistent
        // pair, and the remat path uses the rematerialized table's fresh
        // side activator), so the char-domain DPUC half is omitted.
        let gadget = phi.map(|phi| {
            Arc::new(Node::<B>::Gadget(Arc::new(
                pre_filtering_check::GadgetNode::new_row_only(phi),
            )))
        });

        Self {
            scope,
            parent,
            scalar_function,
            pattern,
            bins,
            phi,
            expr: expr_node,
            gadget,
            output_data_field_cache: Mutex::new(None),
        }
    }

    fn expr(&self) -> Expr {
        Expr::ScalarFunction(self.scalar_function.clone())
    }

    fn parent(&self) -> crate::irs::nodes::PlanNode<B>
    where
        Self: Sized,
    {
        self.parent
            .as_ref()
            .and_then(|weak_ref| weak_ref.upgrade())
            .map(|arc_node| match arc_node.as_ref() {
                Node::Plan(plan_node) => plan_node.clone(),
                Node::Gadget(_) => panic!("PreFilter parent cannot be a gadget node"),
            })
            .expect("PreFilter node must have a parent")
    }

    fn scope(&self) -> Vec<Arc<Node<B>>>
    where
        Self: Sized,
    {
        self.scope
            .iter()
            .map(|s| s.upgrade().expect("PreFilter scope should be available"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prover_chosen_bin_list_must_be_a_subset_of_the_patterns() {
        let all = [3, 17, 240];
        assert_eq!(subset_mask(&all, &[17]), Some(mask_of(&[17])));
        assert_eq!(subset_mask(&all, &[3, 240]), Some(mask_of(&[3, 240])));
        assert!(subset_mask(&all, &[]).is_none(), "nothing to test");
        assert!(subset_mask(&all, &[4]).is_none(), "not the pattern's bin");
        assert!(subset_mask(&all, &[3, 4]).is_none());
    }

    #[test]
    fn bins_travel_as_a_literal() {
        let bins = [3, 17, 240];
        let text = bins_literal(&bins);
        assert_eq!(text, "3,17,240");
        assert_eq!(
            bins_of_scalar(&ScalarValue::Utf8(Some(text))),
            Some(bins.to_vec())
        );
        assert_eq!(
            bins_of_scalar(&ScalarValue::Utf8(Some(String::new()))),
            Some(Vec::new())
        );
        assert!(bins_of_scalar(&ScalarValue::Utf8(Some("3,x".into()))).is_none());
        assert!(bins_of_scalar(&ScalarValue::Int64(Some(3))).is_none());
    }
}
