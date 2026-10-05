use std::collections::BTreeMap;

use arithmetic::ACTIVATOR_COL_NAME;
use arithmetic::fingerprint::{Bin, cost::CostModel, cost::select_bins, scheme_for_column};
use datafusion::arrow::array::{Array, AsArray, BooleanArray};
use datafusion::arrow::compute::cast;
use datafusion::arrow::datatypes::DataType;
use datafusion::dataframe::DataFrame;
use datafusion::execution::context::SessionState;
use datafusion_common::{DataFusionError, Result as DataFusionResult};
use datafusion_expr::{Expr, Filter, LogicalPlan, col};
use tt_core::irs::nodes::plan::exprs::fp_prefilter::{
    pattern_fingerprint, prefilter_args, tt_prefilter_expr,
};
use tt_core::irs::nodes::utils::sweep_factors::parse_like_pattern_bytes;

use super::rematerialize::expressions_for_with_new_exprs;
use super::{DataDependentOptimizationRule, OptimizationHint, collect_blocking, row_count};

/// Data-dependent rule that picks which fingerprint bins each LIKE
/// pre-filter tests. For `Filter(LIKE) ∘ Filter(tt_prefilter) ∘ input`, the
/// prover fingerprints the column's active rows, counts the LIKE's matches,
/// and runs the greedy of [`select_bins`] under the compiled-in cost model:
/// the subset of the pattern's bins that makes the query cheapest, possibly
/// none. The verifier replays the list from the hint and checks it is a
/// subset of the pattern's bins; every such subset is sound, since testing
/// fewer bins only lets more rows through. An empty list removes the
/// pre-filter.
///
/// Must run before `RematerializeRule`, whose decisions depend on how much
/// the pre-filter drops.
#[derive(Debug, Default)]
pub struct PrefilterBinsRule;

impl PrefilterBinsRule {
    pub fn new() -> Self {
        Self
    }
}

impl DataDependentOptimizationRule for PrefilterBinsRule {
    fn name(&self) -> &str {
        "prefilter_bins"
    }

    fn collect_hints(
        &self,
        session_state: &SessionState,
        plan: &LogicalPlan,
    ) -> DataFusionResult<Vec<OptimizationHint>> {
        let mut hints = Vec::new();
        let mut path = Vec::new();
        collect(session_state, plan, &mut path, &mut hints)?;
        Ok(hints)
    }
}

fn collect(
    session_state: &SessionState,
    plan: &LogicalPlan,
    path: &mut Vec<usize>,
    hints: &mut Vec<OptimizationHint>,
) -> DataFusionResult<()> {
    if let LogicalPlan::Filter(like_filter) = plan
        && let LogicalPlan::Filter(prefilter) = like_filter.input.as_ref()
        && let Some((col_expr, pattern, _)) = prefilter_args(&prefilter.predicate)
        && let Expr::Column(column) = col_expr
    {
        let input = prefilter.input.clone();
        let matches = row_count(
            session_state,
            &LogicalPlan::Filter(Filter::try_new(
                like_filter.predicate.clone(),
                input.clone(),
            )?),
        )?;
        let bins = choose_bins(
            session_state,
            &input,
            col_expr,
            &column.name,
            &pattern,
            matches,
        )?;
        let mut target_path = path.clone();
        target_path.push(0);
        hints.push(OptimizationHint::PrefilterBins { target_path, bins });
    }
    for (idx, input) in plan.inputs().into_iter().enumerate() {
        path.push(idx);
        collect(session_state, input, path, hints)?;
        path.pop();
    }
    Ok(())
}

/// The prover's choice for one pre-filter: the greedy over the column's
/// active rows, or nothing when the column has no rule.
fn choose_bins(
    session_state: &SessionState,
    input: &LogicalPlan,
    col_expr: &Expr,
    column: &str,
    pattern: &str,
    matches: usize,
) -> DataFusionResult<Vec<Bin>> {
    // This column's own rule, as the table was committed.
    let Some(scheme) = scheme_for_column(Some(column)) else {
        return Ok(Vec::new());
    };
    let Ok(factors) = parse_like_pattern_bytes(pattern) else {
        return Ok(Vec::new());
    };
    let factors: Vec<&[u8]> = factors.iter().map(|(seg, _)| seg.as_slice()).collect();
    let strings = active_strings(session_state, input, col_expr)?;
    let fingerprints = scheme.fingerprint_all(&strings);
    let chosen = select_bins(
        &scheme,
        &CostModel::default(),
        &factors,
        &strings,
        &fingerprints,
        matches,
    );
    Ok(chosen.bins)
}

/// The column's values on the input's active rows (NULL as an empty
/// string, which no bin test passes — the pre-filter's `false` on NULL).
fn active_strings(
    session_state: &SessionState,
    input: &LogicalPlan,
    col_expr: &Expr,
) -> DataFusionResult<Vec<Vec<u8>>> {
    let has_activator = input
        .schema()
        .fields()
        .iter()
        .any(|f| f.name() == ACTIVATOR_COL_NAME);
    let mut projection = vec![col_expr.clone()];
    if has_activator {
        projection.push(col(ACTIVATOR_COL_NAME));
    }
    let df = DataFrame::new(session_state.clone(), input.clone()).select(projection)?;
    let mut out = Vec::new();
    for batch in collect_blocking(df)? {
        let values = cast(batch.column(0), &DataType::Utf8)?;
        let values = values.as_string::<i32>();
        let active: Option<&BooleanArray> = has_activator.then(|| batch.column(1).as_boolean());
        for i in 0..values.len() {
            if active.is_some_and(|a| !a.is_valid(i) || !a.value(i)) {
                continue;
            }
            out.push(if values.is_null(i) {
                Vec::new()
            } else {
                values.value(i).as_bytes().to_vec()
            });
        }
    }
    Ok(out)
}

/// Apply `PrefilterBins` hints: at each target path, which must hold a
/// `tt_prefilter` filter, set the bins it tests — or replace the filter by
/// its input when the list is empty. A non-empty list that is not a subset
/// of the pattern's bins is an error: the prover's plan kept a pre-filter
/// the verifier cannot accept. Only nodes on a path to a target are
/// rebuilt. Called by [`super::apply_optimization_hints`].
pub(super) fn apply_prefilter_bins_hints(
    plan: LogicalPlan,
    path: &mut Vec<usize>,
    targets: &mut BTreeMap<Vec<usize>, Vec<Bin>>,
) -> DataFusionResult<LogicalPlan> {
    if !targets.keys().any(|target| target.starts_with(path)) {
        return Ok(plan);
    }
    if let Some(bins) = targets.remove(path) {
        let LogicalPlan::Filter(filter) = &plan else {
            return Err(invalid_target(path, &plan));
        };
        let Some((col_expr, pattern, _)) = prefilter_args(&filter.predicate) else {
            return Err(invalid_target(path, &plan));
        };
        let Expr::Column(column) = col_expr else {
            return Err(invalid_target(path, &plan));
        };
        if bins.is_empty() {
            return Ok(filter.input.as_ref().clone());
        }
        if pattern_fingerprint(&column.name, &pattern, &bins).is_none() {
            return Err(DataFusionError::Plan(format!(
                "PrefilterBins hint at path {path:?} names bins {bins:?} that pattern '{pattern}' does not set on column '{}'",
                column.name
            )));
        }
        let predicate = tt_prefilter_expr(col_expr.clone(), &pattern, &bins);
        return Ok(LogicalPlan::Filter(Filter::try_new(
            predicate,
            filter.input.clone(),
        )?));
    }
    let new_inputs = plan
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(idx, input)| {
            path.push(idx);
            let rewritten = apply_prefilter_bins_hints(input.clone(), path, targets);
            path.pop();
            rewritten
        })
        .collect::<DataFusionResult<Vec<_>>>()?;
    plan.with_new_exprs(expressions_for_with_new_exprs(&plan), new_inputs)
}

fn invalid_target(path: &[usize], plan: &LogicalPlan) -> DataFusionError {
    DataFusionError::Plan(format!(
        "PrefilterBins hint at path {path:?} does not target a pre-filter: {}",
        plan.display()
    ))
}
