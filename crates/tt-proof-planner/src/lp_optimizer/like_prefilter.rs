//! Fingerprint pre-filter insertion (paper §7.1).
//!
//! Rewrites every `Filter(col LIKE 'pattern')` directly over a table scan
//! whose pattern sets some fingerprint bin into
//!
//! ```text
//! Filter(col LIKE 'pattern')
//!   Filter(tt_prefilter(col, 'pattern', '3,17,240'))   <- inserted
//!     TableScan
//! ```
//!
//! The inserted filter's predicate is the `tt_prefilter` scalar UDF (the
//! fingerprint subset test `fp(col) & φ == φ`), proven by the
//! PreFilteringCheck PIOP against the scan's committed fingerprint limbs;
//! the outer LIKE is untouched — matching rows always pass the fingerprint
//! test, so query semantics are unchanged. The inserted call lists every
//! bin the pattern sets; the data-dependent `PrefilterBinsRule` then
//! narrows it to the bins worth testing (or removes it), and when the
//! pre-filter shrinks the
//! row count below half the hypercube the data-dependent
//! `CompactionRule` wraps it in a `Compaction`, compacting the tables
//! the LIKE machinery sees.
//!
//! This runs as a deterministic post-pass AFTER the structural optimizer
//! (not as an `OptimizerRule` inside it): rules like
//! `MergeConsecutiveFilters` and `PushDownFilter` would otherwise fold
//! the inserted filter back into the LIKE filter on a later pass. Both
//! prover and verifier run the same post-pass, so the shapes agree.

use datafusion_common::Result as DataFusionResult;
use datafusion_common::tree_node::{Transformed, TreeNode};
use datafusion_expr::{Expr, Filter, LogicalPlan};
use std::sync::Arc;
use tt_core::irs::nodes::plan::exprs::fp_prefilter::{
    TT_PREFILTER_UDF_NAME, pattern_bins, tt_prefilter_expr,
};

/// The column, pattern and pattern bins when the LIKE lowering supports
/// this predicate AND the pattern has literal factors worth pre-filtering
/// on.
fn supported_like(expr: &Expr) -> Option<(Expr, String, Vec<arithmetic::fingerprint::Bin>)> {
    let Expr::Like(like) = expr else {
        return None;
    };
    if like.negated || like.case_insensitive || like.escape_char.is_some() {
        return None;
    }
    if !matches!(like.expr.as_ref(), Expr::Column(_)) {
        return None;
    }
    let pattern = match like.pattern.as_ref() {
        Expr::Literal(datafusion_common::ScalarValue::Utf8(Some(s)))
        | Expr::Literal(datafusion_common::ScalarValue::LargeUtf8(Some(s)))
        | Expr::Literal(datafusion_common::ScalarValue::Utf8View(Some(s))) => s.clone(),
        _ => return None,
    };
    // Only a column the table's rules fingerprint can be pre-filtered.
    let Expr::Column(col) = like.expr.as_ref() else {
        return None;
    };
    let bins = pattern_bins(&col.name, &pattern)?;
    Some((like.expr.as_ref().clone(), pattern, bins))
}

fn is_prefilter_filter(plan: &LogicalPlan) -> bool {
    matches!(
        plan,
        LogicalPlan::Filter(f)
            if matches!(
                &f.predicate,
                Expr::ScalarFunction(sf) if sf.name() == TT_PREFILTER_UDF_NAME
            )
    )
}

/// Insert fingerprint pre-filters in front of every supported LIKE
/// filter over a table scan (the only operator whose payload carries the
/// owner-committed fingerprint limbs). Idempotent: a LIKE filter whose
/// input is already the corresponding pre-filter is left alone.
pub fn insert_like_prefilters(plan: LogicalPlan) -> DataFusionResult<LogicalPlan> {
    let transformed = plan.transform_up(|node| {
        let LogicalPlan::Filter(filter) = &node else {
            return Ok(Transformed::no(node));
        };
        let Some((col_expr, pattern, bins)) = supported_like(&filter.predicate) else {
            return Ok(Transformed::no(node));
        };
        if is_prefilter_filter(filter.input.as_ref())
            || !matches!(filter.input.as_ref(), LogicalPlan::TableScan(_))
        {
            return Ok(Transformed::no(node));
        }
        let inner = LogicalPlan::Filter(Filter::try_new(
            tt_prefilter_expr(col_expr, &pattern, &bins),
            filter.input.clone(),
        )?);
        let outer =
            LogicalPlan::Filter(Filter::try_new(filter.predicate.clone(), Arc::new(inner))?);
        Ok(Transformed::yes(outer))
    })?;
    Ok(transformed.data)
}
