//! A dishonest prover for tests. A [`JoinForgery`] rewrites a many-to-many
//! join's matching pairs before any witness is derived from them, in both
//! places that compute them (the output hint and the gadget's source maps),
//! so every witness carries the same forgery. A [`SortForgery`] reverses an
//! ORDER BY, or its last key, in the prover's plan. A count forgery shifts
//! every COUNT an Aggregate outputs. A claimed-result rewrite
//! makes the prover claim the result of the forged plan, so the result check
//! passes and only the forged operator's own checks can reject.
//!
//! Both are process-wide: a test that installs one must be the only test of
//! its binary that proves meanwhile.

use std::sync::Mutex;

use datafusion::arrow::compute::concat_batches;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::prelude::DataFrame;
use datafusion_common::{Column, Result as DataFusionResult, ScalarValue};
use datafusion_expr::{Expr, JoinType, SortExpr, lit, not};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinForgery {
    /// Leave out the first pair: the count no longer matches the keys.
    DropFirst,
    /// Repeat the first pair in place of the last: a duplicated source pair,
    /// with the honest count.
    DuplicateFirst,
    /// Pair the first left row with the last right row whose key differs.
    MismatchFirst,
}

static FORGERY: Mutex<Option<JoinForgery>> = Mutex::new(None);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortForgery {
    /// Every ORDER BY output is sorted against its keys' directions; the
    /// sort check's witnesses (sorted keys and ranks, rotation, ties) stay
    /// those of the honest order.
    ReverseOutput,
    /// The output and the sort check's witnesses alike: they agree with each
    /// other, and only the order of the sorted keys is wrong.
    ReverseOutputAndWitnesses,
    /// Only the last ORDER BY key of the output is sorted against its
    /// direction, the earlier keys keep theirs; the sort check's witnesses
    /// stay those of the honest order. The wrong order is then only inside
    /// the earlier keys' ties.
    ReverseLastKey,
}

static SORT_FORGERY: Mutex<Option<SortForgery>> = Mutex::new(None);

static COUNT_FORGERY: Mutex<Option<i64>> = Mutex::new(None);

pub type ResultRewrite = Box<dyn Fn(Vec<RecordBatch>) -> Vec<RecordBatch> + Send>;

static CLAIMED_RESULT: Mutex<Option<ResultRewrite>> = Mutex::new(None);

pub fn set_join_forgery(forgery: Option<JoinForgery>) {
    *FORGERY.lock().expect("lock poisoned") = forgery;
}

pub fn set_sort_forgery(forgery: Option<SortForgery>) {
    *SORT_FORGERY.lock().expect("lock poisoned") = forgery;
}

/// The ORDER BY keys the prover's Sort output is sorted on.
pub(crate) fn forge_sort_exprs(exprs: Vec<SortExpr>) -> Vec<SortExpr> {
    match *SORT_FORGERY.lock().expect("lock poisoned") {
        Some(SortForgery::ReverseLastKey) => {
            let mut exprs = exprs;
            if let Some(last) = exprs.pop() {
                exprs.push(last.reverse());
            }
            exprs
        }
        Some(_) => exprs.into_iter().map(|expr| expr.reverse()).collect(),
        None => exprs,
    }
}

/// The keys the sort check's witnesses are planned on, as `(column,
/// ascending, nulls first)`.
pub(crate) fn forge_sort_specs(specs: Vec<(String, bool, bool)>) -> Vec<(String, bool, bool)> {
    match *SORT_FORGERY.lock().expect("lock poisoned") {
        Some(SortForgery::ReverseOutputAndWitnesses) => specs
            .into_iter()
            .map(|(name, asc, nulls_first)| (name, !asc, nulls_first))
            .collect(),
        _ => specs,
    }
}

/// Adds `offset` to every COUNT the prover's Aggregates output.
pub fn set_count_forgery(offset: Option<i64>) {
    *COUNT_FORGERY.lock().expect("lock poisoned") = offset;
}

/// `output`, an Aggregate's output, with the installed count forgery applied
/// to its COUNT columns `counts`.
pub(crate) fn forge_counts(output: DataFrame, counts: &[String]) -> DataFrame {
    let Some(offset) = *COUNT_FORGERY.lock().expect("lock poisoned") else {
        return output;
    };
    let exprs = output
        .schema()
        .columns()
        .into_iter()
        .map(|column| {
            if counts.contains(&column.name) {
                let name = column.name.clone();
                (Expr::Column(column) + lit(offset)).alias(name)
            } else {
                Expr::Column(column)
            }
        })
        .collect::<Vec<_>>();
    output.select(exprs).expect("forged counts select")
}

pub fn set_claimed_result(rewrite: Option<ResultRewrite>) {
    *CLAIMED_RESULT.lock().expect("lock poisoned") = rewrite;
}

/// The result the prover claims: `batches`, its executed result, through the
/// installed rewrite.
pub fn claimed_result(batches: Vec<RecordBatch>) -> Vec<RecordBatch> {
    match CLAIMED_RESULT.lock().expect("lock poisoned").as_ref() {
        Some(rewrite) => rewrite(batches),
        None => batches,
    }
}

/// `joined`, the inner join of `left` and `right` with `left`'s columns
/// first, with the installed forgery applied. "First" and "last" are in
/// (left row id, right row id) order.
pub(crate) fn forge(
    joined: DataFrame,
    left: &DataFrame,
    right: &DataFrame,
    left_row_id: &Column,
    right_row_id: &Column,
    right_keys: &[Expr],
) -> DataFusionResult<DataFrame> {
    let Some(forgery) = *FORGERY.lock().expect("lock poisoned") else {
        return Ok(joined);
    };
    let left_id = || Expr::Column(left_row_id.clone());
    let right_id = || Expr::Column(right_row_id.clone());
    let mut columns = vec![left_id(), right_id()];
    columns.extend(right_keys.iter().cloned());
    let ids = joined.clone().select(columns)?;
    let schema = std::sync::Arc::new(ids.schema().as_arrow().clone());
    let batch = concat_batches(&schema, &crate::session::block_on(ids.collect())?)?;
    let rows: Vec<Vec<ScalarValue>> = (0..batch.num_rows())
        .map(|row| {
            batch
                .columns()
                .iter()
                .map(|column| ScalarValue::try_from_array(column, row))
                .collect()
        })
        .collect::<DataFusionResult<_>>()?;
    let pair = |row: &Vec<ScalarValue>| (row[0].clone(), row[1].clone());
    let first = rows
        .iter()
        .min_by(|a, b| pair(a).partial_cmp(&pair(b)).unwrap());
    let last = rows
        .iter()
        .max_by(|a, b| pair(a).partial_cmp(&pair(b)).unwrap());
    let (Some(first), Some(last)) = (first, last) else {
        return Ok(joined);
    };
    let is = |row: &Vec<ScalarValue>| {
        left_id()
            .eq(lit(row[0].clone()))
            .and(right_id().eq(lit(row[1].clone())))
    };
    match forgery {
        JoinForgery::DropFirst => joined.filter(not(is(first))),
        JoinForgery::DuplicateFirst => joined
            .clone()
            .filter(not(is(last)))?
            .union(joined.filter(is(first))?),
        JoinForgery::MismatchFirst => {
            let other = rows
                .iter()
                .filter(|row| row[2..] != first[2..])
                .max_by(|a, b| a[1].partial_cmp(&b[1]).unwrap())
                .expect("a right row with another key");
            let forged = left
                .clone()
                .filter(left_id().eq(lit(first[0].clone())))?
                .join_on(
                    right.clone().filter(right_id().eq(lit(other[1].clone())))?,
                    JoinType::Inner,
                    [lit(true)],
                )?;
            joined.filter(not(is(first)))?.union(forged)
        }
    }
}
