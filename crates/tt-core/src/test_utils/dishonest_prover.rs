//! A dishonest prover for tests. A [`JoinForgery`] rewrites a many-to-many
//! join's matching pairs before any witness is derived from them, in both
//! places that compute them (the output hint and the gadget's source maps),
//! so every witness carries the same forgery. A [`SortForgery`] reverses an
//! ORDER BY, or its last key, in the prover's plan. A count forgery shifts
//! every COUNT an Aggregate outputs. A duplicate-groups forgery outputs every
//! group of a GROUP BY twice. A rescale forgery adds one to every
//! cast output that divides by `10^k`. An unowned-scan forgery commits the
//! scanned tables itself instead of loading the owner's oracles. A
//! claimed-result rewrite makes the prover claim the result of the forged
//! plan, so the result check passes and only the forged operator's own
//! checks can reject.
//!
//! Every hook is process-wide: a test that installs one must be the only
//! test of its binary that proves meanwhile. A setter returns an
//! [`Installed`] that uninstalls the hook when dropped, so a test that panics
//! while proving does not leave it to the tests after it.

use std::sync::{Mutex, PoisonError};

use arithmetic::encoding::BaseRanks;

use datafusion::arrow::compute::concat_batches;
use datafusion::arrow::datatypes::DataType;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::prelude::DataFrame;
use datafusion_common::{Column, Result as DataFusionResult, ScalarValue};
use datafusion_expr::{Expr, ExprFunctionExt, JoinType, SortExpr, lit, not};

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
    /// The output, and every rank the prover encodes above a table scan,
    /// reversed so that the reversed output is in order on them. The sort
    /// check and its witnesses agree; only the binding of the ranks to the
    /// owner's, at the first node above the scans that commits them, can
    /// reject.
    ReverseOutputAndRanks,
    /// Only the last ORDER BY key of the output is sorted against its
    /// direction, the earlier keys keep theirs; the sort check's witnesses
    /// stay those of the honest order. The wrong order is then only inside
    /// the earlier keys' ties.
    ReverseLastKey,
}

static SORT_FORGERY: Mutex<Option<SortForgery>> = Mutex::new(None);

static COUNT_FORGERY: Mutex<Option<i64>> = Mutex::new(None);

static RESCALE_FORGERY: Mutex<Option<()>> = Mutex::new(None);

static UNOWNED_SCANS: Mutex<Option<()>> = Mutex::new(None);

pub type ResultRewrite = Box<dyn Fn(Vec<RecordBatch>) -> Vec<RecordBatch> + Send>;

static CLAIMED_RESULT: Mutex<Option<ResultRewrite>> = Mutex::new(None);

#[must_use = "the hook is uninstalled when this is dropped"]
pub struct Installed<T: 'static>(&'static Mutex<Option<T>>);

impl<T: 'static> Drop for Installed<T> {
    fn drop(&mut self) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

fn install<T>(hook: &'static Mutex<Option<T>>, value: T) -> Installed<T> {
    *hook.lock().unwrap_or_else(PoisonError::into_inner) = Some(value);
    Installed(hook)
}

pub fn set_join_forgery(forgery: JoinForgery) -> Installed<JoinForgery> {
    install(&FORGERY, forgery)
}

pub fn set_sort_forgery(forgery: SortForgery) -> Installed<SortForgery> {
    install(&SORT_FORGERY, forgery)
}

/// The ORDER BY keys the prover's Sort output is sorted on.
pub(crate) fn forge_sort_exprs(exprs: Vec<SortExpr>) -> Vec<SortExpr> {
    match *SORT_FORGERY.lock().unwrap_or_else(PoisonError::into_inner) {
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
    match *SORT_FORGERY.lock().unwrap_or_else(PoisonError::into_inner) {
        Some(SortForgery::ReverseOutputAndWitnesses) => specs
            .into_iter()
            .map(|(name, asc, nulls_first)| (name, !asc, nulls_first))
            .collect(),
        _ => specs,
    }
}

/// `ranks`, a base column's ranks as the prover encodes them above its
/// table scans, with the installed sort forgery applied.
pub(crate) fn forge_base_ranks(ranks: BaseRanks) -> BaseRanks {
    if *SORT_FORGERY.lock().unwrap_or_else(PoisonError::into_inner)
        != Some(SortForgery::ReverseOutputAndRanks)
    {
        return ranks;
    }
    let top = ranks.values().copied().max().unwrap_or(0);
    ranks
        .into_iter()
        .map(|(value, rank)| (value, top - rank))
        .collect()
}

/// Adds `offset` to every COUNT the prover's Aggregates output.
pub fn set_count_forgery(offset: i64) -> Installed<i64> {
    install(&COUNT_FORGERY, offset)
}

/// `output`, an Aggregate's output, with the installed count forgery applied
/// to its COUNT columns `counts`.
pub(crate) fn forge_counts(output: DataFrame, counts: &[String]) -> DataFrame {
    let Some(offset) = *COUNT_FORGERY.lock().unwrap_or_else(PoisonError::into_inner) else {
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

static SPLIT_UNGROUPED: Mutex<Option<()>> = Mutex::new(None);

/// Makes every Aggregate without GROUP BY output its values on two active
/// rows: the first row holds each value minus one, the second row one.
pub fn set_split_ungrouped_forgery() -> Installed<()> {
    install(&SPLIT_UNGROUPED, ())
}

/// `output`, the output of an Aggregate without GROUP BY whose value
/// columns are `values`, with the installed split forgery applied.
pub(crate) fn forge_split_ungrouped(output: DataFrame, values: &[String]) -> DataFrame {
    if SPLIT_UNGROUPED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .is_none()
    {
        return output;
    }
    let row_id = output
        .schema()
        .columns()
        .into_iter()
        .find(|column| column.name == arithmetic::ROW_ID_COL_NAME)
        .expect("the aggregate output carries a row id");
    let position = datafusion::functions_window::expr_fn::row_number()
        .order_by(vec![Expr::Column(row_id).sort(true, true)])
        .build()
        .expect("row number window")
        .alias("__split_position__");
    let output = output.window(vec![position]).expect("row number");
    let row = |index: i64| datafusion_expr::col("__split_position__").eq(lit(index + 1));
    let exprs = output
        .schema()
        .columns()
        .into_iter()
        .map(|column| {
            let name = column.name.clone();
            if values.contains(&name) {
                datafusion_expr::when(row(0), Expr::Column(column.clone()) - lit(1i64))
                    .when(row(1), lit(1i64))
                    .otherwise(Expr::Column(column))
                    .unwrap()
                    .alias(name)
            } else if name == arithmetic::ACTIVATOR_COL_NAME {
                row(0).or(row(1)).alias(name)
            } else {
                Expr::Column(column)
            }
        })
        .filter(|expr| expr.schema_name().to_string() != "__split_position__")
        .collect::<Vec<_>>();
    output.select(exprs).expect("forged split select")
}

static DUPLICATE_GROUPS: Mutex<Option<()>> = Mutex::new(None);

/// Makes every Aggregate with GROUP BY also activate the second row of each
/// group, so the output holds every group twice, and every lookup spread a
/// repeated super value's multiplicity over its copies, so each copy has a
/// nonzero one as Suppcheck requires.
pub fn set_duplicate_groups_forgery() -> Installed<()> {
    install(&DUPLICATE_GROUPS, ())
}

/// `first`, the condition that picks a group's representative among its
/// rows ordered active first, with the installed duplicate-groups forgery
/// applied: the second such row is picked too.
pub(crate) fn forge_representatives(first: Expr, ungrouped: bool) -> Expr {
    if ungrouped
        || DUPLICATE_GROUPS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none()
    {
        return first;
    }
    first.or(datafusion_expr::col("__row_number__").eq(lit(2_i64)))
}

/// `counts`, a lookup's multiplicities with each value's count on its first
/// super row, with the installed duplicate-groups forgery applied: every
/// later copy of a value takes 1 from the first while the first keeps one.
/// `super_rows` lists the active super rows by key, ties by row.
pub(crate) fn spread_duplicate_multiplicities<K: PartialEq>(
    super_rows: &[(K, usize)],
    counts: &mut [u64],
) {
    if DUPLICATE_GROUPS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .is_none()
    {
        return;
    }
    let mut first: Option<(&K, usize)> = None;
    for (key, row) in super_rows {
        match first {
            Some((first_key, first_row)) if first_key == key => {
                if counts[first_row] > 1 {
                    counts[first_row] -= 1;
                    counts[*row] = 1;
                }
            }
            _ => first = Some((key, *row)),
        }
    }
}

pub fn set_rescale_forgery() -> Installed<()> {
    install(&RESCALE_FORGERY, ())
}

/// `cast`, a cast to `data_type` that divides, with the installed rescale
/// forgery applied.
pub(crate) fn forge_rescale(cast: Expr, data_type: &DataType) -> Expr {
    if RESCALE_FORGERY
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .is_none()
    {
        return cast;
    }
    let name = cast.schema_name().to_string();
    let one = ScalarValue::Int64(Some(1))
        .cast_to(data_type)
        .expect("one in the cast's type");
    datafusion_expr::cast(cast + lit(one), data_type.clone()).alias(name)
}

static IN_LIST_FORGERY: Mutex<Option<()>> = Mutex::new(None);

pub fn set_in_list_forgery() -> Installed<()> {
    install(&IN_LIST_FORGERY, ())
}

/// `in_list` negated when the IN-list forgery is installed.
pub(crate) fn forge_in_list(in_list: Expr) -> Expr {
    if IN_LIST_FORGERY
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .is_none()
    {
        return in_list;
    }
    Expr::Not(Box::new(in_list))
}

pub fn set_unowned_scans() -> Installed<()> {
    install(&UNOWNED_SCANS, ())
}

pub(crate) fn scans_unowned() -> bool {
    UNOWNED_SCANS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .is_some()
}

static EMPTY_FIRST_FILTER: Mutex<Option<()>> = Mutex::new(None);

/// Makes the prover mark the plan's first Filter as proved empty, whatever
/// its output.
pub fn set_empty_first_filter() -> Installed<()> {
    install(&EMPTY_FIRST_FILTER, ())
}

/// The path of the first Filter of `plan` in pre-order, when the installed
/// forgery marks it as proved empty.
pub fn forged_empty_path(plan: &datafusion_expr::LogicalPlan) -> Option<Vec<usize>> {
    fn first_filter(plan: &datafusion_expr::LogicalPlan, path: &mut Vec<usize>) -> bool {
        if matches!(plan, datafusion_expr::LogicalPlan::Filter(_)) {
            return true;
        }
        for (index, input) in plan.inputs().into_iter().enumerate() {
            path.push(index);
            if first_filter(input, path) {
                return true;
            }
            path.pop();
        }
        false
    }
    EMPTY_FIRST_FILTER
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()?;
    let mut path = Vec::new();
    first_filter(plan, &mut path).then_some(path)
}

pub fn set_claimed_result(rewrite: ResultRewrite) -> Installed<ResultRewrite> {
    install(&CLAIMED_RESULT, rewrite)
}

/// The result the prover claims: `batches`, its executed result, through the
/// installed rewrite.
pub fn claimed_result(batches: Vec<RecordBatch>) -> Vec<RecordBatch> {
    match CLAIMED_RESULT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_ref()
    {
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
    let Some(forgery) = *FORGERY.lock().unwrap_or_else(PoisonError::into_inner) else {
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
