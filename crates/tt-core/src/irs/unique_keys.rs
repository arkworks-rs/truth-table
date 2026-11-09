//! The sets of a plan's output columns on which no two active rows agree.
//!
//! A set is listed only when the proof establishes it:
//! - a base table's declared primary key: the data owner commits data that
//!   conforms to its schema (paper §5.8, footnote 4);
//! - through Filter, Limit, Sort, aliases and Compaction, unchanged: each
//!   proves its active output rows a sub-multiset of its input's;
//! - through a projection, for the key columns it copies unchanged;
//! - a GROUP BY's group columns, which its Suppcheck proves distinct, and any
//!   input key among them: the output rows are input rows with the group
//!   columns as virtual copies (PIOP 17);
//! - through an inner equijoin, the union of a left and a right key, since
//!   the join proves its `(src_L, src_R)` pairs distinct and each output row
//!   equal to its source rows (PIOP 18; in PIOP 19 the foreign-key side's key
//!   alone is one). A side's keys stay keys when the other side's join columns
//!   hold one of its keys: each row then has at most one partner;
//! - the empty set for an ungrouped aggregate or a proved-empty table, which
//!   have at most one active row.
//!
//! Prover and verifier derive the sets from the same plan and the same
//! declared keys, so the checks they skip agree.

use std::collections::BTreeSet;

use datafusion_common::{Column, DFSchema};
use datafusion_expr::{Aggregate, Expr, Join, JoinType, LogicalPlan, Projection, TableScan};

use crate::irs::nodes::plan::{
    compaction::CompactionLogicalNode, proved_empty::ProvedEmptyLogicalNode,
    result_check::ResultCheckLogicalNode,
};

/// Output column indices of a plan.
pub type Key = BTreeSet<usize>;

/// The minimal unique keys of `plan`'s output.
pub fn unique_keys(plan: &LogicalPlan) -> Vec<Key> {
    let keys = match plan {
        LogicalPlan::TableScan(scan) => scan_keys(scan),
        LogicalPlan::Filter(filter) => unique_keys(&filter.input),
        LogicalPlan::Limit(limit) => unique_keys(&limit.input),
        LogicalPlan::Sort(sort) => unique_keys(&sort.input),
        LogicalPlan::SubqueryAlias(alias) => unique_keys(&alias.input),
        LogicalPlan::Projection(projection) => projection_keys(projection),
        LogicalPlan::Aggregate(aggregate) => aggregate_keys(aggregate),
        LogicalPlan::Join(join) => join_keys(join),
        LogicalPlan::Extension(extension) => {
            let node = extension.node.as_any();
            if node.is::<ProvedEmptyLogicalNode>() {
                vec![Key::new()]
            } else if let Some(compaction) = node.downcast_ref::<CompactionLogicalNode>() {
                same_columns_keys(plan, compaction.input())
            } else if let Some(result_check) = node.downcast_ref::<ResultCheckLogicalNode>() {
                same_columns_keys(plan, result_check.input())
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    };
    minimal(keys)
}

/// Whether `columns` of `plan`'s output contain one of its unique keys.
pub fn contains_unique_key(plan: &LogicalPlan, columns: &Key) -> bool {
    unique_keys(plan).iter().any(|key| key.is_subset(columns))
}

/// The input column that `expr` passes through unchanged: a column, under
/// aliases. A cast is not unchanged; narrowing one can merge values.
pub fn copied_input_index(expr: &Expr, input: &DFSchema) -> Option<usize> {
    match expr {
        Expr::Column(column) => column_index(input, column),
        Expr::Alias(alias) => copied_input_index(&alias.expr, input),
        _ => None,
    }
}

/// `column`'s index in `schema`, or the index of the one field of that name
/// when the qualifier does not match: a verifier's plan can carry stale
/// qualifiers, and both sides must resolve a column alike.
fn column_index(schema: &DFSchema, column: &Column) -> Option<usize> {
    if let Ok(index) = schema.index_of_column(column) {
        return Some(index);
    }
    let mut named = schema
        .fields()
        .iter()
        .enumerate()
        .filter(|(_, field)| field.name() == &column.name);
    let (index, _) = named.next()?;
    named.next().is_none().then_some(index)
}

fn scan_keys(scan: &TableScan) -> Vec<Key> {
    if !scan.filters.is_empty() || scan.fetch.is_some() {
        return Vec::new();
    }
    let Some(primary_key) = crate::irs::nodes::plan::lps::join::modes::primary_key_columns(scan)
    else {
        return Vec::new();
    };
    if primary_key.is_empty() {
        return Vec::new();
    }
    let fields = scan.projected_schema.fields();
    primary_key
        .iter()
        .map(|name| {
            fields
                .iter()
                .position(|field| field.name().to_lowercase() == *name)
        })
        .collect::<Option<Key>>()
        .into_iter()
        .collect()
}

fn projection_keys(projection: &Projection) -> Vec<Key> {
    let copies: Vec<Option<usize>> = projection
        .expr
        .iter()
        .map(|expr| copied_input_index(expr, projection.input.schema()))
        .collect();
    carry_keys(&unique_keys(&projection.input), &copies)
}

fn aggregate_keys(aggregate: &Aggregate) -> Vec<Key> {
    if aggregate.group_expr.is_empty() {
        return vec![Key::new()];
    }
    if aggregate
        .group_expr
        .iter()
        .any(|expr| matches!(expr, Expr::GroupingSet(_)))
    {
        return Vec::new();
    }
    // The output starts with one column per group expression.
    let copies: Vec<Option<usize>> = aggregate
        .group_expr
        .iter()
        .map(|expr| copied_input_index(expr, aggregate.input.schema()))
        .collect();
    let mut keys = vec![(0..aggregate.group_expr.len()).collect()];
    keys.extend(carry_keys(&unique_keys(&aggregate.input), &copies));
    keys
}

fn join_keys(join: &Join) -> Vec<Key> {
    if join.join_type != JoinType::Inner || join.filter.is_some() || join.on.is_empty() {
        return Vec::new();
    }
    let left = unique_keys(&join.left);
    let right = unique_keys(&join.right);
    let offset = join.left.schema().fields().len();
    let shifted = |key: &Key| key.iter().map(|index| index + offset).collect::<Key>();

    let mut keys: Vec<Key> = left
        .iter()
        .flat_map(|l| right.iter().map(move |r| l | &shifted(r)))
        .collect();
    // A join column under a cast is not one: the cast can merge values.
    let left_on: Option<Key> = join
        .on
        .iter()
        .map(|(l, _)| copied_input_index(l, join.left.schema()))
        .collect();
    let right_on: Option<Key> = join
        .on
        .iter()
        .map(|(_, r)| copied_input_index(r, join.right.schema()))
        .collect();
    let holds_key = |on: &Option<Key>, keys: &[Key]| {
        on.as_ref()
            .is_some_and(|on| keys.iter().any(|key| key.is_subset(on)))
    };
    if holds_key(&right_on, &right) {
        keys.extend(left.iter().cloned());
    }
    if holds_key(&left_on, &left) {
        keys.extend(right.iter().map(shifted));
    }
    keys
}

/// An identity node's keys, when its schema lists its input's columns.
fn same_columns_keys(plan: &LogicalPlan, input: &LogicalPlan) -> Vec<Key> {
    if plan.schema().fields().len() != input.schema().fields().len() {
        return Vec::new();
    }
    unique_keys(input)
}

/// The input keys every column of which some output column copies, in output
/// indices.
fn carry_keys(input_keys: &[Key], copies: &[Option<usize>]) -> Vec<Key> {
    input_keys
        .iter()
        .filter_map(|key| {
            key.iter()
                .map(|input| copies.iter().position(|copy| *copy == Some(*input)))
                .collect::<Option<Key>>()
        })
        .collect()
}

/// `keys` without duplicates and without any key that contains another.
fn minimal(mut keys: Vec<Key>) -> Vec<Key> {
    keys.sort_by_key(Key::len);
    let mut out: Vec<Key> = Vec::new();
    for key in keys {
        if !out.iter().any(|kept| kept.is_subset(&key)) {
            out.push(key);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::functions_aggregate::expr_fn::sum;
    use datafusion_expr::{JoinType, LogicalPlanBuilder, cast, col, lit, logical_plan::table_scan};

    use super::*;

    /// A scan of `table` whose committed schema declares `pk` its primary key.
    fn scan(table: &str, columns: &[&str], pk: &[&str]) -> LogicalPlanBuilder {
        let fields: Vec<Field> = columns
            .iter()
            .map(|name| {
                let mut metadata = HashMap::from([("tt.qualifier".to_string(), table.to_string())]);
                if pk.contains(name) {
                    metadata.insert("tt.pk".to_string(), "true".to_string());
                }
                Field::new(*name, DataType::Int64, false).with_metadata(metadata)
            })
            .collect();
        table_scan(Some(table), &Schema::new(fields), None).unwrap()
    }

    fn orders() -> LogicalPlanBuilder {
        scan("orders", &["o_orderkey", "o_custkey"], &["o_orderkey"])
    }

    fn customer() -> LogicalPlanBuilder {
        scan("customer", &["c_custkey", "c_nationkey"], &["c_custkey"])
    }

    fn lineitem() -> LogicalPlanBuilder {
        scan(
            "lineitem",
            &["l_orderkey", "l_linenumber", "l_quantity"],
            &["l_orderkey", "l_linenumber"],
        )
    }

    fn keys(plan: LogicalPlanBuilder) -> Vec<Vec<usize>> {
        unique_keys(&plan.build().unwrap())
            .into_iter()
            .map(|key| key.into_iter().collect())
            .collect()
    }

    fn group_by(plan: LogicalPlanBuilder, columns: &[&str]) -> LogicalPlanBuilder {
        let groups: Vec<Expr> = columns.iter().map(|name| col(*name)).collect();
        plan.aggregate(groups, Vec::<Expr>::new()).unwrap()
    }

    /// Whether a GROUP BY on `columns` skips its NoDupcheck.
    fn groups_unique(plan: LogicalPlanBuilder, columns: &[&str]) -> bool {
        let plan = plan.build().unwrap();
        let columns = columns
            .iter()
            .map(|name| copied_input_index(&col(*name), plan.schema()).unwrap())
            .collect();
        contains_unique_key(&plan, &columns)
    }

    #[test]
    fn a_scan_is_keyed_by_its_whole_primary_key() {
        assert_eq!(keys(orders()), vec![vec![0]]);
        assert_eq!(keys(lineitem()), vec![vec![0, 1]]);
        assert!(!groups_unique(lineitem(), &["l_orderkey"]));
        assert!(groups_unique(
            lineitem(),
            &["l_quantity", "l_linenumber", "l_orderkey"]
        ));
    }

    #[test]
    fn row_subsets_keep_keys() {
        let plan = lineitem()
            .filter(col("l_quantity").gt(lit(3_i64)))
            .unwrap()
            .sort(vec![col("l_quantity").sort(true, false)])
            .unwrap()
            .limit(0, Some(5))
            .unwrap()
            .alias("l")
            .unwrap();
        assert_eq!(keys(plan), vec![vec![0, 1]]);
    }

    #[test]
    fn a_projection_keeps_the_keys_it_copies() {
        let reordered = lineitem()
            .project(vec![
                col("l_quantity"),
                col("l_linenumber").alias("line"),
                col("l_orderkey"),
            ])
            .unwrap();
        assert_eq!(keys(reordered), vec![vec![1, 2]]);

        let dropped = lineitem()
            .project(vec![col("l_orderkey"), col("l_quantity")])
            .unwrap();
        assert!(keys(dropped).is_empty());

        let cast_key = orders()
            .project(vec![cast(col("o_orderkey"), DataType::Int32)])
            .unwrap();
        assert!(keys(cast_key).is_empty());
    }

    #[test]
    fn an_aggregate_is_keyed_by_its_groups_and_the_input_keys_among_them() {
        let grouped = group_by(lineitem(), &["l_quantity", "l_orderkey"]);
        assert_eq!(keys(grouped), vec![vec![0, 1]]);

        let over_key = group_by(orders(), &["o_custkey", "o_orderkey"]);
        assert_eq!(keys(over_key), vec![vec![1]]);

        let ungrouped = lineitem()
            .aggregate(Vec::<Expr>::new(), vec![sum(col("l_quantity"))])
            .unwrap();
        assert_eq!(keys(ungrouped), vec![Vec::<usize>::new()]);

        // A GROUP BY over a GROUP BY's output reuses the first one's proof.
        assert!(groups_unique(
            group_by(lineitem(), &["l_orderkey"]),
            &["l_orderkey"]
        ));
    }

    #[test]
    fn a_join_keeps_a_side_key_only_when_each_row_has_one_partner() {
        // Each order has one customer: orders' key survives, customer's does not.
        let orders_customer = orders()
            .join(
                customer().build().unwrap(),
                JoinType::Inner,
                (vec!["o_custkey"], vec!["c_custkey"]),
                None,
            )
            .unwrap();
        assert_eq!(keys(orders_customer.clone()), vec![vec![0]]);
        assert!(groups_unique(orders_customer.clone(), &["o_orderkey"]));
        assert!(!groups_unique(orders_customer, &["c_custkey"]));

        // An order has many line items: only lineitem's key survives.
        let orders_lineitem = orders()
            .join(
                lineitem().build().unwrap(),
                JoinType::Inner,
                (vec!["o_orderkey"], vec!["l_orderkey"]),
                None,
            )
            .unwrap();
        assert_eq!(keys(orders_lineitem.clone()), vec![vec![2, 3]]);
        assert!(!groups_unique(orders_lineitem, &["o_orderkey"]));

        // Neither side's join columns hold a key: only the pair of keys does.
        let lineitem_customer = lineitem()
            .join(
                customer().build().unwrap(),
                JoinType::Inner,
                (vec!["l_quantity"], vec!["c_nationkey"]),
                None,
            )
            .unwrap();
        assert_eq!(keys(lineitem_customer), vec![vec![0, 1, 3]]);
    }

    #[test]
    fn non_inner_joins_have_no_keys() {
        let left = orders()
            .join(
                customer().build().unwrap(),
                JoinType::Left,
                (vec!["o_custkey"], vec!["c_custkey"]),
                None,
            )
            .unwrap();
        assert!(keys(left).is_empty());
    }
}
