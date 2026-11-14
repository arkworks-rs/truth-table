//! Functional dependencies among a plan's output columns: column sets whose
//! values fix other columns' values on every active row.
//!
//! A dependency is listed only when the data and the plan imply it:
//! - a base table's declared primary key fixes all its columns, on any subset
//!   of its rows;
//! - through Filter, Limit, Sort, aliases, Compaction and ResultCheck,
//!   unchanged;
//! - through a projection, among the columns it copies unchanged;
//! - through an inner equijoin, each side's dependencies, and each `on` pair
//!   fixes one another;
//! - a GROUP BY's group columns fix its whole output, and the input's
//!   dependencies among the group columns carry over.
//!
//! The NoDupcheck of a GROUP BY uses them to compare fewer columns
//! (`irs::nodes::utils::nodup`). Distinctness on any subset of the columns
//! implies distinctness on all of them, so a wrong dependency cannot make a
//! proof accept; it only makes the honest prover fail.

use std::collections::BTreeSet;

use datafusion_expr::{Aggregate, Join, JoinType, LogicalPlan, Projection, TableScan};

use crate::irs::nodes::plan::{
    compaction::CompactionLogicalNode, result_check::ResultCheckLogicalNode,
};
use crate::irs::unique_keys::copied_input_index;

/// Output column indices of a plan.
pub type Columns = BTreeSet<usize>;

/// `from` fixes `to` on every active row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dependency {
    pub from: Columns,
    pub to: Columns,
}

pub fn dependencies(plan: &LogicalPlan) -> Vec<Dependency> {
    match plan {
        LogicalPlan::TableScan(scan) => scan_dependencies(scan),
        LogicalPlan::Filter(filter) => dependencies(&filter.input),
        LogicalPlan::Limit(limit) => dependencies(&limit.input),
        LogicalPlan::Sort(sort) => dependencies(&sort.input),
        LogicalPlan::SubqueryAlias(alias) => dependencies(&alias.input),
        LogicalPlan::Projection(projection) => projection_dependencies(projection),
        LogicalPlan::Aggregate(aggregate) => aggregate_dependencies(aggregate),
        LogicalPlan::Join(join) => join_dependencies(join),
        LogicalPlan::Extension(extension) => {
            let node = extension.node.as_any();
            let input = if let Some(compaction) = node.downcast_ref::<CompactionLogicalNode>() {
                compaction.input()
            } else if let Some(result_check) = node.downcast_ref::<ResultCheckLogicalNode>() {
                result_check.input()
            } else {
                return Vec::new();
            };
            if plan.schema().fields().len() == input.schema().fields().len() {
                dependencies(input)
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

/// The columns `columns` fix under `dependencies`, `columns` included.
pub fn closure(dependencies: &[Dependency], columns: &Columns) -> Columns {
    let mut closed = columns.clone();
    loop {
        let before = closed.len();
        for dependency in dependencies {
            if dependency.from.is_subset(&closed) {
                closed.extend(dependency.to.iter().copied());
            }
        }
        if closed.len() == before {
            return closed;
        }
    }
}

fn scan_dependencies(scan: &TableScan) -> Vec<Dependency> {
    let Some(primary_key) = crate::irs::nodes::plan::lps::join::modes::primary_key_columns(scan)
    else {
        return Vec::new();
    };
    if primary_key.is_empty() {
        return Vec::new();
    }
    let fields = scan.projected_schema.fields();
    let Some(from) = primary_key
        .iter()
        .map(|name| {
            fields
                .iter()
                .position(|field| field.name().to_lowercase() == *name)
        })
        .collect::<Option<Columns>>()
    else {
        return Vec::new();
    };
    vec![Dependency {
        from,
        to: (0..fields.len()).collect(),
    }]
}

fn projection_dependencies(projection: &Projection) -> Vec<Dependency> {
    let copies: Vec<Option<usize>> = projection
        .expr
        .iter()
        .map(|expr| copied_input_index(expr, projection.input.schema()))
        .collect();
    carry(&dependencies(&projection.input), &copies)
}

fn aggregate_dependencies(aggregate: &Aggregate) -> Vec<Dependency> {
    let groups = aggregate.group_expr.len();
    let copies: Vec<Option<usize>> = aggregate
        .group_expr
        .iter()
        .map(|expr| copied_input_index(expr, aggregate.input.schema()))
        .collect();
    let mut out = carry(&dependencies(&aggregate.input), &copies);
    out.push(Dependency {
        from: (0..groups).collect(),
        to: (0..aggregate.schema.fields().len()).collect(),
    });
    out
}

fn join_dependencies(join: &Join) -> Vec<Dependency> {
    if join.join_type != JoinType::Inner {
        return Vec::new();
    }
    let offset = join.left.schema().fields().len();
    let shift = |columns: &Columns| columns.iter().map(|index| index + offset).collect();
    let mut out = dependencies(&join.left);
    out.extend(
        dependencies(&join.right)
            .iter()
            .map(|dependency| Dependency {
                from: shift(&dependency.from),
                to: shift(&dependency.to),
            }),
    );
    // A join column under a cast is not one: the cast can merge values.
    for (left, right) in &join.on {
        if let (Some(left), Some(right)) = (
            copied_input_index(left, join.left.schema()),
            copied_input_index(right, join.right.schema()),
        ) {
            let (left, right) = (Columns::from([left]), Columns::from([right + offset]));
            out.push(Dependency {
                from: left.clone(),
                to: right.clone(),
            });
            out.push(Dependency {
                from: right,
                to: left,
            });
        }
    }
    out
}

/// The input dependencies whose every determining column some output column
/// copies, in output indices, each with all it fixes in the input: a chain
/// through dropped columns (a join column projected away) still holds. Copies
/// of one input column fix one another.
fn carry(input: &[Dependency], copies: &[Option<usize>]) -> Vec<Dependency> {
    let outputs_of = |input: usize| -> Columns {
        copies
            .iter()
            .enumerate()
            .filter_map(|(output, copy)| (*copy == Some(input)).then_some(output))
            .collect()
    };
    let mut out: Vec<Dependency> = input
        .iter()
        .filter_map(|dependency| {
            let from = dependency
                .from
                .iter()
                .map(|&column| outputs_of(column).first().copied())
                .collect::<Option<Columns>>()?;
            let to: Columns = closure(input, &dependency.from)
                .iter()
                .flat_map(|&column| outputs_of(column))
                .collect();
            (!to.is_empty()).then_some(Dependency { from, to })
        })
        .collect();
    for copy in copies.iter().flatten() {
        let same = outputs_of(*copy);
        for &output in &same {
            out.push(Dependency {
                from: Columns::from([output]),
                to: same.clone(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion_expr::{
        Expr, JoinType, LogicalPlanBuilder, cast, col, lit, logical_plan::table_scan,
    };

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

    fn customer() -> LogicalPlanBuilder {
        scan(
            "customer",
            &["c_custkey", "c_name", "c_nationkey"],
            &["c_custkey"],
        )
    }

    fn nation() -> LogicalPlanBuilder {
        scan("nation", &["n_nationkey", "n_name"], &["n_nationkey"])
    }

    fn orders() -> LogicalPlanBuilder {
        scan(
            "orders",
            &["o_orderkey", "o_custkey", "o_totalprice"],
            &["o_orderkey"],
        )
    }

    /// The columns of `plan` named `from` fix, by name.
    fn fixed(plan: LogicalPlanBuilder, from: &[&str]) -> Vec<String> {
        let plan = plan.build().unwrap();
        let schema = plan.schema();
        let start = from
            .iter()
            .map(|name| copied_input_index(&col(*name), schema).unwrap())
            .collect();
        closure(&dependencies(&plan), &start)
            .into_iter()
            .map(|index| schema.field(index).name().clone())
            .collect()
    }

    #[test]
    fn a_primary_key_fixes_its_table_through_a_filter() {
        let plan = customer().filter(col("c_name").eq(lit(1_i64))).unwrap();
        assert_eq!(
            fixed(plan, &["c_custkey"]),
            ["c_custkey", "c_name", "c_nationkey"]
        );
        assert_eq!(fixed(customer(), &["c_name"]), ["c_name"]);
    }

    #[test]
    fn a_join_carries_both_sides_and_its_equalities() {
        let plan = orders()
            .join(
                customer().build().unwrap(),
                JoinType::Inner,
                (vec!["o_custkey"], vec!["c_custkey"]),
                None,
            )
            .unwrap()
            .join(
                nation().build().unwrap(),
                JoinType::Inner,
                (vec!["c_nationkey"], vec!["n_nationkey"]),
                None,
            )
            .unwrap();
        let mut all = fixed(plan, &["o_orderkey"]);
        all.sort();
        assert_eq!(
            all,
            [
                "c_custkey",
                "c_name",
                "c_nationkey",
                "n_name",
                "n_nationkey",
                "o_custkey",
                "o_orderkey",
                "o_totalprice"
            ]
        );
    }

    #[test]
    fn a_cast_join_column_carries_no_equality() {
        let plan = orders()
            .join_on(
                customer().build().unwrap(),
                JoinType::Inner,
                vec![cast(col("o_custkey"), DataType::Int32).eq(col("c_custkey"))],
            )
            .unwrap();
        assert!(!fixed(plan, &["o_orderkey"]).contains(&"c_name".to_string()));
    }

    #[test]
    fn a_projection_keeps_a_chain_through_the_columns_it_drops() {
        let plan = customer()
            .join(
                nation().build().unwrap(),
                JoinType::Inner,
                (vec!["c_nationkey"], vec!["n_nationkey"]),
                None,
            )
            .unwrap()
            .project(vec![col("c_custkey"), col("n_name")])
            .unwrap();
        assert_eq!(fixed(plan, &["c_custkey"]), ["c_custkey", "n_name"]);
    }

    #[test]
    fn a_projection_and_an_aggregate_keep_what_they_copy() {
        let plan = customer()
            .project(vec![col("c_name"), col("c_custkey").alias("k")])
            .unwrap();
        assert_eq!(fixed(plan, &["k"]), ["c_name", "k"]);

        let plan = customer()
            .aggregate(vec![col("c_custkey"), col("c_name")], Vec::<Expr>::new())
            .unwrap();
        assert_eq!(fixed(plan, &["c_custkey"]), ["c_custkey", "c_name"]);
    }
}
