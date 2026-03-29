use std::sync::Arc;

use datafusion::{config::ConfigOptions, optimizer::analyzer::AnalyzerRule};
use datafusion_common::{
    Result,
    tree_node::{Transformed, TreeNode},
};
use datafusion_expr::{
    Expr,
    expr::{Exists, InSubquery},
    logical_plan::{LogicalPlan, Subquery},
};
use tt_core::irs::nodes::plan::result_check::{self, ResultCheckLogicalNode};

#[derive(Debug, Default)]
pub(crate) struct AddResultCheck;

impl AddResultCheck {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl AnalyzerRule for AddResultCheck {
    fn name(&self) -> &str {
        "add_result_check"
    }

    fn analyze(&self, plan: LogicalPlan, _config: &ConfigOptions) -> Result<LogicalPlan> {
        add_result_check(plan)
    }
}

fn add_result_check(plan: LogicalPlan) -> Result<LogicalPlan> {
    let plan = plan
        .map_expressions(rewrite_subqueries_with_result_check)?
        .data;
    if is_result_check_plan(&plan) {
        Ok(plan)
    } else {
        Ok(result_check::wrap_logical_plan(plan))
    }
}

fn rewrite_subqueries_with_result_check(expr: Expr) -> Result<Transformed<Expr>> {
    expr.transform_up(|expr| match expr {
        Expr::ScalarSubquery(Subquery {
            subquery,
            outer_ref_columns,
        }) => Ok(Transformed::yes(Expr::ScalarSubquery(Subquery {
            subquery: Arc::new(add_result_check(Arc::unwrap_or_clone(subquery))?),
            outer_ref_columns,
        }))),
        Expr::Exists(Exists { subquery, negated }) => {
            Ok(Transformed::yes(Expr::Exists(Exists {
                subquery: Subquery {
                    subquery: Arc::new(add_result_check(Arc::unwrap_or_clone(subquery.subquery))?),
                    outer_ref_columns: subquery.outer_ref_columns,
                },
                negated,
            })))
        }
        Expr::InSubquery(InSubquery {
            expr: input_expr,
            subquery,
            negated,
        }) => Ok(Transformed::yes(Expr::InSubquery(InSubquery::new(
            input_expr,
            Subquery {
                subquery: Arc::new(add_result_check(Arc::unwrap_or_clone(subquery.subquery))?),
                outer_ref_columns: subquery.outer_ref_columns,
            },
            negated,
        )))),
        other => Ok(Transformed::no(other)),
    })
}

fn is_result_check_plan(plan: &LogicalPlan) -> bool {
    matches!(
        plan,
        LogicalPlan::Extension(extension)
            if extension.node.as_any().is::<ResultCheckLogicalNode>()
    )
}

#[cfg(test)]
mod tests {
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion_common::Result;
    use datafusion_expr::{
        Expr, LogicalPlan,
        logical_plan::builder::table_scan,
    };
    use tt_core::irs::nodes::plan::result_check::ResultCheckLogicalNode;
    use tt_core::irs::nodes::plan::result_check;

    use crate::logical_plan_analyzer::{analyze_logical_plan, rules};

    #[test]
    fn wraps_root_plan_once() -> Result<()> {
        let schema = Schema::new(vec![Field::new("a", DataType::Int32, true)]);
        let plan = table_scan(Some("t"), &schema, None)?
            .project(vec![Expr::Column("a".into())])?
            .build()?;

        let analyzed = analyze_logical_plan(plan, rules());
        match analyzed {
            LogicalPlan::Extension(extension) => {
                assert!(extension.node.as_any().is::<ResultCheckLogicalNode>());
            }
            other => panic!("expected result check extension, found {other:?}"),
        }

        Ok(())
    }

    #[test]
    fn does_not_double_wrap_existing_result_check() -> Result<()> {
        let schema = Schema::new(vec![Field::new("a", DataType::Int32, true)]);
        let inner = table_scan(Some("t"), &schema, None)?.build()?;
        let plan = result_check::wrap_logical_plan(inner);

        let analyzed = analyze_logical_plan(plan, rules());
        let outer = match analyzed {
            LogicalPlan::Extension(extension) => extension,
            other => panic!("expected extension, found {other:?}"),
        };
        assert!(outer.node.as_any().is::<ResultCheckLogicalNode>());

        let child = outer
            .node
            .inputs()
            .into_iter()
            .next()
            .expect("result check should have one input")
            .clone();
        assert!(
            !matches!(child, LogicalPlan::Extension(ref extension) if extension.node.as_any().is::<ResultCheckLogicalNode>()),
            "result check should not be nested"
        );

        Ok(())
    }
}
