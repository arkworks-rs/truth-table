use crate::proof_nodes::{HintGenerationPlan, OUTPUT_PLAN_KEY};
use arithmetic::ACTIVATOR_COL_NAME;
use datafusion::{
    common::{
        Result as DFResult, TableReference,
        tree_node::{Transformed, TreeNode, TreeNodeRewriter},
    },
    logical_expr::{
        self as df, Case, ExprFunctionExt, LogicalPlan, LogicalPlanBuilder, WindowFrame,
    },
    prelude::{Column, Expr},
    scalar::ScalarValue,
};
use datafusion_expr::expr::{WindowFunction, WindowFunctionDefinition, WindowFunctionParams};
use datafusion_functions_window::expr_fn::row_number;
use indexmap::IndexMap;

pub(super) fn build_aggregate_hint_generation_plans(
    base_plan: LogicalPlan,
    aggregate_plan: &df::Aggregate,
) -> IndexMap<String, HintGenerationPlan> {
    let output_plan = build_aggregate_hint_output_plan(base_plan.clone(), aggregate_plan);
    let output_schema = output_plan.schema();
    let group_col_count = aggregate_plan.group_expr.len();
    let group_field_names: Vec<String> = aggregate_plan
        .schema
        .fields()
        .iter()
        .take(group_col_count)
        .map(|field| field.name().clone())
        .collect();

    let should_materialize: IndexMap<_, _> = output_schema
        .fields()
        .iter()
        .map(|field_ref| {
            let field_ref = field_ref.clone();
            let should = !group_field_names
                .iter()
                .any(|name| name == field_ref.name());
            (field_ref, should)
        })
        .collect();

    let mut plans = IndexMap::new();
    plans.insert(
        OUTPUT_PLAN_KEY.to_string(),
        HintGenerationPlan::new(
            OUTPUT_PLAN_KEY.to_string(),
            output_plan.clone(),
            should_materialize,
        ),
    );

    plans
}

fn build_aggregate_hint_output_plan(
    base_plan: LogicalPlan,
    aggregate_plan: &df::Aggregate,
) -> LogicalPlan {
    const BASE_ALIAS: &str = "__truthtable_aggr_base";
    const POS_COL: &str = "__truthtable_aggr_pos";
    const RN_COL: &str = "__truthtable_aggr_rank";
    const GROUP_EXPR_PREFIX: &str = "__truthtable_aggr_group_expr_";

    let base_schema = base_plan.schema().clone();

    let mut projection_exprs: Vec<Expr> = base_schema
        .iter()
        .map(|(qualifier, field)| Expr::from((qualifier, field)))
        .collect();

    let group_aliases: Vec<String> = aggregate_plan
        .group_expr
        .iter()
        .enumerate()
        .map(|(idx, _)| format!("{GROUP_EXPR_PREFIX}{idx}"))
        .collect();

    for (expr, alias) in aggregate_plan.group_expr.iter().zip(group_aliases.iter()) {
        projection_exprs.push(expr.clone().alias(alias.clone()));
    }

    let base_with_group_exprs = LogicalPlanBuilder::from(base_plan)
        .project(projection_exprs)
        .expect("failed to append group expressions to aggregate base plan")
        .build()
        .expect("failed to build base plan with group expressions");

    let base_with_pos = LogicalPlanBuilder::from(base_with_group_exprs.clone())
        .window(vec![row_number().alias(POS_COL)])
        .expect("failed to append position column for aggregate plan")
        .build()
        .expect("failed to build plan with position column");

    let partition_exprs: Vec<Expr> = group_aliases
        .iter()
        .map(|alias| Expr::Column(Column::from_name(alias.clone())))
        .collect();

    let order_exprs = vec![Expr::Column(Column::from_name(POS_COL.to_string())).sort(true, false)];

    let rn_expr = row_number()
        .partition_by(partition_exprs.clone())
        .order_by(order_exprs)
        .build()
        .expect("failed to construct row_number expression for aggregate plan")
        .alias(RN_COL);

    let base_with_rn = LogicalPlanBuilder::from(base_with_pos.clone())
        .window(vec![rn_expr])
        .expect("failed to append per-group rank column to aggregate plan")
        .build()
        .expect("failed to build plan with per-group rank column");

    let base_table_ref = TableReference::bare(BASE_ALIAS);

    let base_aliased = LogicalPlanBuilder::from(base_with_rn)
        .alias(base_table_ref.clone())
        .expect("failed to alias aggregate base plan")
        .build()
        .expect("failed to build aliased aggregate base plan");

    let activator_col = Expr::Column(Column::from_name(ACTIVATOR_COL_NAME.to_string()));

    let partition_exprs_for_window: Vec<Expr> = group_aliases
        .iter()
        .map(|alias| Expr::Column(Column::new(Some(base_table_ref.clone()), alias.clone())))
        .collect();

    let mut window_exprs = Vec::with_capacity(aggregate_plan.aggr_expr.len());
    for (agg_idx, expr) in aggregate_plan.aggr_expr.iter().enumerate() {
        let schema_idx = group_aliases.len() + agg_idx;
        let field_name = aggregate_plan.schema.field(schema_idx).name().clone();
        let window_expr =
            aggregate_expr_as_window(expr, &partition_exprs_for_window, &activator_col)
                .alias(field_name);
        window_exprs.push(window_expr);
    }

    let base_with_windows = if window_exprs.is_empty() {
        base_aliased.clone()
    } else {
        LogicalPlanBuilder::from(base_aliased.clone())
            .window(window_exprs)
            .expect("failed to append aggregate window expressions")
            .build()
            .expect("failed to build plan with aggregate window expressions")
    };

    let pos_sort = Expr::Column(Column::new(
        Some(base_table_ref.clone()),
        POS_COL.to_string(),
    ))
    .sort(true, false);

    let sorted = LogicalPlanBuilder::from(base_with_windows)
        .sort(vec![pos_sort])
        .expect("failed to apply ordering to aggregate hint plan")
        .build()
        .expect("failed to build sorted aggregate hint plan");

    let agg_schema = aggregate_plan.schema.as_ref();
    let mut final_exprs =
        Vec::with_capacity(group_aliases.len() + aggregate_plan.aggr_expr.len() + 1);

    for (idx, alias) in group_aliases.iter().enumerate() {
        let field_name = agg_schema.field(idx).name().clone();
        final_exprs.push(Expr::Column(Column::from_name(alias.clone())).alias(field_name));
    }

    for (agg_idx, _) in aggregate_plan.aggr_expr.iter().enumerate() {
        let schema_idx = group_aliases.len() + agg_idx;
        let field_name = agg_schema.field(schema_idx).name().clone();
        final_exprs.push(Expr::Column(Column::from_name(field_name.clone())).alias(field_name));
    }

    let rank_column = Expr::Column(Column::new(
        Some(base_table_ref.clone()),
        RN_COL.to_string(),
    ));
    let activator_column = Expr::Column(Column::from_name(ACTIVATOR_COL_NAME.to_string()));
    let activator_case = Expr::Case(Case::new(
        None,
        vec![(
            Box::new(rank_column.eq(Expr::Literal(ScalarValue::UInt64(Some(1))))),
            Box::new(activator_column),
        )],
        Some(Box::new(Expr::Literal(ScalarValue::Boolean(Some(false))))),
    ))
    .alias(ACTIVATOR_COL_NAME.to_string());
    final_exprs.push(activator_case);

    LogicalPlanBuilder::from(sorted)
        .project(final_exprs)
        .expect("failed to project final aggregate hint output")
        .build()
        .expect("failed to construct aggregate hint output plan")
}

fn aggregate_expr_as_window(expr: &Expr, partition_exprs: &[Expr], activator_col: &Expr) -> Expr {
    match strip_column_relations(expr) {
        Expr::Alias(alias) => {
            aggregate_expr_as_window(alias.expr.as_ref(), partition_exprs, activator_col)
                .alias(alias.name.clone())
        }
        Expr::AggregateFunction(agg) => {
            assert!(
                agg.params.filter.is_none(),
                "filtered aggregates are not supported in window rewrite"
            );
            assert!(
                !agg.params.distinct,
                "distinct aggregates are not supported in window rewrite"
            );
            let mut gated_args = Vec::with_capacity(agg.params.args.len());
            for arg in &agg.params.args {
                let gated = Expr::Case(Case::new(
                    None,
                    vec![(Box::new(activator_col.clone()), Box::new(arg.clone()))],
                    Some(Box::new(Expr::Literal(ScalarValue::Null))),
                ));
                gated_args.push(gated);
            }

            let params = WindowFunctionParams {
                args: gated_args,
                partition_by: partition_exprs.to_vec(),
                order_by: agg.params.order_by.clone().unwrap_or_default(),
                window_frame: WindowFrame::new(None),
                null_treatment: agg.params.null_treatment,
            };

            Expr::WindowFunction(WindowFunction {
                fun: WindowFunctionDefinition::AggregateUDF(agg.func.clone()),
                params,
            })
        }
        other => panic!("unsupported aggregate expression in hint generation: {other:?}"),
    }
}

fn strip_column_relations(expr: &Expr) -> Expr {
    struct Rewriter;
    impl TreeNodeRewriter for Rewriter {
        type Node = Expr;
        fn f_up(&mut self, expr: Expr) -> DFResult<Transformed<Expr>> {
            match expr {
                Expr::Column(mut col) => {
                    if col.relation.is_some() {
                        col.relation = None;
                        Ok(Transformed::yes(Expr::Column(col)))
                    } else {
                        Ok(Transformed::no(Expr::Column(col)))
                    }
                }
                other => Ok(Transformed::no(other)),
            }
        }
    }

    let mut rewriter = Rewriter;
    expr.clone()
        .rewrite(&mut rewriter)
        .expect("column rewrite failed")
        .data
}
