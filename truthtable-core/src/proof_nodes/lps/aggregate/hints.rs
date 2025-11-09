use crate::proof_nodes::{
    HintGenerationPlan, OUTPUT_PLAN_KEY,
};
use arithmetic::ACTIVATOR_COL_NAME;
use datafusion::{
    common::TableReference,
    logical_expr::{
        self as df, Case, ExprFunctionExt, JoinType, LogicalPlan, LogicalPlanBuilder, Operator,
    },
    prelude::{Column, Expr},
    scalar::ScalarValue,
};
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
    const AGG_ALIAS: &str = "__truthtable_aggr_values";
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
        .partition_by(partition_exprs)
        .order_by(order_exprs)
        .build()
        .expect("failed to construct row_number expression for aggregate plan")
        .alias(RN_COL);

    let base_with_rn = LogicalPlanBuilder::from(base_with_pos.clone())
        .window(vec![rn_expr])
        .expect("failed to append per-group rank column to aggregate plan")
        .build()
        .expect("failed to build plan with per-group rank column");

    let group_by_exprs_for_agg: Vec<Expr> = group_aliases
        .iter()
        .map(|alias| Expr::Column(Column::from_name(alias.clone())))
        .collect();

    let activator_filter = Expr::Column(Column::from_name(ACTIVATOR_COL_NAME.to_string()));
    let activated_base_for_agg = LogicalPlanBuilder::from(base_with_group_exprs.clone())
        .filter(activator_filter)
        .expect("failed to filter inactive rows for aggregate hint generation")
        .build()
        .expect("failed to build filtered aggregate base plan");

    let aggregate_values_plan = LogicalPlanBuilder::from(activated_base_for_agg)
        .aggregate(group_by_exprs_for_agg, aggregate_plan.aggr_expr.clone())
        .expect("failed to build aggregate plan for hint generation")
        .build()
        .expect("failed to finalize aggregate hint plan");
    let agg_has_activator = aggregate_values_plan
        .schema()
        .fields()
        .iter()
        .any(|field| field.name() == ACTIVATOR_COL_NAME);

    let base_table_ref = TableReference::bare(BASE_ALIAS);
    let agg_table_ref = TableReference::bare(AGG_ALIAS);

    let base_aliased = LogicalPlanBuilder::from(base_with_rn)
        .alias(base_table_ref.clone())
        .expect("failed to alias aggregate base plan")
        .build()
        .expect("failed to build aliased aggregate base plan");

    let agg_aliased = LogicalPlanBuilder::from(aggregate_values_plan)
        .alias(agg_table_ref.clone())
        .expect("failed to alias aggregate values plan")
        .build()
        .expect("failed to build aliased aggregate values plan");

    let left_join_cols: Vec<Column> = group_aliases
        .iter()
        .map(|alias| Column::new(Some(base_table_ref.clone()), alias.clone()))
        .collect();
    let right_join_cols: Vec<Column> = group_aliases
        .iter()
        .map(|alias| Column::new(Some(agg_table_ref.clone()), alias.clone()))
        .collect();

    let joined = LogicalPlanBuilder::from(base_aliased)
        .join(
            agg_aliased,
            JoinType::Inner,
            (left_join_cols, right_join_cols),
            None,
        )
        .expect("failed to join aggregate base with aggregate values")
        .build()
        .expect("failed to build joined aggregate hint plan");

    let pos_sort = Expr::Column(Column::new(
        Some(base_table_ref.clone()),
        POS_COL.to_string(),
    ))
    .sort(true, false);

    let sorted = LogicalPlanBuilder::from(joined)
        .sort(vec![pos_sort])
        .expect("failed to apply ordering to aggregate hint plan")
        .build()
        .expect("failed to build sorted aggregate hint plan");

    let agg_schema = aggregate_plan.schema.as_ref();
    let mut final_exprs =
        Vec::with_capacity(group_aliases.len() + aggregate_plan.aggr_expr.len() + 1);

    for (idx, alias) in group_aliases.iter().enumerate() {
        let field_name = agg_schema.field(idx).name().clone();
        final_exprs.push(
            Expr::Column(Column::new(Some(base_table_ref.clone()), alias.clone()))
                .alias(field_name),
        );
    }

    for (agg_idx, _) in aggregate_plan.aggr_expr.iter().enumerate() {
        let schema_idx = group_aliases.len() + agg_idx;
        let field_name = agg_schema.field(schema_idx).name().clone();
        final_exprs.push(
            Expr::Column(Column::new(Some(agg_table_ref.clone()), field_name.clone()))
                .alias(field_name),
        );
    }

    let rank_column = Expr::Column(Column::new(
        Some(base_table_ref.clone()),
        RN_COL.to_string(),
    ));
    let activator_column = Expr::Column(Column::new(
        Some(base_table_ref.clone()),
        ACTIVATOR_COL_NAME.to_string(),
    ));
    let output_activator_expr = if agg_has_activator {
        Expr::Column(Column::new(
            Some(agg_table_ref.clone()),
            ACTIVATOR_COL_NAME.to_string(),
        ))
    } else {
        Expr::Literal(ScalarValue::Boolean(Some(true)))
    };
    let combined_activator = Expr::BinaryExpr(datafusion_expr::expr::BinaryExpr::new(
        Box::new(activator_column),
        Operator::And,
        Box::new(output_activator_expr),
    ));
    let activator_case = Expr::Case(Case::new(
        None,
        vec![(
            Box::new(rank_column.eq(Expr::Literal(ScalarValue::UInt64(Some(1))))),
            Box::new(combined_activator),
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
