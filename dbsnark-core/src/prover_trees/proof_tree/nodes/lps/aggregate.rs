use crate::{
    id::NodeId,
    prover_trees::{
        piop_tree::ProverPIOPTree,
        proof_tree::{
            ProverProofTree,
            nodes::{ProverNode, output_logical_plan},
        },
    },
};
use arithmetic::{ctx::SharedCtx, table::TrackedTable};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::Prover,
};
use datafusion::{
    arrow::datatypes::SchemaRef,
    common::{DFSchemaRef, Statistics},
    logical_expr::{
        self as df, ExprSchemable, LogicalPlan, LogicalPlanBuilder, expr_rewriter::normalize_cols,
    },
    prelude::{Expr, SessionContext},
};
use datafusion_expr::{expr::WindowFunction, expr_fn::ExprFunctionExt};
use datafusion_functions_window::expr_fn::row_number;
use ra_toolbox::lp_piop::aggregate_check::{AggregatePIOP, AggregatePIOPProverInput};
use std::{collections::HashMap, sync::Arc};

use crate::prover_trees::proof_tree::nodes::cost::ProvingCost;

pub struct AggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub group_expr: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
    pub aggr_expr: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
    pub inputs: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
    pub node_id: NodeId,
    pub hint_generation_plans: HashMap<String, LogicalPlan>,
}

impl<F, MvPCS, UvPCS> AggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    /// Build the logical plan that realizes the aggregate output, including the
    /// windowed helper columns used during proof generation.
    pub fn build_output_plan(
        group_exprs: &[Expr],
        aggr_exprs: &[Expr],
        aggregate_schema: &DFSchemaRef,
        input_plan: LogicalPlan,
    ) -> LogicalPlan {
        let schema = input_plan.schema().clone();
        // Preserve the activator type so that the flag can be re-created after the
        // window projection.
        let activator_field = schema
            .field_with_unqualified_name("activator")
            .unwrap_or_else(|_| panic!("'activator' column not found in input schema"));
        let activator_dtype = activator_field.data_type().clone();

        // Normalize every expression against the input so column references line up
        // with the resolver that DataFusion expects.
        let normalized_groups =
            normalize_cols(group_exprs.to_vec(), &input_plan).expect("normalize group exprs");
        let normalized_aggrs =
            normalize_cols(aggr_exprs.to_vec(), &input_plan).expect("normalize aggr exprs");

        let partition_by = normalized_groups.clone();

        let mut temp_aliases = Vec::new();
        let mut window_exprs = Vec::new();

        for (idx, expr) in normalized_aggrs.iter().enumerate() {
            // Each aggregate becomes a window expression partitioned by the
            // grouping columns so we can later pick the first row per group.
            let temp_alias = format!("__agg_window_{}", idx);
            let window_expr =
                aggregate_expr_to_window(expr.clone(), &partition_by).alias(temp_alias.clone());
            window_exprs.push(window_expr);
            temp_aliases.push(temp_alias);
        }

        let row_number_alias = "__row_number".to_string();
        // Track the first tuple per partition; only that row keeps the activator.
        let row_number_expr = row_number()
            .partition_by(partition_by.clone())
            .build()
            .expect("build row_number window")
            .alias(row_number_alias.clone());
        window_exprs.push(row_number_expr);

        let window_plan = LogicalPlanBuilder::from(input_plan.clone())
            .window(window_exprs)
            .expect("build window plan")
            .build()
            .expect("window logical plan");

        let mut projection_exprs: Vec<Expr> = Vec::new();
        // Re-emit group columns with their expected output names.
        for (expr, field) in partition_by.iter().zip(aggregate_schema.fields().iter()) {
            projection_exprs.push(expr.clone().alias(field.name().clone()));
        }

        for (idx, field) in aggregate_schema
            .fields()
            .iter()
            .skip(partition_by.len())
            .enumerate()
        {
            let temp_alias = &temp_aliases[idx];
            projection_exprs.push(df::col(temp_alias).alias(field.name().clone()));
        }

        // Only the first row per group keeps activator = 1 so downstream filters
        // continue to work with a single representative tuple.
        let one = df::lit(1u64)
            .cast_to(&activator_dtype, schema.as_ref())
            .expect("cast activator one");
        let zero = df::lit(0u64)
            .cast_to(&activator_dtype, schema.as_ref())
            .expect("cast activator zero");
        let new_activator = df::when(df::col(&row_number_alias).eq(df::lit(1u64)), one)
            .otherwise(zero)
            .expect("build activator expression")
            .alias("activator".to_string());

        projection_exprs.push(new_activator);

        LogicalPlanBuilder::from(window_plan)
            .project(projection_exprs)
            .expect("aggregate projection")
            .build()
            .expect("aggregate output plan")
    }
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for AggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_lp(
        ctx: &SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        let aggregate = match &plan {
            LogicalPlan::Aggregate(agg) => agg,
            _ => panic!("expected aggregate logical plan"),
        };

        let input_tree =
            ProverProofTree::<F, MvPCS, UvPCS>::from_lp(ctx, prover_ctx.clone(), &aggregate.input);
        let input = input_tree.root();

        let child_plan = output_logical_plan::<F, MvPCS, UvPCS>(&input)
            .unwrap_or_else(|| (*aggregate.input).clone());

        let group_expr: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>> = aggregate
            .group_expr
            .iter()
            .map(|expr| {
                ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    expr.clone(),
                    &plan,
                )
            })
            .collect();
        let aggr_expr: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>> = aggregate
            .aggr_expr
            .iter()
            .map(|expr| {
                ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    expr.clone(),
                    &plan,
                )
            })
            .collect();

        let output_plan = Self::build_output_plan(
            &aggregate.group_expr,
            &aggregate.aggr_expr,
            &aggregate.schema,
            child_plan,
        );

        let mut inputs = Vec::with_capacity(1 + group_expr.len() + aggr_expr.len());
        inputs.push(input);
        inputs.extend(group_expr.iter().cloned());
        inputs.extend(aggr_expr.iter().cloned());

        Self {
            group_expr,
            aggr_expr,
            inputs,
            node_id: NodeId::LP(plan),
            hint_generation_plans: HashMap::from([("output_plan".to_string(), output_plan)]),
        }
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        self.inputs.iter().collect()
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(&self) -> HashMap<String, LogicalPlan> {
        self.hint_generation_plans.clone()
    }

    fn cost(&self, _statistics: Statistics, _schema: SchemaRef) -> ProvingCost {
        todo!()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut Prover<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }
    fn prove_piop(
        &self,
        prover: &mut Prover<F, MvPCS, UvPCS>,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let aggregate = match &self.node_id {
            NodeId::LP(LogicalPlan::Aggregate(agg)) => agg,
            _ => panic!("expected aggregate logical plan"),
        }
        .clone();

        let mut grouping_columns: Vec<(
            datafusion::arrow::datatypes::FieldRef,
            ark_piop::prover::structs::polynomial::TrackedPoly<F, MvPCS, UvPCS>,
        )> = Vec::new();
        let mut grouping_table_size: Option<usize> = None;

        for group_node in &self.group_expr {
            let table = piop_tree
                .table(&group_node.node_id(), "output_plan")
                .unwrap_or_else(|| {
                    panic!(
                        "missing output_plan table for group expr {}",
                        group_node.name()
                    )
                });

            let table_size = table.size();
            if let Some(expected) = grouping_table_size {
                assert_eq!(
                    expected, table_size,
                    "grouping expression tables must have matching sizes",
                );
            } else {
                grouping_table_size = Some(table_size);
            }

            for (field, poly) in table.columns() {
                if field.name() == "activator" {
                    continue;
                }
                grouping_columns.push((field.clone(), poly.clone()));
            }
        }

        let input_grouping_table = if grouping_columns.is_empty() {
            panic!("aggregate PIOP requires at least one grouping column");
        } else {
            TrackedTable::new(None, grouping_columns, grouping_table_size.unwrap_or(0))
        };

        let aggregate_piop_prover_input: AggregatePIOPProverInput<F, MvPCS, UvPCS> =
            AggregatePIOPProverInput {
                aggregate,
                input_grouping_table,
                output_grouping_table: todo!(),
            };
        AggregatePIOP::prove(prover, aggregate_piop_prover_input)
    }

    fn from_expr(
        ctx: &SessionContext,
        _prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        expr: datafusion::prelude::Expr,
        parent_logical_plan: LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        std::unimplemented!()
    }

    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
    }

    fn name(&self) -> String {
        self.node_id().to_string()
    }
}

fn aggregate_expr_to_window(expr: Expr, partition_by: &[Expr]) -> Expr {
    match expr {
        Expr::Alias(mut alias) => {
            let inner = aggregate_expr_to_window((*alias.expr).clone(), partition_by);
            alias.expr = Box::new(inner);
            Expr::Alias(alias)
        },
        Expr::AggregateFunction(agg) => {
            assert!(
                !agg.params.distinct,
                "DISTINCT aggregates are not supported in aggregate tracked plans",
            );
            assert!(
                agg.params.filter.is_none(),
                "Filtered aggregates are not supported in aggregate tracked plans",
            );
            let mut builder = Expr::WindowFunction(WindowFunction::new(
                agg.func.clone(),
                agg.params.args.clone(),
            ))
            .partition_by(partition_by.to_vec());
            if let Some(order_by) = agg.params.order_by.clone() {
                builder = builder.order_by(order_by);
            }
            if let Some(null_treatment) = agg.params.null_treatment {
                builder = builder.null_treatment(null_treatment);
            }
            builder
                .build()
                .expect("failed to build aggregate window expression")
        },
        Expr::Cast(mut cast) => {
            cast.expr = Box::new(aggregate_expr_to_window((*cast.expr).clone(), partition_by));
            Expr::Cast(cast)
        },
        Expr::TryCast(mut cast) => {
            cast.expr = Box::new(aggregate_expr_to_window((*cast.expr).clone(), partition_by));
            Expr::TryCast(cast)
        },
        other => other,
    }
}

// TODO: For the aggregation functions, we need some witnesses like the
// broadcast in max, etc TODO: For grouping expressions, we need to compute the
// multiplicity witness for the support check

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::prelude::{ParquetReadOptions, SessionContext};
    use tpch_data::test_data_path;
    #[tokio::test]
    #[ignore = "This is for visualization purposes only"]
    async fn aggregate_unoptimized_plan_treeviz() {
        let ctx = SessionContext::new();
        let parquet_path = test_data_path("customer.parquet");
        assert!(
            parquet_path.exists(),
            "Missing customer parquet at {:?}",
            parquet_path
        );
        ctx.register_parquet(
            "customer",
            parquet_path.to_str().unwrap(),
            ParquetReadOptions::default(),
        )
        .await
        .unwrap();
        let sql = r#"
            SELECT
                c_nationkey,
                c_custkey + c_nationkey AS cust_plus_nation,
                SUM(c_acctbal * c_acctbal) AS total_energy,
                AVG(c_acctbal) AS avg_balance,
                COUNT(DISTINCT c_custkey) AS distinct_customers
            FROM customer
            GROUP BY c_nationkey, c_custkey + c_nationkey
        "#;
        let df = ctx.sql(sql).await.expect("aggregate SQL");
        let plan = df.into_unoptimized_plan();
        let dot = format!("{}", plan.display_graphviz());
        println!("Aggregate logical plan DOT:\n{}", dot);
    }
}
