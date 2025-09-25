use std::{collections::HashMap, sync::Arc};

use crate::ra_proof_plan::{output_logical_plan, ProofPlan, ProofPlanNodeId};
use datafusion::{logical_expr::LogicalPlan, prelude::SessionContext};

pub struct AggregateNode {
    pub group_expr: Vec<Arc<dyn ProofPlan>>,
    pub aggr_expr: Vec<Arc<dyn ProofPlan>>,
    pub input: Arc<dyn ProofPlan>,
    pub node_id: ProofPlanNodeId,
    pub witness_generation_plans: HashMap<String, LogicalPlan>,
}

impl AggregateNode {
    pub fn build_output_plan(
        group_expr: Vec<Arc<dyn ProofPlan>>,
        aggr_expr: Vec<Arc<dyn ProofPlan>>,
        input_plan: LogicalPlan,
    ) -> LogicalPlan {
        todo!()
    }
}

impl ProofPlan for AggregateNode {
    fn from_logical_plan(ctx: &SessionContext, plan: LogicalPlan) -> Self
    where
        Self: Sized,
    {
        todo!()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProofPlan>> {
        vec![&self.input]
    }

    fn node_id(&self) -> ProofPlanNodeId {
        self.node_id.clone()
    }

    fn witness_generation_plans(&self) -> HashMap<String, LogicalPlan> {
        self.witness_generation_plans.clone()
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
    async fn aggregate_unoptimized_plan_graphviz() {
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
