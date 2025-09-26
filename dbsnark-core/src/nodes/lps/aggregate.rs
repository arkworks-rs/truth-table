use std::{collections::HashMap, sync::Arc};

use datafusion::{logical_expr::LogicalPlan, prelude::SessionContext};

use crate::nodes::{ProverNode, ProverNodeNodeId};

pub struct AggregateNode {
    pub group_expr: Vec<Arc<dyn ProverNode>>,
    pub aggr_expr: Vec<Arc<dyn ProverNode>>,
    pub input: Arc<dyn ProverNode>,
    pub node_id: ProverNodeNodeId,
    pub proof_trees: HashMap<String, LogicalPlan>,
}

impl AggregateNode {
    pub fn build_output_plan(
        group_expr: Vec<Arc<dyn ProverNode>>,
        aggr_expr: Vec<Arc<dyn ProverNode>>,
        input_plan: LogicalPlan,
    ) -> LogicalPlan {
        todo!()
    }
}

impl ProverNode for AggregateNode {
    fn from_logical_plan(ctx: &SessionContext, plan: LogicalPlan) -> Self
    where
        Self: Sized,
    {
        todo!()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode>> {
        vec![&self.input]
    }

    fn node_id(&self) -> ProverNodeNodeId {
        self.node_id.clone()
    }

    fn proof_trees(&self) -> HashMap<String, LogicalPlan> {
        self.proof_trees.clone()
    }

    fn piop_plan(&self) {
        todo!()
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
