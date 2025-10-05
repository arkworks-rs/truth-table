use crate::{id::NodeId, verifier_trees::piop_tree::VerifierPIOPTree};
use crate::verifier_trees::proof_tree::nodes::VerifierNode;
use std::{collections::HashMap, sync::Arc};

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
};
use datafusion::{logical_expr::LogicalPlan, prelude::SessionContext};



pub struct AggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub group_expr: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    pub aggr_expr: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    pub input: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
    pub hint_generation_plans: HashMap<String, LogicalPlan>,
}

impl<F, MvPCS, UvPCS> AggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub fn build_output_plan(
        group_expr: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
        aggr_expr: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
        input_plan: LogicalPlan,
    ) -> LogicalPlan {
        todo!()
    }
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for AggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_lp(
        ctx: &SessionContext,
        _verifier_ctx: arithmetic::ctx::ProverCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        todo!()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        vec![&self.input]
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(&self) -> HashMap<String, LogicalPlan> {
        self.hint_generation_plans.clone()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
        let _ = piop_tree;
        todo!()
    }
    fn verify_piop(
        &self,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::verifier_trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        todo!()
    }

    fn from_expr(
        ctx: &SessionContext,
        _verifier_ctx: arithmetic::ctx::ProverCtx<F, MvPCS, UvPCS>,
        expr: datafusion::prelude::Expr,
        parent_logical_plan: LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        std::unimplemented!()
    }

    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
    }

    fn name(&self) -> String {
        self.node_id().to_string()
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
