use datafusion::logical_expr as df;
pub mod nodes;
use datafusion::logical_expr::LogicalPlan;
pub use nodes::*;
pub mod display;
/// A proof plan node decorated with its corresponding logical plan
/// for this subtree.
#[derive(Debug, Clone)]
pub struct ProofPlan {
    pub root: ProofPlanNode,
    pub io_plan: LogicalPlan,
}

impl ProofPlan {
    /// Build a ProofPlan tree from a DataFusion LogicalPlan tree.
    pub fn from_logical_plan(plan: &df::LogicalPlan) -> Self {
        match plan {
            LogicalPlan::Projection(p) => ProofPlan {
                root: ProofPlanNode::Projection(ProjectionNode::from_logical(p)),
                io_plan: ProjectionNode::io_plan(p),
            },
            LogicalPlan::Filter(f) => ProofPlan {
                root: ProofPlanNode::Filter(FilterNode::from_logical(f)),
                io_plan: FilterNode::io_plan(f),
            },
            LogicalPlan::Aggregate(a) => ProofPlan {
                root: ProofPlanNode::Aggregate(AggregateNode::from_logical(a)),
                io_plan: AggregateNode::io_plan(a),
            },
            LogicalPlan::Sort(s) => ProofPlan {
                root: ProofPlanNode::Sort(SortNode::from_logical(s)),
                io_plan: SortNode::io_plan(s),
            },
            LogicalPlan::Join(j) => ProofPlan {
                root: ProofPlanNode::Join(JoinNode::from_logical(j)),
                io_plan: JoinNode::io_plan(j),
            },
            LogicalPlan::Repartition(r) => ProofPlan {
                root: ProofPlanNode::Repartition(RepartitionNode::from_logical(r)),
                io_plan: RepartitionNode::io_plan(r),
            },
            LogicalPlan::Window(w) => ProofPlan {
                root: ProofPlanNode::Window(WindowNode::from_logical(w)),
                io_plan: WindowNode::io_plan(w),
            },
            LogicalPlan::Limit(l) => ProofPlan {
                root: ProofPlanNode::Limit(LimitNode::from_logical(l)),
                io_plan: LimitNode::io_plan(l),
            },
            LogicalPlan::TableScan(t) => ProofPlan {
                root: ProofPlanNode::TableScan(TableScanNode::from_logical(t)),
                io_plan: TableScanNode::io_plan(t),
            },
            LogicalPlan::Union(u) => ProofPlan {
                root: ProofPlanNode::Union(UnionNode::from_logical(u)),
                io_plan: UnionNode::io_plan(u),
            },
            LogicalPlan::Subquery(sq) => ProofPlan {
                root: ProofPlanNode::Subquery(SubqueryNode::from_logical(sq)),
                io_plan: SubqueryNode::io_plan(sq),
            },
            LogicalPlan::SubqueryAlias(sa) => ProofPlan {
                root: ProofPlanNode::SubqueryAlias(SubqueryAliasNode::from_logical(sa)),
                io_plan: SubqueryAliasNode::io_plan(sa),
            },
            LogicalPlan::Distinct(d) => ProofPlan {
                root: ProofPlanNode::Distinct(DistinctNode::from_logical(d)),
                io_plan: DistinctNode::io_plan(d),
            },
            LogicalPlan::Values(v) => ProofPlan {
                root: ProofPlanNode::Values(ValuesNode::from_logical(v)),
                io_plan: ValuesNode::io_plan(v),
            },
            LogicalPlan::Explain(e) => ProofPlan {
                root: ProofPlanNode::Explain(ExplainNode::from_logical(e)),
                io_plan: ExplainNode::io_plan(e),
            },
            LogicalPlan::Analyze(a) => ProofPlan {
                root: ProofPlanNode::Analyze(AnalyzeNode::from_logical(a)),
                io_plan: AnalyzeNode::io_plan(a),
            },
            LogicalPlan::Extension(ext) => ProofPlan {
                root: ProofPlanNode::Extension(ExtensionNode::from_logical(ext)),
                io_plan: ExtensionNode::io_plan(ext),
            },
            other => ProofPlan {
                root: ProofPlanNode::Other(OtherNode::from_logical(other)),
                io_plan: other.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {

    use super::ProofPlan;
    use crate::test_utils::imdb_parquet_path;
    use datafusion::prelude::*;
    #[tokio::test]
    async fn proof_plan_from_nested_filters() -> datafusion::error::Result<()> {
        let ctx = SessionContext::new();

        let parquet_path = imdb_parquet_path();
        assert!(
            parquet_path.exists(),
            "Missing Parquet at {:?}",
            parquet_path
        );
        ctx.register_parquet(
            "titles",
            parquet_path.to_str().unwrap(),
            ParquetReadOptions::default(),
        )
        .await?;

        let sql = r#"
            SELECT PRODUCTION_YEAR, ID
            FROM (SELECT * FROM titles WHERE PRODUCTION_YEAR = 2000) t
            WHERE ID = 1
        "#;
        let df = ctx.sql(sql).await?;
        let logical = df.into_unoptimized_plan();
        let proof = ProofPlan::from_logical_plan(&logical);
        // Print both graphviz renderings for quick visual inspection
        println!(
            "-- LogicalPlan (graphviz) --\n{}",
            logical.display_graphviz()
        );
        println!("-- ProofPlan (graphviz) --\n{}", proof.display_graphviz());
        Ok(())
    }
}
