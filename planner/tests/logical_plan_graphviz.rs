use datafusion::{
    logical_expr::{display::GraphvizVisitor, LogicalPlan},
    prelude::{ParquetReadOptions, SessionContext},
};
use tpch_data::test_data_path;

const QUERY: &str = r#"
SELECT
    l_orderkey,
    l_extendedprice * (1 - l_discount) AS net,
    l_quantity * l_extendedprice AS total
FROM
    lineitem
WHERE
    l_shipdate >= DATE '1996-01-01';
"#;

#[tokio::test]
async fn tpch_lineitem_projection_filter_graphviz() {
    let ctx = SessionContext::new();

    let lineitem_path = test_data_path("lineitem.parquet");
    let lineitem_str = lineitem_path
        .to_str()
        .expect("lineitem parquet path contains invalid UTF-8");

    ctx.register_parquet("lineitem", lineitem_str, ParquetReadOptions::default())
        .await
        .expect("register lineitem parquet");

    let df = ctx.sql(QUERY).await.expect("build DataFrame");
    let plan = df.into_unoptimized_plan();
    let graphviz = simple_logical_plan_graphviz(&plan);

    assert!(
        graphviz.contains("Projection"),
        "Graphviz output should include projection: {graphviz}"
    );
    assert!(
        graphviz.contains("Filter"),
        "Graphviz output should include filter: {graphviz}"
    );

    println!("{graphviz}");
}

fn simple_logical_plan_graphviz(plan: &LogicalPlan) -> String {
    struct Wrapper<'a>(&'a LogicalPlan);

    impl std::fmt::Display for Wrapper<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let mut visitor = GraphvizVisitor::new(f);
            visitor.start_graph()?;
            visitor.pre_visit_plan("LogicalPlan")?;
            self.0
                .visit_with_subqueries(&mut visitor)
                .map_err(|_| std::fmt::Error)?;
            visitor.post_visit_plan()?;
            visitor.end_graph()?;
            Ok(())
        }
    }

    format!("{}", Wrapper(plan))
}
