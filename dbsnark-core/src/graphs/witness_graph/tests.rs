use crate::{
    graphs::witness_graph::display::DisplayableWitnessGraph,
    nodes::{display::DisplayableProofPlan, logical_to_proof_plan, sorted_descendants},
};

use super::*;
use datafusion::prelude::{ParquetReadOptions, SessionContext};
use std::{collections::BTreeSet, sync::Arc};
use tpch_data::test_data_path;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
}

#[tokio::test]
#[ignore = "This test is mainly to visually inspect the generated plans"]
async fn witness_plan_executes_all_witness_queries() {
    init_tracing();
    let ctx = SessionContext::new();

    let parquet_path = test_data_path("lineitem.parquet");
    assert!(
        parquet_path.exists(),
        "Missing Parquet at {:?}",
        parquet_path
    );
    ctx.register_parquet(
        "lineitem",
        parquet_path.to_str().unwrap(),
        ParquetReadOptions::default(),
    )
    .await
    .unwrap();

    let sql = r#"
        SELECT l_discount FROM lineitem WHERE l_quantity = 2
    "#;
    let df = ctx.sql(sql).await.unwrap();
    let logical = df.into_unoptimized_plan();

    let proof_plan = logical_to_proof_plan(&ctx, &logical);
    let proof_dot = DisplayableProofPlan::new(&proof_plan).graphviz();
    println!("ProofPlan DOT:\n{}", proof_dot);

    let witness_plan = WitnessGraph::from_proof_plan(&ctx, Arc::clone(&proof_plan))
        .await
        .unwrap();
    let witness_dot = DisplayableWitnessGraph::new(&proof_plan, &witness_plan).graphviz();
    println!("WitnessGraph DOT:\n{}", witness_dot);

    // For every proof-plan node ensure we collected batches for each declared plan.
    let proof_nodes = sorted_descendants(Arc::clone(&proof_plan));
    assert!(!proof_nodes.is_empty());

    for node in proof_nodes {
        let node_id = node.node_id();
        let expected_labels = node
            .witness_generation_plans()
            .into_keys()
            .collect::<BTreeSet<_>>();

        let actual_labels = witness_plan
            .results_for(&node_id)
            .map(|m| m.keys().cloned().collect::<BTreeSet<_>>())
            .unwrap_or_default();

        assert_eq!(
            expected_labels,
            actual_labels,
            "Witness results missing for node '{}'",
            plan_label(&node)
        );

        if let Some(batches) = witness_plan.primary_batches(&node_id) {
            let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
            if node.as_any().downcast_ref::<TableScanNode>().is_some() {
                assert!(
                    total_rows.is_power_of_two(),
                    "TableScan produced non power-of-two row count: {}",
                    total_rows
                );
            }
        }
    }

    assert!(witness_dot.contains("witness keys:"));
}

#[tokio::test]
#[ignore = "This test is mainly to visually inspect the generated plans"]
async fn witness_plan_handles_larger_query() {
    init_tracing();
    let ctx = SessionContext::new();

    let parquet_path = test_data_path("lineitem.parquet");
    assert!(
        parquet_path.exists(),
        "Missing Parquet at {:?}",
        parquet_path
    );
    ctx.register_parquet(
        "lineitem",
        parquet_path.to_str().unwrap(),
        ParquetReadOptions::default(),
    )
    .await
    .unwrap();

    let sql = r#"
        SELECT l_discount FROM lineitem WHERE l_quantity = 2
    "#;
    let df = ctx.sql(sql).await.unwrap();
    let logical = df.into_unoptimized_plan();

    let proof_plan = logical_to_proof_plan(&ctx, &logical);
    let proof_dot = DisplayableProofPlan::new(&proof_plan).graphviz();
    println!("ProofPlan DOT:\n{}", proof_dot);
    assert!(proof_dot.contains("LogicalPlan"));

    let witness_plan = WitnessGraph::from_proof_plan(&ctx, Arc::clone(&proof_plan))
        .await
        .unwrap();
    let witness_dot = DisplayableWitnessGraph::new(&proof_plan, &witness_plan).graphviz();
    println!("WitnessGraph DOT:\n{}", witness_dot);
    assert!(witness_dot.contains("witness keys:"));
}
