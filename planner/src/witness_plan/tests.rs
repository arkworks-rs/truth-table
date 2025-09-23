use super::*;
use crate::{
    ra_proof_plan::{
        display::DisplayableProofPlan, logical_plan_nodes::TableScanNode, logical_to_proof_plan,
    },
    witness_plan::display::DisplayableWitnessPlan,
};
use datafusion::prelude::{ParquetReadOptions, SessionContext};
use std::{collections::BTreeSet, sync::Arc};
use tpch_data::test_data_path;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
}

#[tokio::test]
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

    let witness_plan = proof_to_witness_plan(&ctx, Arc::clone(&proof_plan))
        .await
        .unwrap();
    let witness_dot = DisplayableWitnessPlan::new(&witness_plan).graphviz();
    println!("WitnessPlan DOT:\n{}", witness_dot);

    // For every witness node ensure we collected batches for each declared plan.
    let witnesses = sorted_descendants(&witness_plan);
    assert!(!witnesses.is_empty());

    for node in witnesses {
        let expected_labels = node
            .node
            .witness_generation_plans()
            .into_keys()
            .collect::<BTreeSet<_>>();

        let actual_labels = node.results.keys().cloned().collect::<BTreeSet<_>>();

        assert_eq!(
            expected_labels,
            actual_labels,
            "Witness results missing for node '{}'",
            plan_label(&node.node)
        );

        if let Some(batches) = node.primary_batches() {
            let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
            if node.node.as_any().downcast_ref::<TableScanNode>().is_some() {
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

    let witness_plan = proof_to_witness_plan(&ctx, proof_plan).await.unwrap();
    let witness_dot = DisplayableWitnessPlan::new(&witness_plan).graphviz();
    println!("WitnessPlan DOT:\n{}", witness_dot);
    assert!(witness_dot.contains("witness keys:"));
}
