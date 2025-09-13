use super::*;
use crate::{
    proof_plan::display::DisplayableProofPlan,
    test_utils::{are_effective_batches_equal, imdb_parquet_path},
    witness_plan::{display::DisplayableWitnessPlan, sorted_descendants, WitnessNode},
};
use datafusion::{
    arrow::{array::{Array, BooleanArray}, record_batch::RecordBatch},
    prelude::{ParquetReadOptions, SessionContext},
};

#[tokio::test]
async fn logical_plan_to_witness_plan_sequential() {
    // Run with the following command:
    // RUST_LOG=off,front_end=trace cargo test --package front-end --lib
    // --all-features --
    // witness_plan::tests::logical_plan_to_witness_plan_sequential --exact
    // --show-output;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let ctx = SessionContext::new();

    let parquet_path = imdb_parquet_path("title-sanitized.parquet");
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
    .await
    .unwrap();

    let sql = r#"
            SELECT TITLE, PRODUCTION_YEAR FROM titles WHERE PRODUCTION_YEAR = 2000
        "#;
    let df = ctx.sql(sql).await.unwrap();
    let logical = df.into_unoptimized_plan();

    // 1) DataFusion Logical Plan DOT
    let logical_dot = format!("{}", logical.display_graphviz());
    println!("LogicalPlan DOT:\n{}", logical_dot);

    // 2) Our Proof Plan DOT
    let proof_root = crate::proof_plan::logical_to_proof_plan(&ctx, &logical);
    let proof_dot = format!("{}", DisplayableProofPlan::new(&proof_root));
    println!("ProofPlan DOT:\n{}", proof_dot);

    // 3) Witness Plan DOT (after sequential execution)
    let wtree = proof_to_witness_tree(&ctx, Arc::clone(&proof_root), false)
        .await
        .unwrap();
    let witness_dot = format!("{}", DisplayableWitnessPlan::new(&wtree));
    println!("WitnessPlan (sequential) DOT:\n{}", witness_dot);

    // Basic sanity: witness should have at least one node and stats present for
    // root
    // Basic sanity: witness should have at least one node and stats present for root
    let flat: Vec<&WitnessNode> = sorted_descendants(&wtree);
    assert!(!flat.is_empty());
    assert!(witness_dot.contains("cols:") && witness_dot.contains("rows:"));
}

#[tokio::test]
async fn logical_plan_to_witness_plan_parallel() {
    // Run with the following command:
    // RUST_LOG=off,front_end=trace cargo test --package front-end --lib
    // --all-features -- witness_plan::tests::logical_plan_to_witness_plan_parallel
    // --exact --show-output;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let ctx = SessionContext::new();

    let parquet_path = imdb_parquet_path("title-sanitized.parquet");
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
    .await
    .unwrap();

    let sql = r#"
            SELECT TITLE, PRODUCTION_YEAR FROM titles WHERE PRODUCTION_YEAR = 2000
        "#;
    let df = ctx.sql(sql).await.unwrap();
    let logical = df.into_unoptimized_plan();

    // 1) DataFusion Logical Plan DOT
    let logical_dot = format!("{}", logical.display_graphviz());
    println!("LogicalPlan DOT:\n{}", logical_dot);

    // 2) Our Proof Plan DOT
    let proof_root = crate::proof_plan::logical_to_proof_plan(&ctx, &logical);
    let proof_dot = format!("{}", DisplayableProofPlan::new(&proof_root));
    println!("ProofPlan DOT:\n{}", proof_dot);

    // 3) Witness Plan DOT (after parallel execution)
    let wtree = proof_to_witness_tree(&ctx, Arc::clone(&proof_root), true)
        .await
        .unwrap();
    let witness_dot = format!("{}", DisplayableWitnessPlan::new(&wtree));
    println!("WitnessPlan (parallel) DOT:\n{}", witness_dot);

    // Basic sanity: witness should have at least one node and stats present for
    // root
    let flat: Vec<&WitnessNode> = sorted_descendants(&wtree);
    assert!(!flat.is_empty());
    assert!(witness_dot.contains("cols:") && witness_dot.contains("rows:"));
}

#[tokio::test]
async fn witness_seq_vs_par_all_nodes_equal() {
    fn count_activator_false(batches: &[RecordBatch]) -> usize {
        let mut total = 0usize;
        for b in batches {
            let idx = match b.schema().index_of("activator") {
                Ok(i) => i,
                Err(_) => continue,
            };
            let mask = b
                .column(idx)
                .as_any()
                .downcast_ref::<BooleanArray>()
                .expect("'activator' must be Boolean");
            // Count entries that are explicitly false (Some(false))
            total += (0..mask.len())
                .filter(|&i| mask.is_valid(i) && !mask.value(i))
                .count();
        }
        total
    }

    let ctx = SessionContext::new();

    let parquet_path = imdb_parquet_path("title-sanitized.parquet");
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
    .await
    .unwrap();

    // Build a logical plan for a simple query
    let sql = r#"
            SELECT TITLE, PRODUCTION_YEAR FROM titles WHERE PRODUCTION_YEAR = 2000
        "#;
    let df = ctx.sql(sql).await.unwrap();
    let logical = df.into_unoptimized_plan();

    // Convert to our proof plan
    let proof_root = crate::proof_plan::logical_to_proof_plan(&ctx, &logical);

    // Materialize witnesses sequentially and in parallel
    let wtree_seq = proof_to_witness_tree(&ctx, Arc::clone(&proof_root), false)
        .await
        .unwrap();
    let wtree_par = proof_to_witness_tree(&ctx, Arc::clone(&proof_root), true)
        .await
        .unwrap();

    // Sanity: same number of nodes
    let flat_seq = sorted_descendants(&wtree_seq);
    let flat_par = sorted_descendants(&wtree_par);
    assert_eq!(flat_seq.len(), flat_par.len());

    // For every node (post-order), compare results using unordered hash equality
    for (i, (ws, wp)) in flat_seq.iter().zip(flat_par.iter()).enumerate() {
        // Cardinality should be preserved and power-of-two after initial padding
        let rows_seq: usize = ws.result.iter().map(|b| b.num_rows()).sum();
        let rows_par: usize = wp.result.iter().map(|b| b.num_rows()).sum();
        assert_eq!(rows_seq, rows_par, "Node {} row count mismatch", i);
        assert!(
            rows_seq.is_power_of_two(),
            "Node {} row count not power-of-two: {}",
            i,
            rows_seq
        );

        let equal = are_effective_batches_equal(&ws.result, &wp.result);
        assert!(
            equal,
            "Node {} mismatch: seq '{}' vs par '{}'",
            i,
            ws.node.name(),
            wp.node.name()
        );

        // Also assert that padded rows (activator=false) counts match
        let pad_seq = count_activator_false(&ws.result);
        let pad_par = count_activator_false(&wp.result);
        assert_eq!(
            pad_seq,
            pad_par,
            "Node {} padded row count differs: seq {} vs par {} (node '{}')",
            i,
            pad_seq,
            pad_par,
            ws.node.name()
        );
    }
}
