#![cfg(feature = "test-utils")]

use dbsnark_core::{
    test_display::{
        display_prover_arithmetized_tree, display_prover_hint_tree, display_prover_piop_tree,
        display_prover_proof_tree, display_prover_tracked_tree,
    },
    test_utils::helper::prove_and_verify_query,
};
use tpch_data::query_spec;

fn spec() -> tpch_data::TpchQuerySpec {
    query_spec(1)
}

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q1_proof_tree() {
    let spec = spec();
    display_prover_proof_tree(spec.tables, spec.sql).await;
}

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q1_hint_tree() {
    let spec = spec();
    display_prover_hint_tree(spec.tables, spec.sql).await;
}

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q1_arithmetized_tree() {
    let spec = spec();
    display_prover_arithmetized_tree(spec.tables, spec.sql).await;
}

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q1_tracked_tree() {
    let spec = spec();
    display_prover_tracked_tree(spec.tables, spec.sql).await;
}

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q1_piop_tree() {
    let spec = spec();
    display_prover_piop_tree(spec.tables, spec.sql).await;
}

#[test]
fn tpch_q1_prove_verify() {
    let spec = spec();
    prove_and_verify_query(spec.sql, spec.tables[0]);
}
