#![cfg(feature = "test-utils")]

use dbsnark_core::test_display::{
    display_prover_arithmetized_tree, display_prover_hint_tree, display_prover_piop_tree,
    display_prover_proof_tree, display_prover_tracked_tree,
};
use tpch_data::query_spec;

fn spec() -> tpch_data::TpchQuerySpec {
    query_spec(2)
}

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q2_proof_tree() {
    let spec = spec();
    display_prover_proof_tree(spec.tables, spec.sql).await;
}

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q2_hint_tree() {
    let spec = spec();
    display_prover_hint_tree(spec.tables, spec.sql).await;
}

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q2_arithmetized_tree() {
    let spec = spec();
    display_prover_arithmetized_tree(spec.tables, spec.sql).await;
}

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q2_tracked_tree() {
    let spec = spec();
    display_prover_tracked_tree(spec.tables, spec.sql).await;
}

#[tokio::test]
#[ignore = "Visualization-focused test"]
async fn tpch_q2_piop_tree() {
    let spec = spec();
    display_prover_piop_tree(spec.tables, spec.sql).await;
}
