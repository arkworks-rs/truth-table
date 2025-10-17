use std::{fs::File, hash::Hash, io::BufReader};

use super::ProverTrackedTree;
use crate::{
    proof_nodes::id::NodeId,
    prover::trees::{
        hint_tree::ProverHintTree, proof_tree::ProverProofTree,
        tracked_tree::ProverArithmetizedTree,
    },
    test_utils::test_df_plan,
};
use arithmetic::{ctx::SharedCtx, table_oracle::ArithTableOracle};
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    prover::Prover,
    test_utils::{init_tracing_for_tests, test_prelude},
};
use ark_serialize::CanonicalDeserialize;
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::{
    error::Result as DFResult,
    logical_expr::LogicalPlan,
    prelude::{ParquetReadOptions, SessionContext},
};
use datafusion_expr::LogicalPlanBuilder;
use indexmap::IndexMap;
use tpch_data::test_data_path;
type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;
#[tokio::test]
#[ignore = "This test is for visualization purposes and may require manual inspection."]
async fn can_display_prover_tracked_trees() {
    init_tracing_for_tests();
    display_prover_tracked_tree(
        "lineitem",
        "SELECT count(l_partkey) FROM lineitem GROUP BY 2*l_quantity",
    )
    .await;
}

pub async fn display_prover_tracked_tree(table: &str, query: &str) {
    let ctx = SessionContext::new();
    let plan = test_df_plan(&ctx, query, table).await.unwrap();

    let table_oracle_path = tpch_data::test_data_path("lineitem.oracle");
    let table_oracle_file = File::open(&table_oracle_path).expect("open table oracle commitment");
    let mut reader = BufReader::new(table_oracle_file);
    let table_serializable =
        ArithTableOracle::<F, MvPCS, UvPCS>::deserialize_uncompressed(&mut reader)
            .expect("deserialize table oracle");
    let mut table_oracles = IndexMap::new();
    if let Some(schema) = table_serializable.schema() {
        table_oracles.insert(schema, table_serializable);
    }

    let prover_ctx = SharedCtx::new(table_oracles);

    let proof_tree = ProverProofTree::from_lp(&ctx, prover_ctx, &plan, &NodeId::None);
    let hint_tree = ProverHintTree::from_proof_tree(&ctx, proof_tree)
        .await
        .unwrap();
    let arith_tree = ProverArithmetizedTree::<F, MvPCS, UvPCS>::from_hint_tree(hint_tree).unwrap();
    let (mut prover, _verifier): (Prover<F, MvPCS, UvPCS>, _) = test_prelude().unwrap();
    let tracked_tree = ProverTrackedTree::from_arithmetized_tree(arith_tree, &mut prover).unwrap();
    tracked_tree.arena().keys().for_each(|v| println!("{}", v));
    println!("--------------------------------");
    println!("{}", tracked_tree.display_graphviz());
}
