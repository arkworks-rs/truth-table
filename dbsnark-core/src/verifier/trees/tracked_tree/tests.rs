use std::{collections::HashMap, fs::File, io::BufReader, time::Instant};

use crate::{
    prover::trees::{
        arithmetized_tree::ProverArithmetizedTree, hint_tree::ProverHintTree,
        piop_tree::ProverPIOPTree, proof_tree::ProverProofTree, tracked_tree::ProverTrackedTree,
    },
    test_utils::test_df_plan,
    verifier::trees::{proof_tree::VerifierProofTree, tracked_tree::VerifierTrackedTree},
};
use arithmetic::{ctx::SharedCtx, table_oracle::ArithTableOracle};
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    test_utils::{init_tracing_for_tests, test_prelude},
    verifier,
};
use ark_serialize::CanonicalDeserialize;
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::prelude::SessionContext;
use tpch_data::test_data_path;

type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;

#[tokio::test]
#[ignore = "This test is for visualization purposes and may require manual inspection."]
async fn display_graphviz() {
    display_graphviz_for(
        "lineitem",
        "SELECT l_partkey, l_extendedprice FROM lineitem where l_linenumber == 5 ",
    )
    .await;
    // display_graphviz_for(
    //     "lineitem",
    //     "SELECT count(l_partkey) FROM lineitem GROUP BY 2*l_quantity",
    // )
    // .await;
}

async fn display_graphviz_for(table: &str, query: &str) {
    init_tracing_for_tests();
    let ctx = SessionContext::new();
    let (mut prover, mut verifier) = test_prelude::<F, MvPCS, UvPCS>().unwrap();
    let plan = test_df_plan(&ctx, query, table).await.unwrap();

    let table_oracle_path = test_data_path("lineitem.oracle");
    let table_oracle_file = File::open(&table_oracle_path).expect("open table oracle commitment");
    let mut reader = BufReader::new(table_oracle_file);
    let table_serializable =
        ArithTableOracle::<F, MvPCS, UvPCS>::deserialize_uncompressed(&mut reader)
            .expect("deserialize table oracle");
    let mut table_oracles = HashMap::new();
    if let Some(schema) = table_serializable.schema() {
        table_oracles.insert(schema, table_serializable);
    }

    let shared_ctx = SharedCtx::new(table_oracles);
    let prover_ctx = shared_ctx.clone();
    let verifier_ctx = shared_ctx.clone();

    let proof_tree = ProverProofTree::<F, MvPCS, UvPCS>::from_lp(&ctx, prover_ctx, &plan);
    let hint_tree = ProverHintTree::from_proof_tree(&ctx, proof_tree.clone())
        .await
        .expect("hint tree");
    let arith_tree = ProverArithmetizedTree::<F, MvPCS, UvPCS>::from_hint_tree(hint_tree)
        .expect("arithmetized tree");
    let tracked_tree =
        ProverTrackedTree::from_arithmetized_tree(arith_tree, &mut prover).expect("tracked tree");
    let mut piop_tree = ProverPIOPTree::from_tracked_plan(tracked_tree, &mut prover);
    let flattened = piop_tree.proof_tree().clone().flatten();
    for node in flattened.values() {
        node.prove_piop(&mut prover, &mut piop_tree)
            .expect("prove piop");
    }
    let proof = prover.build_proof().expect("build proof");

    verifier.set_proof(proof);
    let verifier_proof_tree = VerifierProofTree::from_lp(&ctx, verifier_ctx, &plan);
    let verifier_tracked_tree =
        VerifierTrackedTree::from_proof_tree(verifier_proof_tree.clone(),shared_ctx, &mut verifier);
    println!("{}", verifier_tracked_tree.display_graphviz());
}
