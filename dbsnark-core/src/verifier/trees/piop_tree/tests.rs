use std::{collections::HashMap, fs::File, io::BufReader};

use super::VerifierPIOPTree;
use crate::{
    test_utils::test_df_plan,
    verifier::trees::{proof_tree::VerifierProofTree, tracked_tree::VerifierTrackedTree},
};
use arithmetic::{ctx::SharedCtx, table_oracle::ArithTableOracle};
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    test_utils::test_prelude,
    verifier::Verifier,
};
use ark_serialize::CanonicalDeserialize;
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::{error::Result as DFResult, prelude::SessionContext};
use indexmap::IndexMap;
use tpch_data::test_data_path;

type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;

async fn display_graphviz_for(query: &str, table: &str) -> DFResult<()> {
    let ctx = SessionContext::new();
    let plan = test_df_plan(&ctx, query, table).await?;
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

    let verifier_ctx = SharedCtx::new(table_oracles);
    let proof_tree = VerifierProofTree::from_lp(&ctx, verifier_ctx, &plan);
    let (_prover, mut verifier): (_, Verifier<F, MvPCS, UvPCS>) = test_prelude().unwrap();
    let tracked_tree = VerifierTrackedTree::from_proof_tree(proof_tree, &mut verifier);

    let mut tables = IndexMap::new();
    for node in tracked_tree.proof_tree().sorted_nodes() {
        let node_id = node.node_id();
        if let Some(node_tables) = tracked_tree.tables_for(&node_id) {
            tables.insert(node_id, node_tables.clone());
        }
    }

    let piop_plan = VerifierPIOPTree::new(tracked_tree.proof_tree().clone(), tables);
    println!(
        "The ordered list of nodes {:?}\n",
        piop_plan
            .tracked_table_oracles()
            .keys()
            .map(|k| k.to_string())
            .collect::<Vec<_>>()
    );
    println!("{}", piop_plan.display_graphviz());

    Ok(())
}

#[tokio::test]
#[ignore = "This test is for visualization purposes and may require manual inspection."]
async fn display_graphviz() -> DFResult<()> {
    display_graphviz_for(
        "SELECT l_orderkey FROM lineitem WHERE l_quantity >= l_suppkey",
        "lineitem",
    )
    .await
}
