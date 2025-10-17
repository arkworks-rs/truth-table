use crate::{
    prover::trees::{
        arithmetized_tree::tests::display_prover_arithmetized_tree,
        hint_tree::tests::display_prover_hint_tree, piop_tree::tests::display_prover_piop_tree,
        proof_tree::tests::display_prover_proof_tree,
        tracked_tree::tests::display_prover_tracked_tree,
    },
    test_utils::helper::prove_and_verify_query,
};

const QUERY_SPEC_1: (&str, &str) = (
    "customer",
    r#"
        SELECT
            c_nationkey,
            c_custkey + c_nationkey AS cust_plus_nation,
            SUM(c_acctbal * c_acctbal) AS total_energy,
            AVG(c_acctbal) AS avg_balance,
            COUNT(DISTINCT c_custkey) AS distinct_customers
        FROM customer
        GROUP BY c_nationkey, c_custkey + c_nationkey
    "#,
);

#[tokio::test]
#[ignore = "This test is for visualization purposes and may require manual inspection."]
async fn build_proof_tree() {
    display_prover_proof_tree(QUERY_SPEC_1.0, QUERY_SPEC_1.1).await;
}

#[tokio::test]
#[ignore = "This test is for visualization purposes and may require manual inspection."]
async fn build_hint_tree() {
    display_prover_hint_tree(QUERY_SPEC_1.0, QUERY_SPEC_1.1).await;
}

#[tokio::test]
#[ignore = "This test is for visualization purposes and may require manual inspection."]
async fn build_arithmetized_tree() {
    display_prover_arithmetized_tree(QUERY_SPEC_1.0, QUERY_SPEC_1.1).await;
}
#[tokio::test]
#[ignore = "This test is for visualization purposes and may require manual inspection."]
async fn build_tracked_tree() {
    display_prover_tracked_tree(QUERY_SPEC_1.0, QUERY_SPEC_1.1).await;
}

#[tokio::test]
#[ignore = "This test is for visualization purposes and may require manual inspection."]
async fn build_piop_tree() {
    display_prover_piop_tree(QUERY_SPEC_1.0, QUERY_SPEC_1.1).await;
}

#[tokio::test]
#[ignore = "This test is for visualization purposes and may require manual inspection."]
async fn build_piop_tree2() {
    display_prover_piop_tree(
        "lineitem",
        r#"
        SELECT
            l_suppkey,
            l_linenumber,
            COUNT(l_discount)
        FROM lineitem
        GROUP BY l_suppkey, l_linenumber
    "#,
    )
    .await;
}
#[test]
fn prove_aggregate() {
    prove_and_verify_query(
        r#"
        SELECT
            l_suppkey,
            l_linenumber,
            COUNT(l_discount)
        FROM lineitem
        GROUP BY l_suppkey, l_linenumber
    "#,
        "lineitem",
    );
}
