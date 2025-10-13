use crate::test_utils::helper::prove_and_verify_query;

#[test]
fn prove_eq_filter() {
    prove_and_verify_query(
        "SELECT l_partkey,l_discount FROM lineitem where l_suppkey = 100",
        "lineitem",
    );
}
#[test]
fn prove_gteq_filter() {
    prove_and_verify_query(
        "SELECT l_partkey,l_discount FROM lineitem where l_suppkey >= 100",
        "lineitem",
    );
}

#[test]
fn prove_gt_filter() {
    prove_and_verify_query(
        "SELECT l_partkey,l_discount FROM lineitem where l_suppkey > 100",
        "lineitem",
    );
}

#[test]
fn prove_lteq_filter() {
    prove_and_verify_query(
        "SELECT l_partkey,l_discount FROM lineitem where l_suppkey <= 100",
        "lineitem",
    );
}

#[test]
fn prove_lt_filter() {
    prove_and_verify_query(
        "SELECT l_partkey,l_discount FROM lineitem where l_suppkey < 100",
        "lineitem",
    );
}

#[test]
fn prove_plus_lt_filter() {
    prove_and_verify_query(
        "SELECT l_partkey,l_discount FROM lineitem where l_suppkey+20 > l_partkey*2-l_orderkey",
        "lineitem",
    );
}

#[test]
fn prove_and_filter() {
    prove_and_verify_query(
        "SELECT l_partkey,l_discount FROM lineitem where l_suppkey+20 > l_partkey AND l_orderkey < 100",
        "lineitem",
    );
}
