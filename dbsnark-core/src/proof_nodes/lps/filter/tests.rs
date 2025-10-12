use crate::test_utils::helper::prove_and_verify_query;

#[test]
fn proves_simple_eq_filter() {
    prove_and_verify_query(
        "SELECT l_partkey,l_discount FROM lineitem where l_suppkey = 100",
        "lineitem",
    );
}
#[test]
fn proves_simple_gteq_filter() {
    prove_and_verify_query(
        "SELECT l_partkey,l_discount FROM lineitem where l_suppkey >= 100",
        "lineitem",
    );
}

#[test]
fn proves_simple_gt_filter() {
    prove_and_verify_query(
        "SELECT l_partkey,l_discount FROM lineitem where l_suppkey > 100",
        "lineitem",
    );
}

#[test]
fn proves_simple_lteq_filter() {
    prove_and_verify_query(
        "SELECT l_partkey,l_discount FROM lineitem where l_suppkey <= 100",
        "lineitem",
    );
}

#[test]
fn proves_simple_lt_filter() {
    prove_and_verify_query(
        "SELECT l_partkey,l_discount FROM lineitem where l_suppkey < 100",
        "lineitem",
    );
}

#[test]
fn proves_simple_plus_lt_filter() {
    prove_and_verify_query(
        "SELECT l_partkey,l_discount FROM lineitem where l_suppkey+20 > l_partkey*2-l_orderkey",
        "lineitem",
    );
}
