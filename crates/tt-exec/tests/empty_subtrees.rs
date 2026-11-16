#![cfg(feature = "test-utils")]
//! Queries with an empty intermediate result: the prover proves the lowest
//! empty subtree empty and prunes the operators above it. An aggregate
//! without GROUP BY stays: it outputs one row over no rows, NULL for any
//! aggregate but COUNT, which the verifier computes itself.

mod support;

end_to_end_tests!(&["nation", "region"] => [
    empty_filter => "SELECT n_nationkey FROM nation WHERE n_nationkey > 100",
    join_with_an_empty_side => "SELECT n_name, r_name FROM nation JOIN region ON n_regionkey = r_regionkey WHERE r_regionkey > 10",
    group_by_over_no_rows => "SELECT n_regionkey, COUNT(*) AS c FROM nation WHERE n_nationkey > 100 GROUP BY n_regionkey",
    order_by_over_no_rows => "SELECT n_name FROM nation WHERE n_nationkey > 100 ORDER BY n_name",
    like_matching_nothing => "SELECT n_nationkey FROM nation WHERE n_name LIKE '%zzz%'",
    count_over_no_rows => "SELECT COUNT(*) AS c FROM nation WHERE n_nationkey > 100",
    count_over_an_empty_join => "SELECT COUNT(*) AS c FROM nation JOIN region ON n_regionkey = r_regionkey WHERE r_regionkey > 10",
    count_column_over_no_rows => "SELECT COUNT(n_name) AS c FROM nation WHERE n_name LIKE '%zzz%'",
    sum_over_no_rows => "SELECT SUM(n_nationkey) AS s FROM nation WHERE n_nationkey > 100",
    aggregates_over_an_empty_join => "SELECT COUNT(*) AS c, MIN(n_name) AS m, MAX(r_regionkey) AS r FROM nation JOIN region ON n_regionkey = r_regionkey WHERE r_regionkey > 10",
    having_over_no_rows => "SELECT COUNT(*) AS c FROM nation WHERE n_nationkey > 100 HAVING COUNT(*) > 0",
]);

end_to_end_tests!(&["supplier"] => [
    sum_divided_over_no_rows => "SELECT SUM(s_acctbal) / CAST(7.0 AS DECIMAL(15, 2)) AS s FROM supplier WHERE s_suppkey < 0",
    avg_over_no_rows => "SELECT AVG(s_acctbal) AS a, COUNT(*) AS c FROM supplier WHERE s_suppkey < 0",
]);
