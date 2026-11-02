#![cfg(feature = "test-utils")]
//! Queries with an empty intermediate result: the prover proves the lowest
//! empty subtree empty and prunes the operators above it.
//!
//! TODO(#190): an ungrouped COUNT over no rows cannot be proved yet.

mod support;

end_to_end_tests!(&["nation", "region"] => [
    empty_filter => "SELECT n_nationkey FROM nation WHERE n_nationkey > 100",
    join_with_an_empty_side => "SELECT n_name, r_name FROM nation JOIN region ON n_regionkey = r_regionkey WHERE r_regionkey > 10",
    group_by_over_no_rows => "SELECT n_regionkey, COUNT(*) AS c FROM nation WHERE n_nationkey > 100 GROUP BY n_regionkey",
    order_by_over_no_rows => "SELECT n_name FROM nation WHERE n_nationkey > 100 ORDER BY n_name",
    like_matching_nothing => "SELECT n_nationkey FROM nation WHERE n_name LIKE '%zzz%'",
]);
