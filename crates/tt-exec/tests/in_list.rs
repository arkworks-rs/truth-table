#![cfg(feature = "test-utils")]

mod support;

// Lists of four or more values: shorter ones DataFusion already splits.
end_to_end_tests!(&["nation"] => [
    in_list_in_a_filter => "SELECT n_nationkey FROM nation WHERE n_regionkey IN (0, 2, 3, 4)",
    not_in_list_in_a_filter => "SELECT n_nationkey FROM nation WHERE n_nationkey NOT IN (1, 5, 9, 13, 17)",
    string_in_list => "SELECT n_nationkey FROM nation WHERE n_name IN ('ALGERIA', 'BRAZIL', 'CANADA', 'EGYPT')",
    in_list_in_a_projection => "SELECT n_nationkey, CASE WHEN n_regionkey IN (1, 2, 3, 4) THEN 1 ELSE 0 END AS c FROM nation",
    in_list_under_an_or => "SELECT n_nationkey FROM nation WHERE n_nationkey < 3 OR (n_regionkey = 1 AND n_name IN ('ARGENTINA', 'BRAZIL', 'CANADA', 'PERU'))",
]);
