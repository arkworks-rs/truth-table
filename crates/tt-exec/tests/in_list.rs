#![cfg(feature = "test-utils")]

mod support;

// Lists of four or more values: shorter ones DataFusion already splits.
end_to_end_tests!(&["nation"] => [
    in_list_in_a_filter => "SELECT n_nationkey FROM nation WHERE n_regionkey IN (0, 2, 3, 4)",
    not_in_list_in_a_filter => "SELECT n_nationkey FROM nation WHERE n_nationkey NOT IN (1, 5, 9, 13, 17)",
    string_in_list => "SELECT n_nationkey FROM nation WHERE n_name IN ('ALGERIA', 'BRAZIL', 'CANADA', 'EGYPT')",
    in_list_in_a_projection => "SELECT n_nationkey, CASE WHEN n_regionkey IN (1, 2, 3, 4) THEN 1 ELSE 0 END AS c FROM nation",
    in_list_over_an_expression => "SELECT n_nationkey FROM nation WHERE n_regionkey + 1 IN (1, 3, 4, 5)",
    string_not_in_list => "SELECT n_nationkey FROM nation WHERE n_name NOT IN ('ALGERIA', 'BRAZIL', 'CANADA', 'EGYPT')",
    in_list_under_an_or => "SELECT n_nationkey FROM nation WHERE n_nationkey < 3 OR (n_regionkey = 1 AND n_name IN ('ARGENTINA', 'BRAZIL', 'CANADA', 'PERU'))",
    in_list_matching_no_row => "SELECT n_nationkey FROM nation WHERE n_regionkey IN (10, 20, 30, 40)",
]);

// Lists of more than `MAX_PRODUCT_VALUES` distinct values.
end_to_end_tests!(&["nation"] => [
    long_in_list_in_a_filter => "SELECT n_nationkey FROM nation WHERE n_nationkey IN (0, 2, 4, 6, 8, 10, 12, 14, 16, 18)",
    long_not_in_list_in_a_filter => "SELECT n_nationkey FROM nation WHERE n_nationkey NOT IN (0, 2, 4, 6, 8, 10, 12, 14, 16, 18)",
    long_string_in_list => "SELECT n_nationkey FROM nation WHERE n_name IN ('ALGERIA', 'BRAZIL', 'CANADA', 'EGYPT', 'FRANCE', 'GERMANY', 'INDIA', 'JAPAN', 'KENYA', 'ATLANTIS')",
    long_string_not_in_list => "SELECT n_nationkey FROM nation WHERE n_name NOT IN ('ALGERIA', 'BRAZIL', 'CANADA', 'EGYPT', 'FRANCE', 'GERMANY', 'INDIA', 'JAPAN', 'KENYA', 'ATLANTIS')",
    long_in_list_in_a_projection => "SELECT n_nationkey, CASE WHEN n_nationkey IN (1, 3, 5, 7, 9, 11, 13, 15, 17) THEN 1 ELSE 0 END AS c FROM nation",
    long_in_list_over_an_expression => "SELECT n_nationkey FROM nation WHERE n_regionkey + n_nationkey IN (1, 3, 5, 7, 9, 11, 13, 15, 17)",
    long_in_list_with_repeats => "SELECT n_nationkey FROM nation WHERE n_nationkey IN (1, 1, 2, 2, 3, 4, 5, 6, 7, 8, 9, 9)",
    long_in_list_matching_no_row => "SELECT n_nationkey FROM nation WHERE n_nationkey IN (100, 101, 102, 103, 104, 105, 106, 107, 108)",
    long_in_list_matching_every_row => "SELECT n_nationkey FROM nation WHERE n_regionkey IN (0, 1, 2, 3, 4, 5, 6, 7, 8)",
]);

end_to_end_tests!(&["customer"] => [
    long_in_list_after_a_filter => "SELECT c_custkey FROM customer WHERE c_acctbal > 0 AND c_nationkey IN (0, 2, 4, 6, 8, 10, 12, 14, 16, 18)",
]);
