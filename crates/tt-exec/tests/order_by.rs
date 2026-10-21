#![cfg(feature = "test-utils")]

mod support;

end_to_end_tests!(&["nation"] => [
    order_by_filtered_desc => r#"SELECT n_nationkey, n_name FROM nation WHERE n_regionkey = 1 ORDER BY n_nationkey DESC"#,
    order_by_two_keys => r#"SELECT n_regionkey, n_name FROM nation ORDER BY n_regionkey, n_name"#,
    order_by_with_limit => r#"SELECT n_name FROM nation ORDER BY n_name LIMIT 3"#,
    // Five nations share each region: the result must keep the proof's
    // order among tied rows.
    order_by_with_ties => r#"SELECT n_regionkey, n_nationkey FROM nation ORDER BY n_regionkey"#,
    // The LIMIT keeps two of region 3's five tied nations (#137).
    order_by_with_ties_and_limit => r#"SELECT n_regionkey, n_name FROM nation ORDER BY n_regionkey DESC LIMIT 7"#,
    order_by_filtered_with_ties_and_limit => r#"SELECT n_regionkey, n_name FROM nation WHERE n_nationkey > 2 ORDER BY n_regionkey LIMIT 6"#,
]);

// ORDER BY ... LIMIT through tied rows above a join or an aggregate, whose
// output rows the proof numbers from its inputs' row orders (#137).
end_to_end_tests!(&["nation", "region"] => [
    order_by_ties_limit_pkfk_fk_left => r#"SELECT n.n_name, r.r_name FROM nation n JOIN region r ON n.n_regionkey = r.r_regionkey ORDER BY r.r_name LIMIT 7"#,
    order_by_ties_limit_many_to_many => r#"SELECT n1.n_name AS left_name, n2.n_name AS right_name FROM nation n1 JOIN nation n2 ON n1.n_regionkey = n2.n_regionkey ORDER BY n1.n_regionkey LIMIT 12"#,
    order_by_ties_limit_group_by => r#"SELECT n_regionkey, COUNT(*) AS c FROM nation GROUP BY n_regionkey ORDER BY c LIMIT 2"#,
]);

// Rows tied on `o_orderpriority` come from many customers, so the proof's
// order (by the foreign-key side, orders) differs from (customer, order).
end_to_end_tests!(&["customer", "orders"] => [
    order_by_ties_limit_pkfk_fk_right => r#"SELECT c.c_name, o.o_orderkey FROM customer c JOIN orders o ON c.c_custkey = o.o_custkey ORDER BY o.o_orderpriority LIMIT 10"#,
    // Without a LIMIT too: ResultCheck compares an ORDER BY result in order.
    order_by_ties_above_join => r#"SELECT c.c_name, o.o_orderkey FROM customer c JOIN orders o ON c.c_custkey = o.o_custkey ORDER BY o.o_shippriority, c.c_nationkey"#,
]);
