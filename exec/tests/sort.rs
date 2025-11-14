mod support;

end_to_end_tests!(&["lineitem"] => [
    project_sort => r#"
        SELECT l_suppkey
        FROM lineitem
        ORDER BY l_suppkey ASC;
    "#,
    project_sort_1 => r#"
SELECT 
    l_suppkey,
    (l_suppkey * 7 + 3) AS computed_key
FROM lineitem
ORDER BY 4 + (l_suppkey * 7 + 3) DESC, l_suppkey ASC;
    "#,
    filter_sort => r#"
        SELECT 
    l_suppkey,
    (l_suppkey * 7 + 3) AS computed_key
FROM lineitem
WHERE l_suppkey > 1000
ORDER BY 4 +  (l_suppkey * 7 + 3) DESC, l_suppkey ASC;"#,
    groupby_sort => r#"
SELECT
    l_shipdate,
    l_commitdate,
    SUM(l_extendedprice * (1 - l_discount)) AS revenue,
    COUNT(*) AS row_count
FROM lineitem
GROUP BY
    l_shipdate,
    l_commitdate
ORDER BY
    l_shipdate,
    l_commitdate;
    "#,
]);

type F = ark_test_curves::bls12_381::Fr;
type MvPCS = ark_piop::pcs::pst13::PST13<ark_test_curves::bls12_381::Bls12_381>;
type UvPCS = ark_piop::pcs::kzg10::KZG10<ark_test_curves::bls12_381::Bls12_381>;
