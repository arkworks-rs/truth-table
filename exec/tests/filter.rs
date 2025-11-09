#![cfg(feature = "test-utils")]

mod support;
use support::end_to_end_tests;

end_to_end_tests!(&["lineitem"] => [
    simple_equality_filter => r#"SELECT l_returnflag, l_linestatus FROM lineitem WHERE l_returnflag = 'R'"#,
    simple_inequality_filter => r#"SELECT l_returnflag, l_linestatus FROM lineitem WHERE l_shipdate < DATE '1998-09-01'"#,

]);
