use super::*;

fn assert_clone<T: Clone>() {}
fn assert_debug<T: std::fmt::Debug>() {}

#[test]
fn subquery_alias_inputs_are_clone_and_debug() {
    assert_clone::<SubqueryAliasPIOPProverInput>();
    assert_clone::<SubqueryAliasPIOPVerifierInput>();
    assert_debug::<SubqueryAliasPIOPProverInput>();
    assert_debug::<SubqueryAliasPIOPVerifierInput>();
}
