use super::*;

fn assert_clone<T: Clone>() {}
fn assert_debug<T: std::fmt::Debug>() {}

#[test]
fn subquery_inputs_are_clone_and_debug() {
    assert_clone::<SubqueryPIOPProverInput>();
    assert_clone::<SubqueryPIOPVerifierInput>();
    assert_debug::<SubqueryPIOPProverInput>();
    assert_debug::<SubqueryPIOPVerifierInput>();
}
