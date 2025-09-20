use super::*;

fn assert_clone<T: Clone>() {}
fn assert_debug<T: std::fmt::Debug>() {}

#[test]
fn explain_inputs_are_clone_and_debug() {
    assert_clone::<ExplainPIOPProverInput>();
    assert_clone::<ExplainPIOPVerifierInput>();
    assert_debug::<ExplainPIOPProverInput>();
    assert_debug::<ExplainPIOPVerifierInput>();
}
