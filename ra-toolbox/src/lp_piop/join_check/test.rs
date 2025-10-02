use super::*;

fn assert_clone<T: Clone>() {}
fn assert_debug<T: std::fmt::Debug>() {}

#[test]
fn join_inputs_are_clone_and_debug() {
    assert_clone::<JoinPIOPProverInput>();
    assert_clone::<JoinPIOPVerifierInput>();
    assert_debug::<JoinPIOPProverInput>();
    assert_debug::<JoinPIOPVerifierInput>();
}
