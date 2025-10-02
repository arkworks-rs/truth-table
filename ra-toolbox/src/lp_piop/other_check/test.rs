use super::*;

fn assert_clone<T: Clone>() {}
fn assert_debug<T: std::fmt::Debug>() {}

#[test]
fn other_inputs_are_clone_and_debug() {
    assert_clone::<OtherPIOPProverInput>();
    assert_clone::<OtherPIOPVerifierInput>();
    assert_debug::<OtherPIOPProverInput>();
    assert_debug::<OtherPIOPVerifierInput>();
}
