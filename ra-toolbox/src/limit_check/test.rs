use super::*;

fn assert_clone<T: Clone>() {}
fn assert_debug<T: std::fmt::Debug>() {}

#[test]
fn limit_inputs_are_clone_and_debug() {
    assert_clone::<LimitPIOPProverInput>();
    assert_clone::<LimitPIOPVerifierInput>();
    assert_debug::<LimitPIOPProverInput>();
    assert_debug::<LimitPIOPVerifierInput>();
}
