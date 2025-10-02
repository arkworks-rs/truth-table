use super::*;

fn assert_clone<T: Clone>() {}
fn assert_debug<T: std::fmt::Debug>() {}

#[test]
fn window_inputs_are_clone_and_debug() {
    assert_clone::<WindowPIOPProverInput>();
    assert_clone::<WindowPIOPVerifierInput>();
    assert_debug::<WindowPIOPProverInput>();
    assert_debug::<WindowPIOPVerifierInput>();
}
