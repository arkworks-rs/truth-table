use super::*;

fn assert_clone<T: Clone>() {}
fn assert_debug<T: std::fmt::Debug>() {}

#[test]
fn projection_inputs_are_clone_and_debug() {
    assert_clone::<ProjectionPIOPProverInput>();
    assert_clone::<ProjectionPIOPVerifierInput>();
    assert_debug::<ProjectionPIOPProverInput>();
    assert_debug::<ProjectionPIOPVerifierInput>();
}
