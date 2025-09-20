use super::*;

fn assert_clone<T: Clone>() {}
fn assert_debug<T: std::fmt::Debug>() {}

#[test]
fn filter_inputs_are_clone_and_debug() {
    assert_clone::<FilterPIOPProverInput>();
    assert_clone::<FilterPIOPVerifierInput>();
    assert_debug::<FilterPIOPProverInput>();
    assert_debug::<FilterPIOPVerifierInput>();
}
