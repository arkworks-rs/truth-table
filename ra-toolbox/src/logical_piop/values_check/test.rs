use super::*;

fn assert_clone<T: Clone>() {}
fn assert_debug<T: std::fmt::Debug>() {}

#[test]
fn values_inputs_are_clone_and_debug() {
    assert_clone::<ValuesPIOPProverInput>();
    assert_clone::<ValuesPIOPVerifierInput>();
    assert_debug::<ValuesPIOPProverInput>();
    assert_debug::<ValuesPIOPVerifierInput>();
}
