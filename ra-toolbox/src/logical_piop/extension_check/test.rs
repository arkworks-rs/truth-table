use super::*;

fn assert_clone<T: Clone>() {}
fn assert_debug<T: std::fmt::Debug>() {}

#[test]
fn extension_inputs_are_clone_and_debug() {
    assert_clone::<ExtensionPIOPProverInput>();
    assert_clone::<ExtensionPIOPVerifierInput>();
    assert_debug::<ExtensionPIOPProverInput>();
    assert_debug::<ExtensionPIOPVerifierInput>();
}
