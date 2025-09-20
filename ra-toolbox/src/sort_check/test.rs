use super::*;

fn assert_clone<T: Clone>() {}
fn assert_debug<T: std::fmt::Debug>() {}

#[test]
fn sort_inputs_are_clone_and_debug() {
    assert_clone::<SortPIOPProverInput>();
    assert_clone::<SortPIOPVerifierInput>();
    assert_debug::<SortPIOPProverInput>();
    assert_debug::<SortPIOPVerifierInput>();
}
