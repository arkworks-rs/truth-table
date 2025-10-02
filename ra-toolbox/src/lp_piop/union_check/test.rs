use super::*;

fn assert_clone<T: Clone>() {}
fn assert_debug<T: std::fmt::Debug>() {}

#[test]
fn union_inputs_are_clone_and_debug() {
    assert_clone::<UnionPIOPProverInput>();
    assert_clone::<UnionPIOPVerifierInput>();
    assert_debug::<UnionPIOPProverInput>();
    assert_debug::<UnionPIOPVerifierInput>();
}
