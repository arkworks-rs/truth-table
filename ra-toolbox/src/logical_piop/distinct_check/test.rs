use super::*;

fn assert_clone<T: Clone>() {}
fn assert_debug<T: std::fmt::Debug>() {}

#[test]
fn distinct_inputs_are_clone_and_debug() {
    assert_clone::<DistinctPIOPProverInput>();
    assert_clone::<DistinctPIOPVerifierInput>();
    assert_debug::<DistinctPIOPProverInput>();
    assert_debug::<DistinctPIOPVerifierInput>();
}
