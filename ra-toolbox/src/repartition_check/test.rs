use super::*;

fn assert_clone<T: Clone>() {}
fn assert_debug<T: std::fmt::Debug>() {}

#[test]
fn repartition_inputs_are_clone_and_debug() {
    assert_clone::<RepartitionPIOPProverInput>();
    assert_clone::<RepartitionPIOPVerifierInput>();
    assert_debug::<RepartitionPIOPProverInput>();
    assert_debug::<RepartitionPIOPVerifierInput>();
}
