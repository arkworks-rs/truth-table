use super::*;

fn assert_clone<T: Clone>() {}
fn assert_debug<T: std::fmt::Debug>() {}

#[test]
fn analyze_inputs_are_clone_and_debug() {
    assert_clone::<AnalyzePIOPProverInput>();
    assert_clone::<AnalyzePIOPVerifierInput>();
    assert_debug::<AnalyzePIOPProverInput>();
    assert_debug::<AnalyzePIOPVerifierInput>();
}
