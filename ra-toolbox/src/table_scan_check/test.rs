use super::*;

fn assert_clone<T: Clone>() {}
fn assert_debug<T: std::fmt::Debug>() {}

#[test]
fn table_scan_inputs_are_clone_and_debug() {
    assert_clone::<TableScanPIOPProverInput>();
    assert_clone::<TableScanPIOPVerifierInput>();
    assert_debug::<TableScanPIOPProverInput>();
    assert_debug::<TableScanPIOPVerifierInput>();
}
