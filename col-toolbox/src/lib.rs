//! Various PIOPs (Polynomial Interactive Oracle Proofs) and tools for arguing
//! different properties of columns, e.g. inclusion, having no duplicates,
//! having no zeros, etc. The tools here are mainly consumed in `ra-toolbox`.

pub mod binary_check;
pub mod defragger;
pub mod fold_check;
pub mod keyed_sumcheck;
pub mod lookup;
pub mod perm_check;
pub mod rematerialize_check;
pub(crate) mod util;

// TODO: The names here are col_sth, but in the paper they are sth_check. Make
// it consistent

// TODO: All the PIOPs here are invoked like SthPIOP::<F,
// PCS>::prove(...) but zerocheck and sumchecks are invoked like
// add_zerocheck_claim and add_sumcheck_claim, make it consistent. It will be
// easier for debugging and understanding the code.
