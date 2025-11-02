//! Various PIOPs (Polynomial Interactive Oracle Proofs) and tools for arguing
//! different properties of columns, e.g. inclusion, having no duplicates,
//! having no zeros, etc. The tools here are mainly consumed in `ra-toolbox`.

pub mod and_check;
pub mod binary_check;
pub mod contig_lex_sort_check;
pub mod defragger;
pub mod fold_check;
pub mod inclusion_check;
pub mod local_single_col_sort_check;
pub mod multiplicity_check;
pub mod no_dup_check;
pub mod no_zeros_check;
pub mod or_check;
pub mod perm_check;
pub mod predicate_limit_check;
pub mod prescribed_permutation_check;
pub mod rematerialize_check;
pub mod set_intersec;
pub mod sign_check;
pub mod sort_based_multi_col_nodup;
pub mod sort_check;
pub mod supp_check;
pub(crate) mod util;
pub mod zero_expr_check;

// TODO: The names here are col_sth, but in the paper they are sth_check. Make
// it consistent

// TODO: All the PIOPs here are invoked like SthPIOP::<F,
// PCS>::prove(...) but zerocheck and sumchecks are invoked like
// add_zerocheck_claim and add_sumcheck_claim, make it consistent. It will be
// easier for debugging and understanding the code.
