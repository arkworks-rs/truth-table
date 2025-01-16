pub(crate) mod disjoint_check;
pub(crate) mod eq_check;
pub(crate) mod fold_check;
pub(crate) mod inclusion_check;
pub(crate) mod multiplicity_check;
pub(crate) mod multiplicity_sum_check;
pub(crate) mod no_dup_check;
pub(crate) mod no_zeros_check;
// pub(crate) mod perm_check;
pub(crate) mod prescr_perm_check;
pub(crate) mod sort_check;
pub(crate) mod supp_check;
// mod cross_product;
// mod final_join_one_to_many;
// mod index_transform;
// mod join_reduction;

// mod set_disjoint;
// mod set_union;
// mod set_diff;
// mod set_intersect;
// mod binary_check;

mod util;

// TODO: The names here are col_sth, but in the paper they are sth_check. Make
// it consistent

// TODO: All the PIOPs here are invoked like SthPIOP::<F,
// PCS>::prove(...) but zerocheck and sumchecks are invoked like
// add_zerocheck_claim and add_sumcheck_claim, make it consistent. It will be
// easier for debugging and understanding the code.
