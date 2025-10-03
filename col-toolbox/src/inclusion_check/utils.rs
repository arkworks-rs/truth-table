use arithmetic::col::TrackedCol;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};

use crate::util::multiplicity_count::vec_multiplicity_count;

// TODO: Check if it can be optimized. Also, put in the paper
/// Given a super column and a claimed included column, It outputs an MLE
/// representing the multiplicity of the super polynomial elements in the
/// claimed included column. This MLE will be used in the Multiplicity check
pub fn calc_inclusion_multiplicity<F, MvPCS, UvPCS>(
    included_col: &TrackedCol<F, MvPCS, UvPCS>,
    super_col: &TrackedCol<F, MvPCS, UvPCS>,
) -> MLE<F>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    let included_col_evals = included_col.data_poly().evaluations();
    let super_col_evals = super_col.data_poly().evaluations();

    let super_col_nv = super_col.num_vars();
    let super_col_len = super_col_evals.len();

    let super_col_actv_evals = super_col
        .actvtr_poly()
        .as_ref()
        .map(|sel| sel.evaluations());

    let mut included_col_mults_map = match included_col.actvtr_poly() {
        Some(sel) => vec_multiplicity_count::<F>(&included_col_evals, Some(&sel.evaluations())),
        None => vec_multiplicity_count::<F>(&included_col_evals, None),
    };

    let mut super_col_mult_evals = Vec::with_capacity(super_col_len);

    for (i, &val) in super_col_evals.iter().enumerate() {
        if let Some(ref actv_evals) = super_col_actv_evals {
            if actv_evals[i] == F::zero() {
                super_col_mult_evals.push(F::zero());
                continue;
            }
        }

        if let Some(&included_col_mult) = included_col_mults_map.get(&val) {
            super_col_mult_evals.push(F::from(included_col_mult));
            included_col_mults_map.insert(val, 0);
        } else {
            super_col_mult_evals.push(F::zero());
        }
    }

    MLE::from_evaluations_vec(super_col_nv, super_col_mult_evals)
}
