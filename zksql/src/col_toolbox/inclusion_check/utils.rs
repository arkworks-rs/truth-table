use arithmetic::{ark_ff, ark_poly};
use crypto::ark_ec::pairing::Pairing;
use arithmetic::ark_ff::{Field, PrimeField};
use arithmetic::ark_poly::DenseMultilinearExtension;
use ark_std::Zero;
use crypto::{ark_ec, pcs::PolynomialCommitmentScheme};
use kit::ark_std;

use crate::{
    col_toolbox::util::prelude::mle_multiplicity_count, tracker::prelude::Col,
};

// TODO: Check if it can be optimized. Also, put in the paper
pub fn calc_inclusion_check_advice_from_col<F, PCS>(
    included_col: &Col<F, PCS>,
    super_col: &Col<F, PCS>,
) -> DenseMultilinearExtension<F>
where
    F: PrimeField + PrimeField,
    PCS: PolynomialCommitmentScheme<F>,
{
    let included_col_poly_evals = included_col.inner_poly.evaluations();
    let included_col_poly = DenseMultilinearExtension::from_evaluations_vec(
        included_col.num_vars(),
        included_col_poly_evals,
    );
    let included_col_sel_evals = included_col.actv_poly.evaluations();
    let included_col_sel = DenseMultilinearExtension::from_evaluations_vec(
        included_col.num_vars(),
        included_col_sel_evals,
    );
    let super_col_poly_evals = super_col.inner_poly.evaluations();
    let super_col_poly =
        DenseMultilinearExtension::from_evaluations_vec(super_col.num_vars(), super_col_poly_evals);
    let super_col_sel_evals = super_col.actv_poly.evaluations();
    let super_col_sel =
        DenseMultilinearExtension::from_evaluations_vec(super_col.num_vars(), super_col_sel_evals);
    calc_inclusion_check_advice_from_mle::<F>(
        &included_col_poly,
        &included_col_sel,
        &super_col_poly,
        &super_col_sel,
    )
}

pub fn calc_inclusion_check_advice_from_mle<F: PrimeField>(
    included_col_poly: &DenseMultilinearExtension<F>,
    included_col_sel: &DenseMultilinearExtension<F>,
    super_col_poly: &DenseMultilinearExtension<F>,
    super_col_sel: &DenseMultilinearExtension<F>,
) -> DenseMultilinearExtension<F>
{
    let super_col_nv = super_col_poly.num_vars;
    let super_col_evals = &super_col_poly.evaluations;
    let super_col_sel_evals = &super_col_sel.evaluations;
    let super_col_len = super_col_evals.len();
    let mut included_col_mults_map =
        mle_multiplicity_count::<F>(included_col_poly, included_col_sel);
    let mut super_col_mult_evals = Vec::<F>::with_capacity(super_col_len);

    for i in 0..super_col_len {
        if super_col_sel_evals[i] == F::zero() {
            // not a real element in the col, use zero as a placeholder
            super_col_mult_evals.push(F::zero());
        } else {
            let val = super_col_evals[i];
            let included_col_mult = included_col_mults_map.get(&val);
            if included_col_mult.is_none() {
                // val is not in included_col, so zero out the multiplicity
                super_col_mult_evals.push(F::zero());
            } else {
                // val is in included_col, use the multiplcity
                super_col_mult_evals.push(F::from(*included_col_mult.unwrap()));
                // update the included_col_mults_map to zero, so if val occurs in col_col
                // multiple times we don't double count
                included_col_mults_map.insert(val, 0);
            }
        }
    }

    let super_col_mult_mle =
        DenseMultilinearExtension::from_evaluations_vec(super_col_nv, super_col_mult_evals);

    super_col_mult_mle
}
