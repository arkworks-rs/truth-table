use ark_ec::pairing::Pairing;
use ark_std::Zero;
use ark_poly::DenseMultilinearExtension;

use crate::zksql_poly_iop::util::prelude::mle_multiplicity_count;
use crate::tracker::prelude::*;
use crate::subroutines::pcs::PolynomialCommitmentScheme;


pub fn calc_bag_inclusion_advice_from_bag<E, PCS> (
    included_bag: &Bag<E, PCS>,
    super_bag: &Bag<E, PCS>,
) -> DenseMultilinearExtension<E::ScalarField> 
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    let included_bag_poly_evals = included_bag.poly.evaluations();
    let included_bag_poly = DenseMultilinearExtension::from_evaluations_vec(included_bag.num_vars(), included_bag_poly_evals);
    let included_bag_sel_evals = included_bag.selector.evaluations();
    let included_bag_sel = DenseMultilinearExtension::from_evaluations_vec(included_bag.num_vars(), included_bag_sel_evals);
    let super_bag_poly_evals = super_bag.poly.evaluations();
    let super_bag_poly = DenseMultilinearExtension::from_evaluations_vec(super_bag.num_vars(), super_bag_poly_evals);
    let super_bag_sel_evals = super_bag.selector.evaluations();
    let super_bag_sel = DenseMultilinearExtension::from_evaluations_vec(super_bag.num_vars(), super_bag_sel_evals);
    calc_bag_inclusion_advice_from_mle::<E>(&included_bag_poly, &included_bag_sel, &super_bag_poly, &super_bag_sel)
}

pub fn calc_bag_inclusion_advice_from_mle<E> (
    included_bag_poly: &DenseMultilinearExtension<E::ScalarField>,
    included_bag_sel: &DenseMultilinearExtension<E::ScalarField>,
    super_bag_poly: &DenseMultilinearExtension<E::ScalarField>,
    super_bag_sel: &DenseMultilinearExtension<E::ScalarField>,
) -> DenseMultilinearExtension<E::ScalarField> 
where
    E: Pairing,
{
    let super_bag_nv = super_bag_poly.num_vars;
    let super_bag_evals = &super_bag_poly.evaluations;
    let super_bag_sel_evals = &super_bag_sel.evaluations;
    let super_bag_len = super_bag_evals.len();
    let mut included_bag_mults_map = mle_multiplicity_count::<E>(included_bag_poly, included_bag_sel);
    let mut super_bag_mult_evals = Vec::<E::ScalarField>::with_capacity(super_bag_len);

    for i in 0..super_bag_len {
        if super_bag_sel_evals[i] == E::ScalarField::zero() {
            // not a real element in the bag, use zero as a placeholder
            super_bag_mult_evals.push(E::ScalarField::zero());
        } else {
            let val = super_bag_evals[i];
            let included_bag_mult = included_bag_mults_map.get(&val);
            if included_bag_mult.is_none() {
                // val is not in included_bag, so zero out the multiplicity
                super_bag_mult_evals.push(E::ScalarField::zero());
            } else {
                // val is in included_bag, use the multiplcity
                super_bag_mult_evals.push(E::ScalarField::from(*included_bag_mult.unwrap()));
                // update the included_bag_mults_map to zero, so if val occurs in bag_bag multiple times we don't double count
                included_bag_mults_map.insert(val, 0);
            }
        }
    }

    let super_bag_mult_mle = DenseMultilinearExtension::from_evaluations_vec(super_bag_nv, super_bag_mult_evals);

    super_bag_mult_mle
}