use ark_ec::pairing::Pairing;
use ark_std::{Zero, One};
use ark_poly::DenseMultilinearExtension;
use crate::zksql_poly_iop::util::prelude::mle_multiplicity_count;


pub fn calc_join_reduction_lr_sel_advice<E>(
    poly_a: &DenseMultilinearExtension<E::ScalarField>,
    a_sel: &DenseMultilinearExtension<E::ScalarField>,
    poly_b: &DenseMultilinearExtension<E::ScalarField>,
    b_sel: &DenseMultilinearExtension<E::ScalarField>,
) ->  (DenseMultilinearExtension<E::ScalarField>, DenseMultilinearExtension<E::ScalarField>)
where
    E: Pairing,
{
   // get the multiplicity counts for bag_a and bag_b
   let a_mults_map = mle_multiplicity_count::<E>(poly_a, a_sel);
   let b_mults_map = mle_multiplicity_count::<E>(poly_b, b_sel);

   // setup vars
   let a_evals = &poly_a.evaluations;
   let b_evals = &poly_b.evaluations;
   let a_nv = poly_a.num_vars;
   let b_nv = poly_b.num_vars;
   let a_len = a_evals.len();
   let b_len = b_evals.len();
   let mut l_sel_evals = Vec::<E::ScalarField>::with_capacity(a_len);
   let mut r_sel_evals = Vec::<E::ScalarField>::with_capacity(b_len);

   // create the selector for L
   for i in 0..a_len {
       let a_val = a_evals[i];
       let b_mult = b_mults_map.get(&a_val);
       if b_mult.is_none() {
           // case where a_val not in bag_b, so it belongs in L
           l_sel_evals.push(E::ScalarField::one());
       } else {
           // case where a_val in bag_b, so doesn't belong in L
           l_sel_evals.push(E::ScalarField::zero());
       }
   }
   // create the selector for R
   for i in 0..b_len {
       let b_val = b_evals[i];
       let a_mult = a_mults_map.get(&b_val);
       if a_mult.is_none() {
           // case where b_val not in bag_a, so it belongs in R
           r_sel_evals.push(E::ScalarField::one());
       } else {
           // case where b_val in bag_a, so doesn't belong in R
           r_sel_evals.push(E::ScalarField::zero());
       }
   }

   // create the mles from the evaluation vectors
   let l_sel_mle = DenseMultilinearExtension::from_evaluations_vec(a_nv, l_sel_evals);
   let r_sel_mle = DenseMultilinearExtension::from_evaluations_vec(b_nv, r_sel_evals);

   (l_sel_mle, r_sel_mle)
}

// pub fn calc_join_reduction_mid_inclusion_advice<E>(
//     mid_a_poly:  &DenseMultilinearExtension<E::ScalarField>,
//     mid_a_sel: &DenseMultilinearExtension<E::ScalarField>,
//     mid_b_poly: &DenseMultilinearExtension<E::ScalarField>,
//     mid_b_sel: &DenseMultilinearExtension<E::ScalarField>,
// ) -> (DenseMultilinearExtension<E::ScalarField>, DenseMultilinearExtension<E::ScalarField>)
// where
//     E: Pairing,
// {
//     let mid_a_inclusion_m = calc_bag_inclusion_advice::<E>(mid_b_poly, mid_b_sel, mid_a_poly, mid_a_sel);
//     let mid_b_inclusion_m = calc_bag_inclusion_advice::<E>(mid_a_poly, mid_a_sel, mid_b_poly, mid_b_sel);

//     (mid_a_inclusion_m, mid_b_inclusion_m)
// }