use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use ark_std::{Zero, One};
use crate::tracker::prelude::*;
use crate::subroutines::pcs::PolynomialCommitmentScheme;

pub fn calc_bag_supp_advice<E, PCS>(
    bag: &Bag<E, PCS>
) -> Result<(DenseMultilinearExtension<E::ScalarField>, DenseMultilinearExtension<E::ScalarField>, DenseMultilinearExtension<E::ScalarField>), PolyIOPErrors>  // (supp, m)
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    let bag_nv = bag.num_vars();
    let bag_len = 2_usize.pow(bag_nv as u32);
    let bag_poly_evals = bag.poly.evaluations();
    let bag_sel_evals = bag.selector.evaluations();

    // sort ascending with bag_sel = 0 at the end
    let mut indices: Vec<usize> = (0..bag_len).collect();
    indices.sort_by(|&i, &j| (bag_sel_evals[j], bag_poly_evals[i]).cmp(&(bag_sel_evals[i], bag_poly_evals[j])));
    
    let mut reindexed_bag_poly_evals = Vec::<E::ScalarField>::with_capacity(bag_len);
    let mut reindexed_bag_sel_evals = Vec::<E::ScalarField>::with_capacity(bag_len);
    for i in 0..bag_len {
        reindexed_bag_poly_evals.push(bag_poly_evals[indices[i]]);
        reindexed_bag_sel_evals.push(bag_sel_evals[indices[i]]);
    }

    // calculate the SUPP(bag_a) and the corresponding multiplicity vector
    let mut temp_supp_evals = Vec::<E::ScalarField>::with_capacity(bag_len);
    let mut temp_supp_sel_evals = Vec::<E::ScalarField>::with_capacity(bag_len);
    let mut temp_multiplicities = Vec::<E::ScalarField>::with_capacity(bag_len);
    let mut i = 0;


    // get the values of elements actually in the bag and their multiplicities
    // push all the zero elements for bag_sel = 0, replacing poly values with zero
    while i < indices.len() && bag_sel_evals[indices[i]] != E::ScalarField::zero(){
       let val = bag_poly_evals[indices[i]];
       let mut mult: u64 = 0;
       while i < indices.len() && bag_sel_evals[indices[i]] != E::ScalarField::zero() && bag_poly_evals[indices[i]] == val {
           mult += 1;
           i += 1;
       }
       temp_supp_evals.push(val);
       temp_supp_sel_evals.push(E::ScalarField::one());
       temp_multiplicities.push(E::ScalarField::from(mult));
    }
    // extend vectors to the correct length
    // putting zero values at the front for sorting
    let mut supp_evals = Vec::<E::ScalarField>::with_capacity(bag_len);
    let mut supp_sel_evals = Vec::<E::ScalarField>::with_capacity(bag_len);
    let mut multiplicities = Vec::<E::ScalarField>::with_capacity(bag_len);
    supp_evals.extend(vec![E::ScalarField::zero(); bag_len - temp_supp_evals.len()]);
    supp_sel_evals.extend(vec![E::ScalarField::zero(); bag_len - temp_supp_sel_evals.len()]);
    multiplicities.extend(vec![E::ScalarField::zero(); bag_len - temp_multiplicities.len()]);
    supp_evals.extend(temp_supp_evals.clone());
    supp_sel_evals.extend(temp_supp_sel_evals);
    multiplicities.extend(temp_multiplicities);

    // create the mles from the evaluation vectors
    let supp_mle = DenseMultilinearExtension::from_evaluations_vec(bag_nv, supp_evals);
    let supp_sel_mle = DenseMultilinearExtension::from_evaluations_vec(bag_nv, supp_sel_evals);
    let multiplicity_mle = DenseMultilinearExtension::from_evaluations_vec(bag_nv, multiplicities);

    Ok((supp_mle, supp_sel_mle, multiplicity_mle))
}