
use ark_ec::pairing::Pairing;
use crate::subroutines::PolynomialCommitmentScheme;
use crate::tracker::prelude::ProverTrackerRef;
use crate::tracker::prelude::Bag;
use crate::tracker::prelude::PolyIOPErrors;
use ark_std::Zero;
use ark_std::One;
use ark_poly::DenseMultilinearExtension;
use std::cmp::max;
use crate::tracker::prelude::TrackedPoly;

pub fn bag_lmr_split<E, PCS>(
    prover_tracker: &mut ProverTrackerRef<E, PCS>,
    bag_a: &Bag<E, PCS>,
    bag_b: &Bag<E, PCS>,
) -> Result<(Bag<E, PCS>, Bag<E, PCS>, Bag<E, PCS>, Bag<E, PCS>), PolyIOPErrors>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    // set up the eval vectors
    let a_nv = bag_a.num_vars();
    let a_len = 2_usize.pow(a_nv as u32);
    let b_nv = bag_b.num_vars();
    let b_len = 2_usize.pow(b_nv as u32);
    let l_nv = a_nv;
    let l_len = a_len;
    let ma_nv = a_nv;
    let ma_len = a_len;
    let mb_nv = b_nv;
    let mb_len = b_len;
    let r_nv = b_nv;
    let r_len = b_len;
    let mut l_evals = Vec::with_capacity(l_len);
    let mut ma_evals = Vec::with_capacity(ma_len);
    let mut mb_evals = Vec::with_capacity(mb_len);
    let mut r_evals = Vec::with_capacity(r_len);

    // get the sorted elements of bag_a and bag_b
    let mut sorted_a_evals = Vec::with_capacity(l_len);
    let a_evals = bag_a.poly.evaluations();
    let a_sel_evals = bag_a.selector.evaluations();
    for i in 0..l_len {
        if !a_sel_evals[i].is_zero() {
            sorted_a_evals.push(a_evals[i]);
        }
    }
    sorted_a_evals.sort();
    let mut sorted_b_evals = Vec::with_capacity(r_len);
    let b_evals = bag_b.poly.evaluations();
    let b_sel_evals = bag_b.selector.evaluations();
    for i in 0..r_len {
        if !b_sel_evals[i].is_zero() {
            sorted_b_evals.push(b_evals[i]);
        }
    }
    sorted_b_evals.sort();

    // itereate through the sorted elements of bag_a and bag_b
    // and create the intermediate bags
    let mut a_counter = 0;
    let mut b_counter = 0;
    while a_counter < sorted_a_evals.len() && b_counter < sorted_b_evals.len() {
        if a_evals[a_counter] < b_evals[b_counter] {
            l_evals.push(a_evals[a_counter]);
            a_counter += 1;
        } else if a_evals[a_counter] > b_evals[b_counter] {
            r_evals.push(b_evals[b_counter]);
            b_counter += 1;
        } else {
            let match_eval = a_evals[a_counter];
            while a_counter < sorted_a_evals.len() && a_evals[a_counter] == match_eval {
                ma_evals.push(a_evals[a_counter]);
                a_counter += 1;
            }
            while b_counter < sorted_b_evals.len() && b_evals[b_counter] == match_eval {
                mb_evals.push(b_evals[b_counter]);
                b_counter += 1;
            }
        }
    }
    for i in a_counter..a_len {
        if !a_sel_evals[i].is_zero() {
            l_evals.push(a_evals[i]);
        }
    }
    for i in b_counter..b_len {
        if !b_sel_evals[i].is_zero() {
            r_evals.push(b_evals[i]);
        }
    }

    // create selectors for the intermediate bags and extend things to the correct length
    let mut l_sel_evals = vec![E::ScalarField::one(); l_evals.len()];
    l_evals.extend(vec![E::ScalarField::zero(); l_len - l_evals.len()]);
    l_sel_evals.extend(vec![E::ScalarField::zero(); l_len - l_sel_evals.len()]);
    let mut ma_sel_evals = vec![E::ScalarField::one(); ma_evals.len()];
    ma_evals.extend(vec![E::ScalarField::zero(); ma_len - ma_evals.len()]);
    ma_sel_evals.extend(vec![E::ScalarField::zero(); ma_len - ma_sel_evals.len()]);
    let mut mb_sel_evals = vec![E::ScalarField::one(); mb_evals.len()];
    mb_evals.extend(vec![E::ScalarField::zero(); mb_len - mb_evals.len()]);
    mb_sel_evals.extend(vec![E::ScalarField::zero(); mb_len - mb_sel_evals.len()]);
    let mut r_sel_evals = vec![E::ScalarField::one(); r_evals.len()];
    r_evals.extend(vec![E::ScalarField::zero(); r_len - r_evals.len()]);
    r_sel_evals.extend(vec![E::ScalarField::zero(); r_len - r_sel_evals.len()]);

    // create the intermediate bags
    let l_mle = DenseMultilinearExtension::from_evaluations_vec(l_nv, l_evals);
    let l_sel_mle = DenseMultilinearExtension::from_evaluations_vec(l_nv, l_sel_evals);
    let ma_mle = DenseMultilinearExtension::from_evaluations_vec(ma_nv, ma_evals);
    let ma_sel_mle = DenseMultilinearExtension::from_evaluations_vec(ma_nv, ma_sel_evals);
    let mb_mle = DenseMultilinearExtension::from_evaluations_vec(mb_nv, mb_evals);
    let mb_sel_mle = DenseMultilinearExtension::from_evaluations_vec(mb_nv, mb_sel_evals);
    let r_mle = DenseMultilinearExtension::from_evaluations_vec(r_nv, r_evals);
    let r_sel_mle = DenseMultilinearExtension::from_evaluations_vec(r_nv, r_sel_evals);
    let l_bag = Bag::new(prover_tracker.track_and_commit_poly(l_mle)?, prover_tracker.track_and_commit_poly(l_sel_mle)?);
    let ma_bag = Bag::new(prover_tracker.track_and_commit_poly(ma_mle)?, prover_tracker.track_and_commit_poly(ma_sel_mle)?);
    let mb_bag = Bag::new(prover_tracker.track_and_commit_poly(mb_mle)?, prover_tracker.track_and_commit_poly(mb_sel_mle)?);
    let r_bag = Bag::new(prover_tracker.track_and_commit_poly(r_mle)?, prover_tracker.track_and_commit_poly(r_sel_mle)?);

    Ok((l_bag, ma_bag, mb_bag, r_bag))
}

pub fn set_lmr_split<E, PCS>(
    prover_tracker: &mut ProverTrackerRef<E, PCS>,
    bag_a: &Bag<E, PCS>,
    bag_b: &Bag<E, PCS>,
) -> Result<(Bag<E, PCS>, Bag<E, PCS>, Bag<E, PCS>), PolyIOPErrors> 
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    let (l_bag, ma_bag, mb_bag, r_bag) = bag_lmr_split(prover_tracker, bag_a, bag_b)?;
    
    // use the smaller bag as the m bag
    // ma_bag and mb_bag should have the same number elements besides zero-selectors because bag_a and bag_b are sets
    let m_bag: Bag<E, PCS>;
    if bag_a.num_vars() < bag_b.num_vars() {
        m_bag = ma_bag;
    } else {
        m_bag = mb_bag;
    }
    Ok((l_bag, m_bag, r_bag))
}

// splits and deduplicates, giveing multiplicity vectors for checking correctness 
pub fn bag_lmr_multiplicity_split<E, PCS>(
    prover_tracker: &mut ProverTrackerRef<E, PCS>,
    bag_a: &Bag<E, PCS>,
    bag_b: &Bag<E, PCS>,
) -> Result<(Bag<E, PCS>, Bag<E, PCS>, Bag<E, PCS>, TrackedPoly<E, PCS>, TrackedPoly<E, PCS>, TrackedPoly<E, PCS>, TrackedPoly<E, PCS>,), PolyIOPErrors>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    // set up the eval vectors
    let a_nv = bag_a.num_vars();
    let a_len = 2_usize.pow(a_nv as u32);
    let b_nv = bag_b.num_vars();
    let b_len = 2_usize.pow(b_nv as u32);
    let left_nv = a_nv;
    let left_len = a_len;
    let mid_nv = max(a_nv, b_nv);
    let mid_len = max(a_len, b_len);
    let right_nv = b_nv;
    let right_len = b_len;
    let mut l_evals = Vec::<E::ScalarField>::with_capacity(left_len);
    let mut l_mul_evals = Vec::<E::ScalarField>::with_capacity(left_len);
    let mut m_evals = Vec::<E::ScalarField>::with_capacity(mid_len);
    let mut m_amul_evals = Vec::<E::ScalarField>::with_capacity(mid_len);
    let mut m_bmul_evals = Vec::<E::ScalarField>::with_capacity(mid_len);
    let mut r_evals = Vec::<E::ScalarField>::with_capacity(right_len);
    let mut r_mul_evals =  Vec::<E::ScalarField>::with_capacity(right_len);

    // get the sorted elements of bag_a and bag_b
    let mut sorted_a_evals = Vec::<E::ScalarField>::with_capacity(left_len);
    let a_evals = bag_a.poly.evaluations();
    let a_sel_evals = bag_a.selector.evaluations();
    for i in 0..left_len {
        if !a_sel_evals[i].is_zero() {
            sorted_a_evals.push(a_evals[i]);
        }
    }
    sorted_a_evals.sort();
    let mut sorted_b_evals = Vec::<E::ScalarField>::with_capacity(right_len);
    let b_evals = bag_b.poly.evaluations();
    let b_sel_evals = bag_b.selector.evaluations();
    for i in 0..right_len {
        if !b_sel_evals[i].is_zero() {
            sorted_b_evals.push(b_evals[i]);
        }
    }
    sorted_b_evals.sort();

    // itereate through the sorted elements of bag_a and bag_b
    // and create the intermediate bags
    let mut a_index = 0;
    let mut b_index = 0;
    while a_index < sorted_a_evals.len() && b_index < sorted_b_evals.len() {
        if a_evals[a_index] < b_evals[b_index] {
            let mut mul_counter: u64 = 0;
            let val = a_evals[a_index];
            while a_evals[a_index] == val {
                mul_counter += 1;
                a_index += 1;
            }
            l_evals.push(a_evals[a_index]);
            l_mul_evals.push(E::ScalarField::from(mul_counter));
        } else if a_evals[a_index] > b_evals[b_index] {
            let mut mul_counter: u64 = 0;
            let val = b_evals[b_index];
            while b_evals[b_index] == val {
                mul_counter += 1;
                b_index += 1;
            }
            r_evals.push(b_evals[b_index]);
            r_mul_evals.push(E::ScalarField::from(mul_counter));
        } else {
            let match_eval = a_evals[a_index];
            let mut a_mul_counter: u64 = 0;
            let mut b_mul_counter: u64 = 0;
            while a_index < sorted_a_evals.len() && a_evals[a_index] == match_eval {
                a_mul_counter += 1;
                a_index += 1;
            }
            while b_index < sorted_b_evals.len() && b_evals[b_index] == match_eval {
                b_mul_counter += 1;
                b_index += 1;
            }
            m_evals.push(match_eval);
            m_amul_evals.push(E::ScalarField::from(a_mul_counter));
            m_bmul_evals.push(E::ScalarField::from(b_mul_counter));
        }
    }
    for i in a_index..a_len {
        if !a_sel_evals[i].is_zero() {
            let mut mul_counter: u64 = 0;
            let val = a_evals[a_index];
            while a_evals[a_index] == val {
                mul_counter += 1;
                a_index += 1;
            }
            l_evals.push(a_evals[a_index]);
            l_mul_evals.push(E::ScalarField::from(mul_counter));
        }
    }
    for i in b_index..b_len {
        if !b_sel_evals[i].is_zero() {
            let mut mul_counter: u64 = 0;
            let val = b_evals[b_index];
            while b_evals[b_index] == val {
                mul_counter += 1;
                b_index += 1;
            }
            r_evals.push(b_evals[b_index]);
            r_mul_evals.push(E::ScalarField::from(mul_counter));
        }
    }

    // create selectors for the intermediate bags and extend things to the correct length
    let mut l_sel_evals = vec![E::ScalarField::one(); l_evals.len()];
    l_evals.extend(vec![E::ScalarField::zero(); left_len - l_evals.len()]);
    l_sel_evals.extend(vec![E::ScalarField::zero(); left_len - l_sel_evals.len()]);
    l_mul_evals.extend(vec![E::ScalarField::zero(); left_len - l_mul_evals.len()]);
    let mut m_sel_evals = vec![E::ScalarField::one(); m_evals.len()];
    m_evals.extend(vec![E::ScalarField::zero(); mid_len - m_evals.len()]);
    m_sel_evals.extend(vec![E::ScalarField::zero(); mid_len - m_sel_evals.len()]);
    m_amul_evals.extend(vec![E::ScalarField::zero(); mid_len - m_amul_evals.len()]);
    m_bmul_evals.extend(vec![E::ScalarField::zero(); mid_len - m_bmul_evals.len()]);
    let mut r_sel_evals = vec![E::ScalarField::one(); r_evals.len()];
    r_evals.extend(vec![E::ScalarField::zero(); right_len - r_evals.len()]);
    r_sel_evals.extend(vec![E::ScalarField::zero(); right_len - r_sel_evals.len()]);
    r_mul_evals.extend(vec![E::ScalarField::zero(); right_len - r_mul_evals.len()]);

    // create the intermediate bags
    let l_mle = DenseMultilinearExtension::from_evaluations_vec(left_nv, l_evals);
    let l_sel_mle = DenseMultilinearExtension::from_evaluations_vec(left_nv, l_sel_evals);
    let l_mul_mle = DenseMultilinearExtension::from_evaluations_vec(left_nv, l_mul_evals);
    let m_mle = DenseMultilinearExtension::from_evaluations_vec(mid_nv, m_evals);
    let m_sel_mle = DenseMultilinearExtension::from_evaluations_vec(mid_nv, m_sel_evals);
    let m_amul_mle = DenseMultilinearExtension::from_evaluations_vec(mid_nv, m_amul_evals);
    let m_bmul_mle = DenseMultilinearExtension::from_evaluations_vec(mid_nv, m_bmul_evals);
    let r_mle = DenseMultilinearExtension::from_evaluations_vec(right_nv, r_evals);
    let r_sel_mle = DenseMultilinearExtension::from_evaluations_vec(right_nv, r_sel_evals);
    let r_mul_mle = DenseMultilinearExtension::from_evaluations_vec(right_nv, r_mul_evals);

    let l_bag = Bag::new(prover_tracker.track_and_commit_poly(l_mle)?, prover_tracker.track_and_commit_poly(l_sel_mle)?);
    let m_bag = Bag::new(prover_tracker.track_and_commit_poly(m_mle)?, prover_tracker.track_and_commit_poly(m_sel_mle)?);
    let r_bag = Bag::new(prover_tracker.track_and_commit_poly(r_mle)?, prover_tracker.track_and_commit_poly(r_sel_mle)?);
    let l_mul = prover_tracker.track_and_commit_poly(l_mul_mle)?;
    let ma_mul = prover_tracker.track_and_commit_poly(m_amul_mle)?;
    let mb_mul = prover_tracker.track_and_commit_poly(m_bmul_mle)?;
    let r_mul = prover_tracker.track_and_commit_poly(r_mul_mle)?;

    Ok((l_bag, m_bag, r_bag, l_mul, ma_mul, mb_mul, r_mul))
}


#[cfg(test)]
mod test {

    use super::*;
    use crate::subroutines::MultilinearKzgPCS;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_std::test_rng;

    #[test]
    pub fn test_bag_lmr_split() -> Result<(), PolyIOPErrors> {
        let a_nv = 4;
        let b_nv = 3;
        let a_nums = vec![1, 2, 3, 4, 5, 6, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let a_sel_nums = vec![1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let b_nums = vec![5, 5, 6, 16, 17, 18, 0, 0];
        let b_sel_nums = vec![1, 1, 1, 1, 1, 1, 0, 0];

        // PCS params
        let mut rng = test_rng();
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, 10)?;
        let (pcs_prover_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(10))?;

        // create trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        
        let a_mle = DenseMultilinearExtension::from_evaluations_vec(a_nv, a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_sel_mle = DenseMultilinearExtension::from_evaluations_vec(a_nv, a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_mle = DenseMultilinearExtension::from_evaluations_vec(b_nv, b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_sel_mle = DenseMultilinearExtension::from_evaluations_vec(b_nv, b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_poly = prover_tracker.track_and_commit_poly(a_mle)?;
        let a_sel_poly = prover_tracker.track_and_commit_poly(a_sel_mle)?;
        let b_poly = prover_tracker.track_and_commit_poly(b_mle)?;
        let b_sel_poly = prover_tracker.track_and_commit_poly(b_sel_mle)?;
        let a_bag = Bag::new(a_poly, a_sel_poly);
        let b_bag = Bag::new(b_poly, b_sel_poly);

        let (l_bag, ma_bag, mb_bag, r_bag) = bag_lmr_split(&mut prover_tracker, &a_bag, &b_bag)?;
    
        let exp_l_poly_nums = vec![1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let exp_l_poly_sel_nums = vec![1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let exp_ma_poly_nums = vec![5, 6, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let exp_ma_poly_sel_nums = vec![1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let exp_mb_poly_nums = vec![5, 5, 6, 0, 0, 0, 0, 0];
        let exp_mb_poly_sel_nums = vec![1, 1, 1, 0, 0, 0, 0, 0];
        let exp_r_poly_nums = vec![16, 17, 18, 0, 0, 0, 0, 0];
        let exp_r_poly_sel_nums = vec![1, 1, 1, 0, 0, 0, 0, 0];
        let exp_l_evals = exp_l_poly_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let exp_l_sel_evals = exp_l_poly_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let exp_ma_evals = exp_ma_poly_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let exp_ma_sel_evals = exp_ma_poly_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let exp_mb_evals = exp_mb_poly_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let exp_mb_sel_evals = exp_mb_poly_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let exp_r_evals = exp_r_poly_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let exp_r_sel_evals = exp_r_poly_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();

        assert_eq!(l_bag.poly.evaluations(), exp_l_evals);
        assert_eq!(l_bag.selector.evaluations(), exp_l_sel_evals);
        assert_eq!(ma_bag.poly.evaluations(), exp_ma_evals);
        assert_eq!(ma_bag.selector.evaluations(), exp_ma_sel_evals);
        assert_eq!(mb_bag.poly.evaluations(), exp_mb_evals);
        assert_eq!(mb_bag.selector.evaluations(), exp_mb_sel_evals);
        assert_eq!(r_bag.poly.evaluations(), exp_r_evals);
        assert_eq!(r_bag.selector.evaluations(), exp_r_sel_evals);

        Ok(())
    }

    #[test]
    fn test_set_lmr_split() -> Result<(), PolyIOPErrors> {
        let a_nv = 4;
        let b_nv = 3;
        let a_nums =        vec![1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let a_sel_nums =    vec![1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let b_nums =        vec![5, 6, 7, 16, 17, 18, 0, 0];
        let b_sel_nums =    vec![1, 1, 1, 1, 1, 1, 0, 0];

        // PCS params
        let mut rng = test_rng();
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, 10)?;
        let (pcs_prover_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(10))?;

        // create trackers
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        
        let a_mle = DenseMultilinearExtension::from_evaluations_vec(a_nv, a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_sel_mle = DenseMultilinearExtension::from_evaluations_vec(a_nv, a_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_mle = DenseMultilinearExtension::from_evaluations_vec(b_nv, b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let b_sel_mle = DenseMultilinearExtension::from_evaluations_vec(b_nv, b_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect());
        let a_poly = prover_tracker.track_and_commit_poly(a_mle)?;
        let a_sel_poly = prover_tracker.track_and_commit_poly(a_sel_mle)?;
        let b_poly = prover_tracker.track_and_commit_poly(b_mle)?;
        let b_sel_poly = prover_tracker.track_and_commit_poly(b_sel_mle)?;
        let a_bag = Bag::new(a_poly, a_sel_poly);
        let b_bag = Bag::new(b_poly, b_sel_poly);
        let (l_bag, m_bag, r_bag) = set_lmr_split(&mut prover_tracker, &a_bag, &b_bag)?;
    
        let exp_l_poly_nums = vec![1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let exp_l_poly_sel_nums = vec![1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let exp_m_poly_nums = vec![5, 6, 7, 0, 0, 0, 0, 0];
        let exp_m_poly_sel_nums = vec![1, 1, 1, 0, 0, 0, 0, 0];
        let exp_r_poly_nums = vec![16, 17, 18, 0, 0, 0, 0, 0];
        let exp_r_poly_sel_nums = vec![1, 1, 1, 0, 0, 0, 0, 0];
        let exp_l_evals = exp_l_poly_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let exp_l_sel_evals = exp_l_poly_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let exp_m_evals = exp_m_poly_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let exp_m_sel_evals = exp_m_poly_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let exp_r_evals = exp_r_poly_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();
        let exp_r_sel_evals = exp_r_poly_sel_nums.iter().map(|x| Fr::from(*x as u64)).collect::<Vec<Fr>>();

        assert_eq!(l_bag.poly.evaluations(), exp_l_evals);
        assert_eq!(l_bag.selector.evaluations(), exp_l_sel_evals);
        assert_eq!(m_bag.poly.evaluations(), exp_m_evals);
        assert_eq!(m_bag.selector.evaluations(), exp_m_sel_evals);
        assert_eq!(r_bag.poly.evaluations(), exp_r_evals);
        assert_eq!(r_bag.selector.evaluations(), exp_r_sel_evals);

        Ok(())
    }
}