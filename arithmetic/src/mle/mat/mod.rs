use ark_ff::{Field, PrimeField};
use ark_poly::MultilinearExtension;
use kit::ark_std::{end_timer, rand::RngCore, start_timer};
#[cfg(feature = "parallel")]
use kit::rayon::prelude::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
use std::sync::Arc;

pub use ark_poly::DenseMultilinearExtension;

use crate::errors::ArithErrors;

use super::virt::build_eq_x_r_vec;

/// Sample a random list of multilinear polynomials.
/// Returns
/// - the list of polynomials,
/// - its sum of polynomial evaluations over the boolean hypercube.
pub fn random_mle_list<F: PrimeField, R: RngCore>(
    nv: usize,
    degree: usize,
    rng: &mut R,
) -> (Vec<Arc<DenseMultilinearExtension<F>>>, F) {
    let start = start_timer!(|| "sample random mle list");
    let mut multiplicands = Vec::with_capacity(degree);
    for _ in 0..degree {
        multiplicands.push(Vec::with_capacity(1 << nv))
    }
    let mut sum = F::zero();

    for _ in 0..(1 << nv) {
        let mut product = F::one();

        for e in multiplicands.iter_mut() {
            let val = F::rand(rng);
            e.push(val);
            product *= val;
        }
        sum += product;
    }

    let list = multiplicands
        .into_iter()
        .map(|x| Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, x)))
        .collect();

    end_timer!(start);
    (list, sum)
}

// Build a randomize list of mle-s whose sum is zero.
pub fn random_zero_mle_list<F: PrimeField, R: RngCore>(
    nv: usize,
    degree: usize,
    rng: &mut R,
) -> Vec<Arc<DenseMultilinearExtension<F>>> {
    let start = start_timer!(|| "sample random zero mle list");

    let mut multiplicands = Vec::with_capacity(degree);
    for _ in 0..degree {
        multiplicands.push(Vec::with_capacity(1 << nv))
    }
    for _ in 0..(1 << nv) {
        multiplicands[0].push(F::zero());
        for e in multiplicands.iter_mut().skip(1) {
            e.push(F::rand(rng));
        }
    }

    let list = multiplicands
        .into_iter()
        .map(|x| Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, x)))
        .collect();

    end_timer!(start);
    list
}

pub fn random_permutation<F: PrimeField, R: RngCore>(
    num_vars: usize,
    num_chunks: usize,
    rng: &mut R,
) -> Vec<F> {
    let len = (num_chunks as u64) * (1u64 << num_vars);
    let mut s_id_vec: Vec<F> = (0..len).map(F::from).collect();
    let mut s_perm_vec = vec![];
    for _ in 0..len {
        let index = rng.next_u64() as usize % s_id_vec.len();
        s_perm_vec.push(s_id_vec.remove(index));
    }
    s_perm_vec
}

/// A list of MLEs that represent a random permutation
pub fn random_permutation_mles<F: PrimeField, R: RngCore>(
    num_vars: usize,
    num_chunks: usize,
    rng: &mut R,
) -> Vec<DenseMultilinearExtension<F>> {
    let s_perm_vec = random_permutation(num_vars, num_chunks, rng);
    let mut res = vec![];
    let n = 1 << num_vars;
    for i in 0..num_chunks {
        res.push(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            s_perm_vec[i * n..i * n + n].to_vec(),
        ));
    }
    res
}

pub fn evaluate_opt<F: PrimeField>(poly: &DenseMultilinearExtension<F>, point: &[F]) -> F {
    assert_eq!(poly.num_vars, point.len());
    fix_variables(poly, point).evaluations[0]
}

pub fn fix_variables<F: PrimeField>(
    poly: &DenseMultilinearExtension<F>,
    partial_point: &[F],
) -> DenseMultilinearExtension<F> {
    assert!(
        partial_point.len() <= poly.num_vars,
        "invalid size of partial point"
    );
    let nv = poly.num_vars;
    let mut poly = poly.evaluations.to_vec();
    let dim = partial_point.len();
    // evaluate single variable of partial point from left to right
    for (i, point) in partial_point.iter().enumerate().take(dim) {
        poly = fix_one_variable_helper(&poly, nv - i, point);
    }

    DenseMultilinearExtension::<F>::from_evaluations_slice(nv - dim, &poly[..(1 << (nv - dim))])
}

fn fix_one_variable_helper<F: PrimeField>(data: &[F], nv: usize, point: &F) -> Vec<F> {
    let mut res = vec![F::zero(); 1 << (nv - 1)];

    // evaluate single variable of partial point from left to right
    #[cfg(not(feature = "parallel"))]
    for i in 0..(1 << (nv - 1)) {
        res[i] = data[i] + (data[(i << 1) + 1] - data[i << 1]) * point;
    }

    #[cfg(feature = "parallel")]
    res.par_iter_mut().enumerate().for_each(|(i, mut x)| {
        *x = data[i << 1] + (data[(i << 1) + 1] - data[i << 1]) * point;
    });

    res
}

/// Increase the number of variables of a multilinear polynomial by adding
/// variables at the front Ex for input (P(X, Y), 3) result in P'(Z, X, Y),
/// where P'(Z, X, Y) = P(X, Y)
pub fn dmle_increase_nv_front<F: PrimeField>(
    mle: &Arc<DenseMultilinearExtension<F>>,
    new_nv: usize,
) -> Arc<DenseMultilinearExtension<F>> {
    if mle.num_vars == new_nv {
        return mle.clone();
    }
    if mle.num_vars > new_nv {
        panic!("dmle_increase_nv Error: old_len > new_len");
    }
    let old_len = 2_usize.pow(mle.num_vars as u32);
    let new_len = 2_usize.pow(new_nv as u32);
    let num_copies = new_len / old_len;
    let mut evals = Vec::<F>::with_capacity(new_len);
    for i in 0..old_len {
        for _ in 0..num_copies {
            evals.push(mle.evaluations[i]);
        }
    }
    Arc::new(DenseMultilinearExtension::from_evaluations_vec(
        new_nv, evals,
    ))
}

/// Increase the number of variables of a multilinear polynomial by adding
/// variables at the back Ex for input (P(X, Y), 3) result in P'(X, Y, Z), where
/// P'(X, Y, Z) = P(X, Y)
pub fn dmle_increase_nv_back<F: PrimeField>(
    mle: &Arc<DenseMultilinearExtension<F>>,
    new_nv: usize,
) -> Arc<DenseMultilinearExtension<F>> {
    if mle.num_vars == new_nv {
        return mle.clone();
    }
    if mle.num_vars > new_nv {
        panic!("dmle_increase_nv Error: old_len > new_len");
    }

    let old_len = 2_usize.pow(mle.num_vars as u32);
    let new_len = 2_usize.pow(new_nv as u32);
    let mut evals = mle.evaluations.clone();
    evals.resize(new_len, F::default());
    for i in old_len..new_len {
        evals[i] = evals[i % old_len];
    }
    Arc::new(DenseMultilinearExtension::from_evaluations_vec(
        new_nv, evals,
    ))
}

// TODO: Do checks on the sizes and number of variables
pub fn fold_mles<F: PrimeField>(
    mles: &[DenseMultilinearExtension<F>],
    challs: &[F],
) -> DenseMultilinearExtension<F> {
    let nv = mles[0].num_vars;
    let mut res = Vec::with_capacity(1 << nv);
    for i in 0..(1 << nv) {
        let mut val = F::zero();
        for (mle, chall) in mles.iter().zip(challs.iter()) {
            val += mle.evaluations[i] * chall;
        }
        res.push(val);
    }
    DenseMultilinearExtension::from_evaluations_vec(nv, res)
}

pub fn rand_mles<F: PrimeField, R: RngCore>(
    num: usize,
    nv: usize,
    rng: &mut R,
) -> Vec<DenseMultilinearExtension<F>> {
    let mut result = Vec::with_capacity(num);
    for _ in 0..num {
        result.push(DenseMultilinearExtension::rand(nv, rng));
    }
    result
}

#[cfg(test)]
mod test {
    use super::{random_permutation_mles, *};
    use ark_ff::UniformRand;
    use ark_poly::{MultilinearExtension, Polynomial};
    use ark_test_curves::bls12_381::Fr;
    use kit::ark_std::test_rng;
    #[test]
    fn test_dmle_increase_nv() {
        let mut rng = test_rng();
        let small_nv = 3;
        let large_nv = 8;

        let small_mle: DenseMultilinearExtension<Fr> =
            random_permutation_mles(small_nv, 1, &mut rng)[0].clone();
        let large_mle = dmle_increase_nv_back(&Arc::new(small_mle.clone()), large_nv);
        let large_eval_pt: Vec<Fr> = (0..large_nv).map(|_| Fr::rand(&mut rng)).collect();
        let small_eval_pt: Vec<Fr> = large_eval_pt[0..small_nv].to_vec();
        let large_mle_rand_eval = large_mle.evaluate(&large_eval_pt);
        let small_mle_rand_eval = small_mle.evaluate(&small_eval_pt);
        println!("large_eval_pt: {:?}", large_eval_pt);
        println!("large_mle_rand_eval: {}", large_mle_rand_eval);
        println!("small_mle_rand_eval: {}", small_mle_rand_eval);

        assert_eq!(large_mle.num_vars(), large_nv);
        assert_eq!(
            large_mle.evaluations[0..2_usize.pow(small_nv as u32)],
            small_mle.evaluations
        );
        assert_eq!(large_mle_rand_eval, small_mle_rand_eval);
    }
}
