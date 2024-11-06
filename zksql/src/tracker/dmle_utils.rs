use crate::arithmetic::ArithErrors;
use crate::arithmetic::build_eq_x_r_vec;
use std::sync::Arc;
use ark_poly::DenseMultilinearExtension;
use ark_ff::Field;
use ark_ff::PrimeField;



/// Decompose an integer into a binary vector in little endian.
pub fn bit_decompose(input: u64, num_var: usize) -> Vec<bool> {
    let mut res = Vec::with_capacity(num_var);
    let mut i = input;
    for _ in 0..num_var {
        res.push(i & 1 == 1);
        i >>= 1;
    }
    res
}

pub fn binary_decompose<F: Field>(input: u64, num_var: usize) -> Vec<F> {
    let bit_sequence = bit_decompose(input, num_var);
    bit_sequence.iter().map(|&x| F::from(x as u64)).collect()
}

/// Increase the number of variables of a multilinear polynomial by adding variables at the front
/// Ex for input (P(X, Y), 3) result in P'(Z, X, Y), where P'(Z, X, Y) = P(X, Y)
pub fn dmle_increase_nv_front<F: Field>(
    mle: &Arc<DenseMultilinearExtension<F>>,
    new_nv: usize
) -> Arc<DenseMultilinearExtension<F>> {
    if mle.num_vars == new_nv {
        return mle.clone();
    } if mle.num_vars > new_nv {
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
    Arc::new(DenseMultilinearExtension::from_evaluations_vec(new_nv, evals))
}

/// Increase the number of variables of a multilinear polynomial by adding variables at the back
/// Ex for input (P(X, Y), 3) result in P'(X, Y, Z), where P'(X, Y, Z) = P(X, Y)
pub fn dmle_increase_nv_back<F: Field>(
    mle: &Arc<DenseMultilinearExtension<F>>,
    new_nv: usize
) -> Arc<DenseMultilinearExtension<F>> {
    if mle.num_vars == new_nv {
        return mle.clone();
    } if mle.num_vars > new_nv {
        panic!("dmle_increase_nv Error: old_len > new_len");
    }

    let old_len = 2_usize.pow(mle.num_vars as u32);
    let new_len = 2_usize.pow(new_nv as u32);
    let mut evals = mle.evaluations.clone();
    evals.resize(new_len, F::default());
    for i in old_len..new_len {
        evals[i] = evals[i % old_len];
    }
    Arc::new(DenseMultilinearExtension::from_evaluations_vec(new_nv, evals))
}

/// This function build the eq(x, r) polynomial for any given r.
/// Used in ZeroCheck when converting from zerocheck to sumcheck
/// 
/// Evaluate
///      eq(x,y) = \prod_i=1^num_var (x_i * y_i + (1-x_i)*(1-y_i))
/// over r, which is
///      eq(x,y) = \prod_i=1^num_var (x_i * r_i + (1-x_i)*(1-r_i))
pub fn build_eq_x_r<F: PrimeField>(
    r: &[F],
) -> Result<DenseMultilinearExtension<F>, ArithErrors> {
    let evals = build_eq_x_r_vec(r)?;
    let mle = DenseMultilinearExtension::from_evaluations_vec(r.len(), evals);

    Ok(mle)
}

/// Evaluate eq polynomial.
pub fn eq_eval<F: PrimeField>(x: &[F], y: &[F]) -> Result<F, ArithErrors> {
    if x.len() != y.len() {
        return Err(ArithErrors::InvalidParameters(
            "x and y have different length".to_string(),
        ));
    }
    let mut res = F::one();
    for (&xi, &yi) in x.iter().zip(y.iter()) {
        let xi_yi = xi * yi;
        res *= xi_yi + xi_yi - xi - yi + F::one();
    }
    Ok(res)
}



mod test {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::UniformRand;
    use ark_poly::MultilinearExtension;
    use ark_std::test_rng;

    #[test]
    fn test_dmle_increase_nv() {
        let mut rng = test_rng();
        let small_nv = 3;
        let large_nv = 8;
        
        let small_mle: DenseMultilinearExtension<Fr> = crate::arithmetic::random_permutation_mles(small_nv, 1, &mut rng)[0].clone();
        let large_mle = dmle_increase_nv_back(&Arc::new(small_mle.clone()), large_nv);
        let large_eval_pt: Vec<Fr> = (0..large_nv).map(|_| Fr::rand(&mut rng)).collect();
        let small_eval_pt: Vec<Fr> = large_eval_pt[0..small_nv].to_vec();
        let large_mle_rand_eval = large_mle.evaluate(&large_eval_pt).unwrap();
        let small_mle_rand_eval = small_mle.evaluate(&small_eval_pt).unwrap();
        println!("large_eval_pt: {:?}", large_eval_pt);
        println!("large_mle_rand_eval: {}", large_mle_rand_eval);
        println!("small_mle_rand_eval: {}", small_mle_rand_eval);

        assert_eq!(large_mle.num_vars(), large_nv);
        assert_eq!(large_mle.evaluations[0..2_usize.pow(small_nv as u32)], small_mle.evaluations);
        assert_eq!(large_mle_rand_eval, small_mle_rand_eval);
    }
}