use ark_ff::{FftField, PrimeField};
use ark_piop::{
    arithmetic::{
        index,
        mat_poly::{lde::LDE, mle::MLE},
    },
    errors::{SnarkError, SnarkResult},
};
use ark_poly::DenseUVPolynomial;
use ark_std::cfg_iter;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
/// Compute the product polynomial $f(X): \mathbb{F}^{\mu+1}\to\mathbb{F}$ such
/// that $$ f(X)=[(1-x_1)\cdot p(x_2, ..., x_n, 0) + x_1\cdot f(x_2, ..., x_n,
/// 0)]\times [(1-x_1)\times p(x_2, ..., x_n, 1) + x_1\times f(x_2, ..., x_n,
/// 1)]$$ on the boolean hypercube {0,1}^n
///
/// The caller needs to check num_vars matches in f and g
/// Cost: linear in N.
pub(super) fn compute_product_poly<F: PrimeField>(
    evals: &[F],
    num_vars: usize,
) -> SnarkResult<MLE<F>> {
    // ===================================
    // prod(x)
    // ===================================
    //
    // `prod(x)` can be computed via recursing the following formula for 2^n-1
    // times
    //
    // `prod(x_1, ..., x_n) :=
    //      [(1-x1)*p(x2, ..., xn, 0) + x1*prod(x2, ..., xn, 0)] *
    //      [(1-x1)*p(x2, ..., xn, 1) + x1*prod(x2, ..., xn, 1)]`
    //
    // At any given step, the right hand side of the equation
    // is available via either p_x or the current view of prod_x
    let mut prod_x_evals = vec![];
    for x in 0..(1 << num_vars) - 1 {
        // sign will decide if the evaluation should be looked up from p_x or
        // prod_x; x_zero_index is the index for the evaluation (x_2, ..., x_n,
        // 0); x_one_index is the index for the evaluation (x_2, ..., x_n, 1);
        let (x_zero_index, x_one_index, sign) = index(x, num_vars);
        if !sign {
            prod_x_evals.push(evals[x_zero_index] * evals[x_one_index]);
        } else {
            // sanity check: if we are trying to look up from the prod_x_evals table,
            // then the target index must already exist
            if x_zero_index >= prod_x_evals.len() || x_one_index >= prod_x_evals.len() {
                return Err(SnarkError::DummyError);
            }
            prod_x_evals.push(prod_x_evals[x_zero_index] * prod_x_evals[x_one_index]);
        }
    }

    // prod(1, 1, ..., 1) := 0
    prod_x_evals.push(F::zero());
    Ok(MLE::from_evaluations_vec(num_vars, prod_x_evals))
}

/// Compute the product polynomial $f'(X): \mathbb{F}^{\mu+1}\to\mathbb{F}$ such
/// that $$ f(X)=[(1-x_1)\cdot p(x_2, ..., x_n, 0) + x_1\cdot f(x_2, ..., x_n,
/// 0)]\times [(1-x_1)\times p(x_2, ..., x_n, 1) + x_1\times f(x_2, ..., x_n,
/// 1)]$$ on the boolean hypercube {0,1}^n
///
///
/// The caller needs to check num_vars matches in f and g
/// Cost: linear in N.
pub(super) fn compute_derivative_poly<F: PrimeField>(
    p_evals: &[F],
    f_evals: &[F],
    num_vars: usize,
) -> SnarkResult<MLE<F>> {
    // TODO: Check the sizes
    // ===================================
    // prod(x)
    // ===================================
    //
    // `prod(x)` can be computed via recursing the following formula for 2^n-1
    // times
    //
    // `prod(x_1, ..., x_n) :=
    //      [(1-x1)*p(x2, ..., xn, 0) + x1*prod(x2, ..., xn, 0)] *
    //      [(1-x1)*p(x2, ..., xn, 1) + x1*prod(x2, ..., xn, 1)]`
    //
    // At any given step, the right hand side of the equation
    // is available via either p_x or the current view of prod_x
    let mut f_prime_evals = vec![];
    for x in 0..(1 << num_vars) - 1 {
        // sign will decide if the evaluation should be looked up from p_x or
        // prod_x; x_zero_index is the index for the evaluation (x_2, ..., x_n,
        // 0); x_one_index is the index for the evaluation (x_2, ..., x_n, 1);
        let (x_zero_index, x_one_index, sign) = index(x, num_vars);
        if !sign {
            f_prime_evals.push(p_evals[x_zero_index] + p_evals[x_one_index]);
        } else {
            // sanity check: if we are trying to look up from the prod_x_evals table,
            // then the target index must already exist
            if x_zero_index >= f_prime_evals.len() || x_one_index >= f_prime_evals.len() {
                return Err(SnarkError::DummyError);
            }
            f_prime_evals.push(
                f_evals[x_zero_index] * f_prime_evals[x_one_index]
                    + f_prime_evals[x_zero_index] * f_evals[x_one_index],
            );
        }
    }

    // prod(1, 1, ..., 1) := 0
    f_prime_evals.push(F::zero());

    Ok(MLE::from_evaluations_vec(num_vars, f_prime_evals))
}

// This can be improved
pub fn build_root_products<F: FftField>(roots: &[F]) -> LDE<F> {
    let l = roots.len();

    if l == 1 {
        return LDE::from_coefficients_vec(vec![-roots[0], F::one()]);
    }

    let mid = l / 2;
    let (left, right) = roots.split_at(mid);

    #[cfg(not(feature = "parallel"))]
    {
        let left_poly = build_root_products(left);
        let right_poly = build_root_products(right);
    }

    #[cfg(feature = "parallel")]
    // Parallelize the recursive calls using Rayon
    let (left_poly, right_poly) = rayon::join(
        || build_root_products(left),  // Run in parallel
        || build_root_products(right), // Run in parallel
    );

    left_poly * right_poly
}

pub fn d_dx<F: PrimeField>(poly: &LDE<F>) -> LDE<F> {
    // Skip the constant term and parallelize the computation of the derivative
    let coeffs: Vec<F> = cfg_iter!(poly
            .coeffs)
        .enumerate() // Get the index for each coefficient
        .skip(1) // Skip the constant term since its derivative is 0
        .map(|(i, coeff)| F::from(i as u64) * coeff) // Derivative: i * coeff[i]
        .collect();

    LDE { coeffs }
}

#[cfg(test)]
mod tests {
    use ark_ff::Field;
    use ark_piop::arithmetic::mat_poly::lde::LDE;
    use ark_poly::DenseUVPolynomial;
    use ark_test_curves::bls12_381::Fr;

    use super::{build_root_products, d_dx};
    #[test]
    fn test_build_root_products() {
        let roots = vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        let poly = build_root_products(&roots);
        let expected = LDE::from_coefficients_vec(vec![
            Fr::from(24u64),
            Fr::from(-50i64),
            Fr::from(35u64),
            Fr::from(-10i64),
            Fr::ONE,
        ]);
        assert_eq!(poly, expected);
    }

    #[test]
    fn test_d_dx() {
        let poly = LDE::from_coefficients_vec(vec![
            Fr::from(24u64),
            Fr::from(-50i64),
            Fr::from(35u64),
            Fr::from(-10i64),
            Fr::ONE,
        ]);
        let expected = LDE::from_coefficients_vec(vec![
            Fr::from(-50i64),
            Fr::from(70u64),
            Fr::from(-30i64),
            Fr::from(4u64),
        ]);
        assert_eq!(d_dx(&poly), expected);
    }
}

#[cfg(test)]
mod test {
    use ark_test_curves::bls12_381::Fr;

    #[test]
    fn test_compute_product_poly() {
        let p_evals = vec![
            Fr::from(2),
            Fr::from(5),
            Fr::from(6),
            Fr::from(4),
            Fr::from(1),
            Fr::from(3),
            Fr::from(2),
            Fr::from(9),
        ];
        let prod = super::compute_product_poly(&p_evals, 3).unwrap();
        assert_eq!(
            prod.evaluations(),
            vec![
                Fr::from(10),
                Fr::from(24),
                Fr::from(3),
                Fr::from(18),
                Fr::from(240),
                Fr::from(54),
                Fr::from(12960),
                Fr::from(0)
            ]
        );
    }

    #[test]
    fn test_compute_derivative_poly() {
        let gamma = Fr::from(10);
        let c_evals = vec![
            Fr::from(8),
            Fr::from(5),
            Fr::from(4),
            Fr::from(6),
            Fr::from(9),
            Fr::from(7),
            Fr::from(8),
            Fr::from(1),
        ];
        let p_evals: Vec<Fr> = c_evals.iter().map(|x| gamma - *x).collect();
        let f = super::compute_product_poly(&p_evals, 3).unwrap();
        let f_prime = super::compute_derivative_poly(&p_evals, &f.evaluations(), 3).unwrap();
        assert_eq!(f_prime.evaluations()[6], Fr::from(39672));
    }
}
