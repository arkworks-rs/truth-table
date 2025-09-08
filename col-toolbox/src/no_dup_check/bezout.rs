use ark_ff::{FftField, Zero};
use ark_piop::arithmetic::mat_poly::lde::LDE;
use ark_poly::{DenseUVPolynomial, Polynomial, univariate::DenseOrSparsePolynomial};

// -----------------------------------------------------------------------------
// A small helper trait to unify parallel + / - / * on LDE.
// You can also just call `poly_add_par`, etc. directly.
// -----------------------------------------------------------------------------
// trait PolyParOps<F: FftField> {
//     fn par_add(&self, rhs: &Self) -> Self;
//     fn par_sub(&self, rhs: &Self) -> Self;
//     fn par_mul(&self, rhs: &Self) -> Self;
// }

// impl<F: FftField> PolyParOps<F> for LDE<F> {
//     fn par_add(&self, rhs: &Self) -> Self {
//         poly_add_par(self, rhs)
//     }
//     fn par_sub(&self, rhs: &Self) -> Self {
//         poly_sub_par(self, rhs)
//     }
//     fn par_mul(&self, rhs: &Self) -> Self {
//         poly_mul_par(self, rhs)
//     }
// }

// -----------------------------------------------------------------------------
// 4) A "classical" extended GCD for small-degree polynomials, using parallel
//    polynomial ops. (You could do it purely sequentially if you prefer.)
// -----------------------------------------------------------------------------
fn classical_xgcd_polynomials_par<F: FftField>(a: &LDE<F>, b: &LDE<F>) -> (LDE<F>, LDE<F>) {
    // Base case
    if b.is_zero() {
        let gcd_val = a.coeffs[0];
        let gcd_inv = gcd_val.inverse().unwrap();
        return (LDE::from_coefficients_vec(vec![gcd_inv]), LDE::zero());
    }

    let a_dsp = DenseOrSparsePolynomial::from(a);
    let b_dsp = DenseOrSparsePolynomial::from(b);
    let (q, r) = a_dsp.divide_with_q_and_r(&b_dsp).unwrap();

    let (f_sub, g_sub) = classical_xgcd_polynomials_par(b, &r);

    // Combine
    let qg = q * (&g_sub);
    let next_g = f_sub - (&qg);
    (g_sub, next_g)
}

// -----------------------------------------------------------------------------
// 5) 2×2 "matrix" of polynomials, with parallel multiply
// -----------------------------------------------------------------------------
#[derive(Clone, Debug)]
struct PolyMatrix2x2<F: FftField> {
    a11: LDE<F>,
    a12: LDE<F>,
    a21: LDE<F>,
    a22: LDE<F>,
}

impl<F: FftField> PolyMatrix2x2<F> {
    fn identity() -> Self {
        Self {
            a11: LDE::from_coefficients_vec(vec![F::one()]),
            a12: LDE::zero(),
            a21: LDE::zero(),
            a22: LDE::from_coefficients_vec(vec![F::one()]),
        }
    }

    // Multiply this 2x2 matrix by another 2x2, all in parallel
    fn par_multiply(&self, rhs: &Self) -> Self {
        // We'll compute (a11, a12) in one `rayon::join`, and (a21, a22) in parallel.
        // That spawns two parallel tasks, *each* possibly doing more parallel steps
        // in polynomial multiplication.
        let (res_top, res_bot) = rayon::join(
            // top row: (a11, a12)
            || {
                let a11 = (&self.a11) * (&rhs.a11) + (&self.a12 * (&rhs.a21));
                let a12 = (&self.a11) * (&rhs.a12) + (&self.a12 * (&rhs.a22));
                (a11, a12)
            },
            // bottom row: (a21, a22)
            || {
                let a21 = (&self.a21) * (&rhs.a11) + (&self.a22 * (&rhs.a21));
                let a22 = (&self.a21) * (&rhs.a12) + (&self.a22 * (&rhs.a22));
                (a21, a22)
            },
        );

        let (a11, a12) = res_top;
        let (a21, a22) = res_bot;
        Self { a11, a12, a21, a22 }
    }

    // Apply to a vector (f, g) in parallel => (a11*f + a12*g, a21*f + a22*g)
    fn par_apply(&self, f: &LDE<F>, g: &LDE<F>) -> (LDE<F>, LDE<F>) {
        // Each output can be computed in parallel
        let (out1, out2) = rayon::join(
            || (&self.a11) * (f) + (&self.a12 * (g)),
            || (&self.a21) * (f) + (&self.a22 * (g)),
        );
        (out1, out2)
    }
}

// -----------------------------------------------------------------------------
// 6) partial_gcd_step: repeated Euclidean divisions until deg(r1) ~ half of
//    deg(a), collecting transformations in a 2x2 matrix, but with parallel
//    polynomial ops.
// -----------------------------------------------------------------------------
fn partial_gcd_step_par<F: FftField>(a: &LDE<F>, b: &LDE<F>) -> (PolyMatrix2x2<F>, LDE<F>, LDE<F>) {
    let mut r0 = a.clone();
    let mut r1 = b.clone();

    let mut m = PolyMatrix2x2::identity();

    let deg_a = r0.degree();
    let half_deg = deg_a / 2;

    while !r1.is_zero() && r1.degree() > half_deg {
        let r0_dsp = DenseOrSparsePolynomial::from(&r0);
        let r1_dsp = DenseOrSparsePolynomial::from(&r1);
        let (q, remainder) = r0_dsp.divide_with_q_and_r(&r1_dsp).unwrap();

        // Matrix for step: (r0, r1) -> (r1, r0 - q*r1)
        //   [0,   1]
        //   [1,  -q]
        let mut minus_q = q.clone();
        minus_q.coeffs.iter_mut().for_each(|c| *c = -(*c));

        let step_mat = PolyMatrix2x2 {
            a11: LDE::zero(),
            a12: LDE::from_coefficients_vec(vec![F::one()]),
            a21: LDE::from_coefficients_vec(vec![F::one()]),
            a22: minus_q,
        };

        // Parallel matrix multiplication
        m = m.par_multiply(&step_mat);

        r0 = r1;
        r1 = remainder;
    }

    (m, r0, r1)
}

// -----------------------------------------------------------------------------
// 7) The half-gcd recursion itself, parallel version
// -----------------------------------------------------------------------------
fn half_gcd_polynomials_par<F: FftField>(a: &LDE<F>, b: &LDE<F>) -> (LDE<F>, LDE<F>) {
    // Base case
    if b.is_zero() {
        let gcd_val = a.coeffs[0];
        let gcd_inv = gcd_val.inverse().unwrap();
        return (LDE::from_coefficients_vec(vec![gcd_inv]), LDE::zero());
    }

    // Ensure deg(a) >= deg(b)
    if b.degree() > a.degree() {
        let (f_sub, g_sub) = half_gcd_polynomials_par(b, a);
        // Swap result
        return (g_sub, f_sub);
    }

    // Fallback to classical if degrees are small
    let threshold = 16; // tune
    if a.degree() <= threshold || b.degree() <= threshold {
        return classical_xgcd_polynomials_par(a, b);
    }

    // partial step
    let (m, r0, r1) = partial_gcd_step_par(a, b);

    // recurse on smaller pair
    let (f_sub, g_sub) = half_gcd_polynomials_par(&r0, &r1);

    // "lift" back up
    let (f_res, g_res) = m.par_apply(&f_sub, &g_sub);
    (f_res, g_res)
}

// -----------------------------------------------------------------------------
// 8) Finally, `bez_polys` with the *same signature* as requested, but
//    internally uses our parallel half-GCD approach.
// -----------------------------------------------------------------------------
pub fn bez_polys<F: FftField>(a: &LDE<F>, b: &LDE<F>) -> (LDE<F>, LDE<F>) {
    half_gcd_polynomials_par(a, b)
}
#[cfg(test)]
mod test {
    use ark_ff::Field;
    use ark_piop::arithmetic::mat_poly::lde::LDE;
    use ark_poly::DenseUVPolynomial;
    use ark_test_curves::bls12_381::Fr;

    #[test]
    fn works() {
        assert!(helper_coprime(
            vec![Fr::from(-6), Fr::from(1)],
            vec![Fr::from(-15), Fr::from(1)],
        ));

        assert!(helper_coprime(
            vec![Fr::from(2), Fr::from(-3), Fr::from(1)],
            vec![Fr::from(-48), Fr::from(35), Fr::from(-12), Fr::from(1)],
        ));

        assert!(!helper_coprime(
            vec![Fr::from(-3), Fr::from(1)],
            vec![Fr::from(-3), Fr::from(1)],
        ));
        assert!(!helper_coprime(
            vec![Fr::from(-3), Fr::from(1)],
            vec![Fr::from(12), Fr::from(-7), Fr::from(1)],
        ));
        assert!(helper_coprime(
            vec![
                Fr::from(123456789),
                Fr::from(-987654321),
                Fr::from(135792468),
                Fr::from(246813579),
                Fr::from(999999937)
            ], // 999999937x^4 + 246813579x^3 + 135792468x^2 - 987654321x + 123456789
            vec![
                Fr::from(314159265),
                Fr::from(-271828182),
                Fr::from(161803398),
                Fr::from(-141421356),
                Fr::from(173205080),
                Fr::from(223606797)
            ] // 223606797x^5 + 173205080x^4 - 141421356x^3 + 161803398x^2 - 271828182x + 314159265
        ));
    }

    fn helper_coprime(a_coeffs: Vec<Fr>, b_coeffs: Vec<Fr>) -> bool {
        let c = helper(a_coeffs, b_coeffs);
        c.coeffs == vec![Fr::ONE]
    }

    fn helper(a_coeffs: Vec<Fr>, b_coeffs: Vec<Fr>) -> LDE<Fr> {
        let a = LDE::from_coefficients_vec(a_coeffs);
        let b = LDE::from_coefficients_vec(b_coeffs);
        let (f, g) = super::bez_polys(&a, &b);
        (f * a) + (g * b)
    }
}
