use ark_piop::{SnarkBackend, arithmetic::mat_poly::mle::MLE, errors::SnarkResult};
use ark_poly::{
    DenseMVPolynomial,
    multivariate::{SparsePolynomial, SparseTerm, Term},
};

use super::SignCheckPIOP;

impl<B: SnarkBackend> SignCheckPIOP<B>
where
    B: SnarkBackend,
{
    pub(crate) fn sparse_range_poly_by_nv(
        nv: usize,
    ) -> SnarkResult<SparsePolynomial<B::F, SparseTerm>> {
        let terms = (0..nv)
            .map(|i| {
                (
                    B::F::from(u64::pow(2, i as u32)),
                    SparseTerm::new(vec![(i, 1)]),
                )
            })
            .collect::<Vec<_>>();
        Ok(SparsePolynomial::from_coefficients_vec(nv, terms))
    }

    pub(crate) fn dense_range_poly_by_nv(nv: usize) -> SnarkResult<MLE<B::F>> {
        let evals: Vec<B::F> = (0..2_usize.pow(nv as u32))
            .map(|x| B::F::from(x as u64))
            .collect();
        Ok(MLE::from_evaluations_vec(nv, evals))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_piop::{DefaultSnarkBackend, to_field_vec};
    use ark_poly::Polynomial;
    use ark_test_curves::bls12_381::Fr;

    #[test]
    fn test_range_poly() {
        let u8_sparse_poly =
            SignCheckPIOP::<DefaultSnarkBackend>::sparse_range_poly_by_nv(8).unwrap();

        let u8_dense_poly =
            SignCheckPIOP::<DefaultSnarkBackend>::dense_range_poly_by_nv(8).unwrap();
        assert_eq!(
            u8_sparse_poly.evaluate(&to_field_vec!([1, 1, 1, 0, 0, 0, 0, 0], Fr)),
            Fr::from(7)
        );

        assert_eq!(
            u8_dense_poly.evaluate(&to_field_vec!([1, 1, 1, 0, 0, 0, 0, 0], Fr)),
            Fr::from(7)
        );
        let u16_sparse_poly =
            SignCheckPIOP::<DefaultSnarkBackend>::sparse_range_poly_by_nv(16).unwrap();
        let u16_dense_poly =
            SignCheckPIOP::<DefaultSnarkBackend>::dense_range_poly_by_nv(16).unwrap();
        assert_eq!(
            u16_sparse_poly.evaluate(&to_field_vec!(
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
                Fr
            )),
            Fr::from(2048)
        );

        assert_eq!(
            u16_dense_poly.evaluate(&to_field_vec!(
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
                Fr
            )),
            Fr::from(2048)
        );
    }
}
