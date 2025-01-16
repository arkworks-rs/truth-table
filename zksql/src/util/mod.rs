use arithmetic::ark_ff::{Field, PrimeField};
use arithmetic::ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use crypto::pcs::PolynomialCommitmentScheme;
use kit::ark_std::test_rng;
use kit::rayon::vec;

use crate::{
    tracker::prelude::{PolyIOPErrors, ProverTrackerRef, VerifierTrackerRef},
};

/// this function helps with slice iterator creation that optionally use
/// `par_iter()` when feature flag `parallel` is on.
///
/// # Usage
/// let v = [1, 2, 3, 4, 5];
/// let sum = parallelizable_slice_iter(&v).sum();
///
/// // the above code is a shorthand for (thus equivalent to)
/// #[cfg(feature = "parallel")]
/// let sum = v.par_iter().sum();
/// #[cfg(not(feature = "parallel"))]
/// let sum = v.iter().sum();
#[cfg(feature = "parallel")]
pub fn parallelizable_slice_iter<T: Sync>(data: &[T]) -> kit::rayon::slice::Iter<T> {
    use kit::rayon;
    use rayon::iter::IntoParallelIterator;
    data.into_par_iter()
}

#[cfg(not(feature = "parallel"))]
pub fn parallelizable_slice_iter<T>(data: &[T]) -> core::slice::Iter<T> {
    data.iter()
}

pub fn test_prelude<F: Field + PrimeField, PCS: PolynomialCommitmentScheme<F>>(
    nv: usize,
) -> Result<(ProverTrackerRef<F, PCS>, VerifierTrackerRef<F, PCS>), PolyIOPErrors> {
    let mut rng = test_rng();
    let srs = PCS::gen_srs_for_testing(&mut rng, nv)?;
    let (p_param, v_param) = PCS::trim(&srs, None, Some(10))?;
    let prover_tracker: ProverTrackerRef<F, PCS> = ProverTrackerRef::new_from_pcs_params(p_param);
    let verifier_tracker: VerifierTrackerRef<F, PCS> =
        VerifierTrackerRef::new_from_pcs_params(v_param);
    Ok((prover_tracker, verifier_tracker))
}


