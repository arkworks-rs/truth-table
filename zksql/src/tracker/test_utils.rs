use arithmetic::ark_ff::{Field, PrimeField};
use arithmetic::ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use crypto::pcs::PolynomialCommitmentScheme;
use kit::ark_std::test_rng;
use kit::rayon::vec;

use crate::{
    tracker::prelude::{PolyIOPErrors, ProverTrackerRef, VerifierTrackerRef},
};

pub fn test_prelude<F: Field + PrimeField, PCS: PolynomialCommitmentScheme<F>>(
    nv: usize,
) -> Result<(ProverTrackerRef<F, PCS>, VerifierTrackerRef<F, PCS>), PolyIOPErrors> {
    let mut rng = test_rng();
    let srs = PCS::gen_srs_for_testing(&mut rng, nv)?;
    let (p_param, v_param) = PCS::trim(&srs, None, Some(nv))?;
    let prover_tracker: ProverTrackerRef<F, PCS> = ProverTrackerRef::new_from_pcs_params(p_param);
    let verifier_tracker: VerifierTrackerRef<F, PCS> =
        VerifierTrackerRef::new_from_pcs_params(v_param);
    Ok((prover_tracker, verifier_tracker))
}

