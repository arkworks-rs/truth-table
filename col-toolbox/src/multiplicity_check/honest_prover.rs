use std::collections::BTreeMap;

use super::{MultiplicityCheck, MultiplicityCheckProverInput};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{
        InputShapeError::{EmptyInput, InputLengthMismatch},
        SnarkError, SnarkResult,
    },
    pcs::PCS,
    piop::DeepClone,
    prover::{
        Prover,
        errors::{HonestProverError, ProverError},
    },
};
impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> DeepClone<F, MvPCS, UvPCS>
    for MultiplicityCheckProverInput<F, MvPCS, UvPCS>
where
    MvPCS: PCS<F, Poly = MLE<F>> + Clone,
    UvPCS: PCS<F, Poly = LDE<F>> + Clone,
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            fxs: self
                .fxs
                .iter()
                .map(|x| x.deep_clone(prover.clone()))
                .collect(),
            gxs: self
                .gxs
                .iter()
                .map(|x| x.deep_clone(prover.clone()))
                .collect(),
            mfxs: self
                .mfxs
                .iter()
                .map(|x| x.as_ref().map(|x| x.deep_clone(prover.clone())))
                .collect(),
            mgxs: self
                .mgxs
                .iter()
                .map(|x| x.as_ref().map(|x| x.deep_clone(prover.clone())))
                .collect(),
        }
    }
}

#[cfg(feature = "honest-prover")]
impl<F, MvPCS, UvPCS> MultiplicityCheck<F, MvPCS, UvPCS>
where
    F: ark_ff::PrimeField,
    MvPCS: ark_piop::pcs::PCS<F, Poly = ark_piop::arithmetic::mat_poly::mle::MLE<F>> + Clone,
    UvPCS: ark_piop::pcs::PCS<F, Poly = LDE<F>> + Clone,
{
    /// A helper function to check if the prover input is valid.
    /// Since the function is huge, we put it in a seperate file.
    // TODO: Although the performance does not matter for release, we should
    // parallelize this
    pub(crate) fn honest_prover_check_helper(
        input: &MultiplicityCheckProverInput<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        // Check that we do actually have some polynomial on the left hand side

        if input.fxs.is_empty() {
            return Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::WrongInputShape(EmptyInput),
            )));
        }
        // Check that we have as many multiplicity polynomials as we do polynomials on
        // the left side
        if input.fxs.len() != input.mfxs.len() {
            return Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::WrongInputShape(InputLengthMismatch {
                    expected: input.fxs.len(),
                    actual: input.mfxs.len(),
                }),
            )));
        }

        // Check that we do actually have some polynomial on the right hand side
        if input.gxs.is_empty() {
            return Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::WrongInputShape(EmptyInput),
            )));
        }
        // Check that we have as many multiplicity polynomials as we do polynomials on
        // the right side
        if input.gxs.len() != input.mgxs.len() {
            return Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::WrongInputShape(InputLengthMismatch {
                    expected: input.gxs.len(),
                    actual: input.mgxs.len(),
                }),
            )));
        }

        let mut bookkeeping_map: BTreeMap<F, F> = BTreeMap::new();
        for (fx, mfx) in input.fxs.iter().zip(&input.mfxs) {
            match (mfx, fx.activator_tracked_poly()) {
                (Some(mfx), Some(activator)) => {
                    let mfx_evals = mfx.evaluations();
                    let activator_evals = activator.evaluations();
                    for ((elem, mf_elem), activator_elem) in fx
                        .data_tracked_poly()
                        .evaluations()
                        .into_iter()
                        .zip(mfx_evals.iter())
                        .zip(activator_evals.iter())
                    {
                        if *activator_elem == F::one() {
                            *bookkeeping_map.entry(elem).or_insert(F::zero()) += *mf_elem;
                        }
                    }
                },
                (None, Some(activator)) => {
                    let activator_evals = activator.evaluations();
                    for (elem, activator_elem) in fx
                        .data_tracked_poly()
                        .evaluations()
                        .into_iter()
                        .zip(activator_evals.iter())
                    {
                        if *activator_elem == F::one() {
                            *bookkeeping_map.entry(elem).or_insert(F::zero()) += F::one();
                        }
                    }
                },
                (None, None) => {
                    for elem in fx.data_tracked_poly().evaluations() {
                        *bookkeeping_map.entry(elem).or_insert(F::zero()) += F::one();
                    }
                },
                (Some(mfx), None) => {
                    for (elem, mf_elem) in fx
                        .data_tracked_poly()
                        .evaluations()
                        .into_iter()
                        .zip(mfx.evaluations().iter())
                    {
                        *bookkeeping_map.entry(elem).or_insert(F::zero()) += *mf_elem;
                    }
                },
            }
        }

        for (gx, mgx) in input.gxs.iter().zip(&input.mgxs) {
            match (mgx, gx.activator_tracked_poly()) {
                (Some(mgx), Some(activator)) => {
                    let mgx_evals = mgx.evaluations();
                    let activator_evals = activator.evaluations();
                    for ((elem, mg_elem), activator_elem) in gx
                        .data_tracked_poly()
                        .evaluations()
                        .into_iter()
                        .zip(mgx_evals.iter())
                        .zip(activator_evals.iter())
                    {
                        if *activator_elem == F::one() {
                            *bookkeeping_map.entry(elem).or_insert(F::zero()) -= *mg_elem;
                        }
                    }
                },
                (None, Some(activator)) => {
                    let activator_evals = activator.evaluations();
                    for (elem, activator_elem) in gx
                        .data_tracked_poly()
                        .evaluations()
                        .into_iter()
                        .zip(activator_evals.iter())
                    {
                        if *activator_elem == F::one() {
                            *bookkeeping_map.entry(elem).or_insert(F::zero()) -= F::one();
                        }
                    }
                },
                (None, None) => {
                    for elem in gx.data_tracked_poly().evaluations() {
                        *bookkeeping_map.entry(elem).or_insert(F::zero()) -= F::one();
                    }
                },
                (Some(mgx), None) => {
                    for (elem, mg_elem) in gx
                        .data_tracked_poly()
                        .evaluations()
                        .into_iter()
                        .zip(mgx.evaluations().iter())
                    {
                        *bookkeeping_map.entry(elem).or_insert(F::zero()) -= *mg_elem;
                    }
                },
            }
        }

        for (_, count) in bookkeeping_map.iter() {
            if *count != F::zero() {
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }

        Ok(())
    }
}
