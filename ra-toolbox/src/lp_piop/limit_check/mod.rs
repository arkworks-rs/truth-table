use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{SnarkError, SnarkResult},
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};
use datafusion::logical_expr::{FetchType, Limit, SkipType};
use derivative::Derivative;

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct LimitPIOPProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    pub limit: Limit,
    pub input_activator_tracked_poly: Option<TrackedPoly<F, MvPCS, UvPCS>>,
    pub output_activator_tracked_poly: Option<TrackedPoly<F, MvPCS, UvPCS>>,
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct LimitPIOPVerifierInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    pub limit: Limit,
    pub input_activator: Option<TrackedOracle<F, MvPCS, UvPCS>>,
    pub output_activator: Option<TrackedOracle<F, MvPCS, UvPCS>>,
}

pub struct LimitPIOP<F, MvPCS, UvPCS>(PhantomData<F>, PhantomData<MvPCS>, PhantomData<UvPCS>);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for LimitPIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    type ProverInput = LimitPIOPProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = LimitPIOPVerifierInput<F, MvPCS, UvPCS>;

    fn prove_inner(
        prover: &mut ArgProver<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let LimitPIOPProverInput {
            limit,
            input_activator_tracked_poly,
            output_activator_tracked_poly,
        } = input;

        let limit_mask_tracked_poly =
            if let Some(ref input_activator) = input_activator_tracked_poly {
                let mask_poly = Self::limit_mask_poly(&limit, input_activator)?;
                Some(prover.track_mat_mv_poly(mask_poly))
            } else {
                None
            };

        if let (Some(input_activator), Some(output_activator), Some(limit_mask)) = (
            input_activator_tracked_poly.as_ref(),
            output_activator_tracked_poly.as_ref(),
            limit_mask_tracked_poly.as_ref(),
        ) {
            let masked_input = input_activator * limit_mask;
            let zero_poly = output_activator - &masked_input;
            prover.add_mv_zerocheck_claim(zero_poly.id())?;
        }

        // match (
        //     input.input_activator_tracked_poly,
        //     input.output_activator_tracked_poly,
        // ) {
        //     (Some(input_activator), Some(output_activator)) => {

        //     }
        //     _ => {}

        // }
        Ok(())
    }

    fn verify_inner(
        _verifier: &mut ArgVerifier<F, MvPCS, UvPCS>,
        _input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        Ok(())
    }
}

impl<F, MvPCS, UvPCS> LimitPIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    fn limit_mask_poly(
        limit: &Limit,
        input_activator: &TrackedPoly<F, MvPCS, UvPCS>,
    ) -> SnarkResult<MLE<F>> {
        let (skip_literal, skip_was_none, fetch_literal) = Self::limit_window(limit)?;
        let activator_evals = input_activator.evaluations();
        let total_len = activator_evals.len();
        let log_size = input_activator.log_size();

        let start_idx = if skip_was_none {
            0
        } else {
            let nth = skip_literal.saturating_add(1);
            Self::nth_active_index(&activator_evals, nth).unwrap_or(total_len)
        };

        let end_idx = match fetch_literal {
            None => total_len,
            Some(fetch) => {
                let nth = skip_literal.saturating_add(fetch).saturating_add(1);
                Self::nth_active_index(&activator_evals, nth).unwrap_or(total_len)
            }
        };

        let start_idx = start_idx.min(total_len);
        let end_idx = end_idx.min(total_len);
        let mut mask_values = vec![F::zero(); total_len];
        if start_idx < end_idx {
            mask_values[start_idx..end_idx].clone_from_slice(&activator_evals[start_idx..end_idx]);
        }

        Ok(MLE::from_evaluations_vec(log_size, mask_values))
    }

    fn limit_window(limit: &Limit) -> SnarkResult<(usize, bool, Option<usize>)> {
        let skip_was_none = limit.skip.is_none();
        let skip_literal = match limit.get_skip_type().map_err(|_| SnarkError::DummyError)? {
            SkipType::Literal(value) => value,
            SkipType::UnsupportedExpr => return Err(SnarkError::DummyError),
        };

        let fetch_literal = match limit.get_fetch_type().map_err(|_| SnarkError::DummyError)? {
            FetchType::Literal(value) => value,
            FetchType::UnsupportedExpr => return Err(SnarkError::DummyError),
        };

        Ok((skip_literal, skip_was_none, fetch_literal))
    }

    fn nth_active_index(evals: &[F], target: usize) -> Option<usize> {
        if target == 0 {
            return Some(0);
        }

        let mut remaining = target;
        for (idx, value) in evals.iter().enumerate() {
            if !value.is_zero() {
                remaining -= 1;
                if remaining == 0 {
                    return Some(idx);
                }
            }
        }
        None
    }
}

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for LimitPIOPProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    fn deep_clone(&self, _new_prover: ArgProver<F, MvPCS, UvPCS>) -> Self {
        Self {
            limit: self.limit.clone(),
            input_activator_tracked_poly: self
                .input_activator_tracked_poly
                .as_ref()
                .map(|poly| poly.deep_clone(_new_prover.clone())),
            output_activator_tracked_poly: self
                .output_activator_tracked_poly
                .as_ref()
                .map(|poly| poly.deep_clone(_new_prover.clone())),
        }
    }
}
