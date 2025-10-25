#[cfg(test)]
mod test;

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{Prover, structs::polynomial::TrackedPoly},
    verifier::{
        Verifier,
        structs::oracle::{Oracle, TrackedOracle},
    },
};
use ark_poly::Polynomial;
use derivative::Derivative;
use std::marker::PhantomData;

use crate::{
    perm_check::{PermPIOP, PermPIOPProverInput, PermPIOPVerifierInput},
    sign_check::SignCheckPIOP,
};

// Convinces the verifier that
pub struct PrescribedPermutationPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct PrescribedPermutationPIOPProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub left_tracked_poly: TrackedPoly<F, MvPCS, UvPCS>,
    pub right_tracked_poly: TrackedPoly<F, MvPCS, UvPCS>,
    pub permutation_tracked_poly: TrackedPoly<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for PrescribedPermutationPIOPProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            left_tracked_poly: self.left_tracked_poly.deep_clone(prover.clone()),
            right_tracked_poly: self.right_tracked_poly.deep_clone(prover.clone()),
            permutation_tracked_poly: self.permutation_tracked_poly.deep_clone(prover.clone()),
        }
    }
}

pub struct PrescribedPermutationPIOPVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub left_tracked_oracle: TrackedOracle<F, MvPCS, UvPCS>,
    pub right_tracked_oracle: TrackedOracle<F, MvPCS, UvPCS>,
    pub permutation_tracked_oracle: TrackedOracle<F, MvPCS, UvPCS>,
}
impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for PrescribedPermutationPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = PrescribedPermutationPIOPProverInput<F, MvPCS, UvPCS>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = PrescribedPermutationPIOPVerifierInput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        use ark_piop::{
            errors::SnarkError,
            prover::errors::{HonestProverError, ProverError},
        };

        let left_vals = input.left_tracked_poly.evaluations();
        let right_vals = input.right_tracked_poly.evaluations();
        let permutation = input.permutation_tracked_poly.evaluations();

        let false_claim = || {
            Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::FalseClaim,
            )))
        };

        let len = left_vals.len();
        if right_vals.len() != len || permutation.len() != len || len == 0 {
            return false_claim();
        }

        let mut seen = vec![false; len];

        for (value, destination) in left_vals.iter().zip(permutation.into_iter()) {
            let bigint = destination.into_bigint();
            if bigint.as_ref().iter().skip(1).any(|&limb| limb != 0) {
                return false_claim();
            }
            let dest_idx = bigint.as_ref()[0] as usize;
            if dest_idx >= len {
                return false_claim();
            }
            if seen[dest_idx] {
                return false_claim();
            }
            if right_vals[dest_idx] != *value {
                return false_claim();
            }
            seen[dest_idx] = true;
        }

        if seen.iter().any(|assigned| !assigned) {
            return false_claim();
        }

        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let index_mle = MLE::from_evaluations_vec(
            input.left_tracked_poly.log_size(),
            (0..(1 << input.left_tracked_poly.log_size()))
                .map(|i| F::from(i as u64))
                .collect(),
        );
        let index_tracked_poly = prover.track_mat_mv_poly(index_mle);
        let folding_challenge = prover.get_and_append_challenge(b"folding_challenge")?;
        let folded_left =
            &input.left_tracked_poly + &(&input.permutation_tracked_poly * folding_challenge);
        let folded_right = &input.right_tracked_poly + &(&index_tracked_poly * folding_challenge);
        let permutation_check_prover_input = PermPIOPProverInput {
            left_col: TrackedCol::new(folded_left, None, None),
            right_col: TrackedCol::new(folded_right, None, None),
        };
        PermPIOP::prove(prover, permutation_check_prover_input)?;
        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let log_size = input.left_tracked_oracle.log_size();
        let index_oracle = Oracle::new_multivariate(log_size, move |x| {
            let value =
                SignCheckPIOP::<F, MvPCS, UvPCS>::sparse_range_poly_by_nv(log_size)?.evaluate(&x);
            Ok(value)
        });
        let index_tracked_oracle = verifier.track_oracle(index_oracle);
        let folding_challenge = verifier.get_and_append_challenge(b"folding_challenge")?;
        let folded_left =
            &input.left_tracked_oracle + &(&input.permutation_tracked_oracle * folding_challenge);
        let folded_right =
            &input.right_tracked_oracle + &(&index_tracked_oracle * folding_challenge);
        let permutation_check_verifier_input = PermPIOPVerifierInput {
            left_tracked_col_oracle: TrackedColOracle::new(folded_left, None, None),
            right_tracked_col_oracle: TrackedColOracle::new(folded_right, None, None),
        };
        PermPIOP::verify(verifier, permutation_check_verifier_input)?;
        Ok(())
    }
}
