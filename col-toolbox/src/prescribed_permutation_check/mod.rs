#[cfg(test)]
mod test;

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
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

/// Builds a permutation polynomial representing a cyclic rotation of the
/// identity mapping.
///
/// # Arguments
/// * `log_size` - number of variables (domain size `2^log_size`)
/// * `shift` - rotation distance (normalized modulo domain size)
/// * `right` - when `true` rotates right, otherwise rotates left
pub fn shift_permutation_mle<F: PrimeField>(log_size: usize, shift: usize, right: bool) -> MLE<F> {
    let domain_size = 1usize << log_size;
    let normalized_shift = if domain_size == 0 {
        0
    } else {
        shift % domain_size
    };

    let mut evals: Vec<F> = (0..domain_size).map(|idx| F::from(idx as u64)).collect();

    if domain_size > 0 {
        if right {
            evals.rotate_right(normalized_shift);
        } else {
            evals.rotate_left(normalized_shift);
        }
    }

    MLE::from_evaluations_vec(log_size, evals)
}

/// Builds an oracle representing the cyclic permutation shift without
/// materialising the dense MLE. Everything that only depends on `log_size`,
/// `shift`, and `right` is pre-computed up front so that the closure only
/// performs point-dependent work.
pub fn shift_permutation_oracle<F: PrimeField>(
    log_size: usize,
    shift: usize,
    right: bool,
) -> Oracle<F> {
    // Domain size of the Boolean hypercube (2^log_size) and normalized shift.
    let domain_size = 1usize << log_size;
    let shift_mod = if domain_size == 0 {
        0
    } else {
        shift % domain_size
    };

    // Pre-compute the weights of the sparse range polynomial Σ x_i · 2^i.
    let mut weights = Vec::with_capacity(log_size);
    let mut coeff = F::one();
    for _ in 0..log_size {
        weights.push(coeff);
        coeff += coeff;
    }

    // Determine the additive offset and the threshold that marks wrap-around.
    let (delta_int, overflow_threshold) = if shift_mod == 0 {
        (0usize, None)
    } else if right {
        ((domain_size - shift_mod) % domain_size, Some(shift_mod))
    } else {
        (shift_mod, Some(domain_size - shift_mod))
    };

    // Convert the additive offset into the field once.
    let mut delta_f = F::zero();
    for (i, weight) in weights.iter().enumerate() {
        if ((delta_int >> i) & 1) == 1 {
            delta_f += *weight;
        }
    }

    // Field representation of 2^{log_size}, only needed when an overflow occurs.
    let domain_f = overflow_threshold.map(|_| {
        let mut value = F::one();
        for _ in 0..log_size {
            value += value;
        }
        value
    });

    // Cache the overflow threshold bits (least-significant bit first).
    let threshold_bits = overflow_threshold.map(|thr| {
        (0..log_size)
            .map(|i| ((thr >> i) & 1) == 1)
            .collect::<Vec<bool>>()
    });

    Oracle::new_multivariate(log_size, move |mut point: Vec<F>| {
        // 1. Normalise the input length to exactly `log_size`.
        if point.len() > log_size {
            point.truncate(log_size);
        } else if point.len() < log_size {
            point.resize(log_size, F::zero());
        }

        // 2. Evaluate the sparse range polynomial Σ x_i · 2^i using the cached weights.
        let range_value = point
            .iter()
            .zip(weights.iter())
            .fold(F::zero(), |acc, (bit, weight)| acc + (*bit * *weight));

        // 3. Apply the additive shift offset.
        let mut result = range_value + delta_f;

        // 4. Subtract 2^{log_size} if the rotation would overflow past the domain.
        if let (Some(bits), Some(domain)) = (threshold_bits.as_ref(), domain_f) {
            let overflow = evaluate_ge_bits(&point, bits);
            result -= domain * overflow;
        }

        Ok(result)
    })
}

/// Evaluates a polynomial that outputs 1 when `vars` encodes an integer that is
/// greater than or equal to the threshold defined by `threshold_bits` (LSB
/// first).
fn evaluate_ge_bits<F: PrimeField>(vars: &[F], threshold_bits: &[bool]) -> F {
    let one = F::one();
    let mut prefix_equal = F::one();
    let mut greater = F::zero();

    for i in (0..vars.len()).rev() {
        let bit_val = vars[i];
        if !threshold_bits[i] {
            greater += prefix_equal * bit_val;
            prefix_equal *= one - bit_val;
        } else {
            prefix_equal *= bit_val;
        }
    }

    greater + prefix_equal
}

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
    fn deep_clone(&self, prover: ArgProver<F, MvPCS, UvPCS>) -> Self {
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
        prover: &mut ArgProver<F, MvPCS, UvPCS>,
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
