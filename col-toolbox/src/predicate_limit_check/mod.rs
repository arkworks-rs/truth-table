//! A PIOP to check if two columns are a permutation of each other.
// More precisely, this PIOP checks if the activated elements of one column
// are a permutation of the activated elements of another column.
#[cfg(test)]
mod test;
use crate::sign_check::{self, SignCheckPIOP, SignCheckProverInput, SignCheckVerifierInput};
use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::One;
use ark_ff::PrimeField;
use ark_ff::Zero;
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{
        ArgVerifier,
        structs::oracle::{Oracle, TrackedOracle},
    },
};
use ark_poly::Polynomial;
use datafusion::arrow::datatypes::{DataType, Field, FieldRef};
use derivative::Derivative;
use std::{marker::PhantomData, sync::Arc};
// Convinces the verifier that
pub struct PredicateLimitCheck<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct PredicateLimitCheckProverInput<B: SnarkBackend> {
    pub input_predicate: TrackedPoly<B>,
    pub output_predicate: TrackedPoly<B>,
    pub limit: usize,
}

impl<B: SnarkBackend> DeepClone<B> for PredicateLimitCheckProverInput<B> {
    fn deep_clone(&self, prover: ArgProver<B>) -> Self {
        Self {
            input_predicate: self.input_predicate.deep_clone(prover.clone()),
            output_predicate: self.output_predicate.deep_clone(prover),
            limit: self.limit,
        }
    }
}

pub struct PredicateLimitCheckVerifierInput<B: SnarkBackend> {
    pub input_predicate_oracle: TrackedOracle<B>,
    pub output_predicate_oracle: TrackedOracle<B>,
    pub limit: usize,
}

impl<B> PredicateLimitCheck<B>
where
    B: SnarkBackend,
{
    fn nth_non_zero_index_from_evals(evals: &[B::F], mut n: usize) -> Option<usize> {
        if n == 0 {
            return None;
        }

        for (idx, value) in evals.iter().enumerate() {
            if !value.is_zero() {
                n -= 1;
                if n == 0 {
                    return Some(idx);
                }
            }
        }
        None
    }

    fn nth_non_zero_index(predicate: &TrackedPoly<B>, n: usize) -> Option<usize> {
        let evals = predicate.evaluations();
        Self::nth_non_zero_index_from_evals(&evals, n)
    }

    fn limit_mask_poly(predicate: &TrackedPoly<B>, limit: usize) -> SnarkResult<(MLE<B::F>, B::F)> {
        let log_size = predicate.log_size();
        let total_len = 1usize << log_size;

        let cutoff_idx = if limit == 0 {
            None
        } else {
            Self::nth_non_zero_index(predicate, limit)
        };

        let mut mask = vec![B::F::zero(); total_len];
        if let Some(idx) = cutoff_idx {
            for slot in mask.iter_mut().take(idx + 1) {
                *slot = B::F::one();
            }
        }

        let mask_size = cutoff_idx.map(|idx| idx + 1).unwrap_or(0);
        let mask_size_f = B::F::from(mask_size as u64);

        Ok((MLE::from_evaluations_vec(log_size, mask), mask_size_f))
    }
}
impl<B: SnarkBackend> PIOP<B> for PredicateLimitCheck<B> {
    type ProverInput = PredicateLimitCheckProverInput<B>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = PredicateLimitCheckVerifierInput<B>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        let PredicateLimitCheckProverInput {
            input_predicate,
            output_predicate,
            limit,
        } = input;

        let input_evals = input_predicate.evaluations();
        let output_evals = output_predicate.evaluations();

        if input_evals.len() != output_evals.len() {
            use ark_piop::errors::SnarkError;
            use ark_piop::prover::errors::{HonestProverError, ProverError};
            return Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::FalseClaim,
            )));
        }

        for val in input_evals.iter().chain(output_evals.iter()) {
            if !val.is_zero() && *val != B::F::one() {
                use ark_piop::{
                    errors::SnarkError,
                    prover::errors::{HonestProverError, ProverError},
                };

                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }

        if limit > input_evals.len() {
            use ark_piop::{
                errors::SnarkError,
                prover::errors::{HonestProverError, ProverError},
            };

            return Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::FalseClaim,
            )));
        }

        let mut remaining = limit;
        let mut retained_non_zero = 0usize;

        for (input_val, output_val) in input_evals.iter().zip(output_evals.iter()) {
            if remaining > 0 {
                if input_val.is_zero() {
                    if !output_val.is_zero() {
                        use ark_piop::{
                            errors::SnarkError,
                            prover::errors::{HonestProverError, ProverError},
                        };

                        return Err(SnarkError::ProverError(ProverError::HonestProverError(
                            HonestProverError::FalseClaim,
                        )));
                    }
                } else {
                    if output_val != input_val {
                        use ark_piop::{
                            errors::SnarkError,
                            prover::errors::{HonestProverError, ProverError},
                        };

                        return Err(SnarkError::ProverError(ProverError::HonestProverError(
                            HonestProverError::FalseClaim,
                        )));
                    }
                    remaining -= 1;
                    retained_non_zero += 1;
                }
            } else if !output_val.is_zero() {
                use ark_piop::{
                    errors::SnarkError,
                    prover::errors::{HonestProverError, ProverError},
                };

                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }
        use ark_piop::prover::errors::ProverError;
        if remaining != 0 || retained_non_zero != limit {
            use ark_piop::{errors::SnarkError, prover::errors::HonestProverError};

            return Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::FalseClaim,
            )));
        }

        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<B>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let PredicateLimitCheckProverInput {
            input_predicate,
            output_predicate,
            limit,
        } = input;
        let _limit_f = B::F::from(limit as u64);
        let (limit_mask_poly, mask_size_f) = Self::limit_mask_poly(&input_predicate, limit)?;
        let mask_key_challenge = prover.get_and_append_challenge(b"predicate_limit_mask_key")?;
        let mask_key = format!("{:?}", mask_key_challenge.into_bigint());
        prover.add_miscellaneous_field_element(mask_key, mask_size_f)?;
        let limit_mask_tracked = prover.track_and_commit_mat_mv_poly(&limit_mask_poly)?;
        // TODO: Make this scaling automatic in the trackers. Currently the multicplicty
        // check and this check have manual scaling.
        // prover.add_mv_sumcheck_claim(output_predicate.id(), limit_f)?;
        let zero_tracked_poly = &output_predicate - &(&input_predicate * &limit_mask_tracked);
        prover.add_mv_zerocheck_claim(zero_tracked_poly.id())?;

        let index_mle = MLE::from_evaluations_vec(
            input_predicate.log_size(),
            (0..(1 << input_predicate.log_size()))
                .map(|i| B::F::from(i as u64) + B::F::one())
                .collect(),
        );
        let index_tracked_poly = prover.track_mat_mv_poly(index_mle);
        let diff_poly = index_tracked_poly.clone() - mask_size_f;
        let positive_activator_poly =
            (limit_mask_tracked.clone() * (-B::F::one())) + B::F::one();
        let none_positive_activator_poly = limit_mask_tracked;
        let predicate_field_ref: FieldRef =
            Arc::new(Field::new("predicate_limit_index", DataType::UInt64, false));
        let sign_check_prover_input = SignCheckProverInput {
            col: TrackedCol::new(
                diff_poly.clone(),
                Some(positive_activator_poly),
                Some(predicate_field_ref.clone()),
            ),
            sign: sign_check::Sign::Positive,
        };
        SignCheckPIOP::<B>::prove(prover, sign_check_prover_input)?;

        let sign_check_prover_input = SignCheckProverInput {
            col: TrackedCol::new(
                diff_poly,
                Some(none_positive_activator_poly),
                Some(predicate_field_ref),
            ),
            sign: sign_check::Sign::NonePositive,
        };
        SignCheckPIOP::<B>::prove(prover, sign_check_prover_input)?;

        Ok(())
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let PredicateLimitCheckVerifierInput {
            input_predicate_oracle,
            output_predicate_oracle,
            limit,
        } = input;
        let _limit_f = B::F::from(limit as u64);
        let mask_key_challenge = verifier.get_and_append_challenge(b"predicate_limit_mask_key")?;
        let mask_key = format!("{:?}", mask_key_challenge.into_bigint());
        let mask_size_f = verifier.miscellaneous_field_element(&mask_key)?;
        let limit_mask_id = verifier.peek_next_id();
        let limit_mask_tracked = verifier.track_mv_com_by_id(limit_mask_id)?;
        // TODO: Make this scaling automatic in the trackers. Currently the multicplicty
        // check and this check have manual scaling.
        // verifier.add_sumcheck_claim(output_predicate_oracle.id(), limit_f);
        let zero_tracked_poly =
            &output_predicate_oracle - &(&input_predicate_oracle * &limit_mask_tracked);
        verifier.add_zerocheck_claim(zero_tracked_poly.id());

        let predicate_log_size = input_predicate_oracle.log_size();
        let index_oracle = Oracle::new_multivariate(predicate_log_size, move |x| {
            Ok(
                SignCheckPIOP::<B>::sparse_range_poly_by_nv(predicate_log_size)?.evaluate(&x)
                    + B::F::one(),
            )
        });
        let index_tracked_oracle = verifier.track_oracle(index_oracle);
        let diff_oracle = index_tracked_oracle.clone() - mask_size_f;
        let positive_activator_oracle =
            (limit_mask_tracked.clone() * B::F::from(-1)) + B::F::one();
        let none_positive_activator_poly = limit_mask_tracked;
        let predicate_field_ref: FieldRef =
            Arc::new(Field::new("predicate_limit_index", DataType::UInt64, false));
        let sign_check_verifier_input = SignCheckVerifierInput {
            tracked_col_oracle: TrackedColOracle::new(
                diff_oracle.clone(),
                Some(positive_activator_oracle),
                Some(predicate_field_ref.clone()),
            ),
            sign: sign_check::Sign::Positive,
        };
        SignCheckPIOP::<B>::verify(verifier, sign_check_verifier_input)?;
        let sign_check_verifier_input = SignCheckVerifierInput {
            tracked_col_oracle: TrackedColOracle::new(
                diff_oracle,
                Some(none_positive_activator_poly),
                Some(predicate_field_ref),
            ),
            sign: sign_check::Sign::NonePositive,
        };
        SignCheckPIOP::<B>::verify(verifier, sign_check_verifier_input)?;

        Ok(())
    }
}
