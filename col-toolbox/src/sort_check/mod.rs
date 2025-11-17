//! A PIOP to check if two columns are a permutation of each other.
// More precisely, this PIOP checks if the activated elements of one column
// are a permutation of the activated elements of another column.
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
    verifier::{Verifier, structs::oracle::TrackedOracle},
};
use derivative::Derivative;
use std::marker::PhantomData;

use crate::{
    prescribed_permutation_check::{
        PrescribedPermutationPIOP, PrescribedPermutationPIOPProverInput,
        PrescribedPermutationPIOPVerifierInput, shift_permutation_mle, shift_permutation_oracle,
    },
    sign_check::{SignCheckPIOP, SignCheckProverInput, SignCheckVerifierInput},
};
// Convinces the verifier that
pub struct SortCheck<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct SortCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub tracked_col: TrackedCol<F, MvPCS, UvPCS>,
    pub ascending: bool,
    pub strict: bool,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for SortCheckProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: ArgProver<F, MvPCS, UvPCS>) -> Self {
        Self {
            tracked_col: self.tracked_col.deep_clone(prover.clone()),
            ascending: self.ascending,
            strict: self.strict,
        }
    }
}

pub struct SortCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    pub ascending: bool,
    pub strict: bool,
}
impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for SortCheck<F, MvPCS, UvPCS>
{
    type ProverInput = SortCheckProverInput<F, MvPCS, UvPCS>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = SortCheckVerifierInput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        let mut iter = input.tracked_col.effective_iter().into_iter();
        let Some(mut prev) = iter.next() else {
            return Ok(());
        };

        for current in iter {
            use std::cmp::Ordering;

            let ordering = current.cmp(&prev);
            let valid = match (input.ascending, input.strict) {
                (true, true) => ordering == Ordering::Greater,
                (true, false) => ordering != Ordering::Less,
                (false, true) => ordering == Ordering::Less,
                (false, false) => ordering != Ordering::Greater,
            };
            use ark_piop::prover::errors::HonestProverError::FalseClaim;
            use ark_piop::prover::errors::ProverError::HonestProverError;
            if !valid {
                use ark_piop::errors::SnarkError::ProverError;
                return Err(ProverError(HonestProverError(FalseClaim)));
            }

            prev = current;
        }
        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let new_col =
            if let Some(activator_tracked_poly) = input.tracked_col.activator_tracked_poly() {
                let new_mle: MLE<F> = Self::p_prep(&input.tracked_col)?;
                let new_tr_p: TrackedPoly<F, MvPCS, UvPCS> =
                    prover.track_and_commit_mat_mv_poly(&new_mle)?;
                let new_wit_tr_p: TrackedPoly<F, MvPCS, UvPCS> =
                    &(&new_tr_p - &input.tracked_col.data_tracked_poly()) * &activator_tracked_poly;
                prover.add_mv_zerocheck_claim(new_wit_tr_p.id())?;
                TrackedCol::new(
                    new_tr_p,
                    Some(activator_tracked_poly.clone()),
                    input.tracked_col.field_ref().clone(),
                )
            } else {
                input.tracked_col.clone()
            };

        let shifted_mle = Self::circular_shift_col(&new_col);
        let shifted_data_tracked_poly = prover.track_and_commit_mat_mv_poly(&shifted_mle)?;
        let shifted_col = TrackedCol::new(
            shifted_data_tracked_poly.clone(),
            new_col.activator_tracked_poly(),
            new_col.field_ref(),
        );

        let shift_permutation_mle =
            shift_permutation_mle(new_col.data_tracked_poly().log_size(), 1, true);
        let shift_permutation_tracked_poly = prover.track_mat_mv_poly(shift_permutation_mle);
        let prescribed_permutation_check_prover_input = PrescribedPermutationPIOPProverInput {
            left_tracked_poly: new_col.data_tracked_poly().clone(),
            right_tracked_poly: shifted_data_tracked_poly.clone(),
            permutation_tracked_poly: shift_permutation_tracked_poly,
        };
        PrescribedPermutationPIOP::<F, MvPCS, UvPCS>::prove(
            prover,
            prescribed_permutation_check_prover_input,
        )?;

        let truncated_activator_mle = Self::truncate_activator_mle(prover, &new_col);
        let truncated_activator_tracked_poly =
            prover.track_and_commit_mat_mv_poly(&truncated_activator_mle)?;

        // TODO: Do the predicate limit check prover
        // let (limit, new_col_activator) = match new_col.activator_tracked_poly() {
        //     Some(actv) => (
        //         actv.evaluations().iter().filter(|&&v| !v.is_zero()).count() -
        // 1_usize,         actv,
        //     ),
        //     None => (
        //         (1usize << new_col.data_tracked_poly().log_size()) - 1,
        //         prover.track_mat_mv_cnst_poly(input.tracked_col.log_size(),
        // F::one()),     ),
        // };
        // let predicate_limit_check_piop_prover_input = PredicateLimitCheckProverInput
        // {     input_predicate: new_col_activator.clone(),
        //     output_predicate: truncated_activator_tracked_poly.clone(),
        //     limit,
        // };
        // PredicateLimitCheck::<F, MvPCS, UvPCS>::prove(
        //     prover,
        //     predicate_limit_check_piop_prover_input,
        // )?;

        let diff_col = TrackedCol::new(
            &shifted_col.data_tracked_poly() - &new_col.data_tracked_poly(),
            Some(truncated_activator_tracked_poly),
            new_col.field_ref().clone(),
        );
        // Remember to change the activator and do a contiguous check
        let sign_check_prover_input = match (input.ascending, input.strict) {
            (true, true) => SignCheckProverInput {
                col: diff_col,
                sign: crate::sign_check::Sign::Positive,
            },
            (true, false) => SignCheckProverInput {
                col: diff_col,
                sign: crate::sign_check::Sign::NoneNegative,
            },
            (false, true) => SignCheckProverInput {
                col: diff_col,
                sign: crate::sign_check::Sign::Negative,
            },
            (false, false) => SignCheckProverInput {
                col: diff_col,
                sign: crate::sign_check::Sign::NonePositive,
            },
        };
        SignCheckPIOP::<F, MvPCS, UvPCS>::prove(prover, sign_check_prover_input)?;
        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let new_col = if let Some(activator_tracked_oracle) =
            input.tracked_col_oracle.activator_tracked_oracle()
        {
            let new_tr_id = verifier.peek_next_id();
            let new_tr_p = verifier.track_mv_com_by_id(new_tr_id)?;
            let new_wit_tr_p: TrackedOracle<F, MvPCS, UvPCS> = &(&new_tr_p
                - &input.tracked_col_oracle.data_tracked_oracle())
                * &activator_tracked_oracle;
            verifier.add_zerocheck_claim(new_wit_tr_p.id());
            TrackedColOracle::new(
                new_tr_p,
                Some(activator_tracked_oracle.clone()),
                input.tracked_col_oracle.field_ref().clone(),
            )
        } else {
            input.tracked_col_oracle.clone()
        };
        let shifted_data_id = verifier.peek_next_id();
        let shifted_data_tracked_oracle = verifier.track_mv_com_by_id(shifted_data_id)?;
        let shifted_col = TrackedColOracle::new(
            shifted_data_tracked_oracle.clone(),
            new_col.activator_tracked_oracle(),
            new_col.field_ref(),
        );

        let shift_permutation_oracle =
            shift_permutation_oracle::<F>(new_col.data_tracked_oracle().log_size(), 1, true);
        let shift_permutation_tracked_oracle = verifier.track_oracle(shift_permutation_oracle);
        let prescribed_permutation_check_verifier_input = PrescribedPermutationPIOPVerifierInput {
            left_tracked_oracle: new_col.data_tracked_oracle().clone(),
            right_tracked_oracle: shifted_data_tracked_oracle.clone(),
            permutation_tracked_oracle: shift_permutation_tracked_oracle,
        };
        PrescribedPermutationPIOP::<F, MvPCS, UvPCS>::verify(
            verifier,
            prescribed_permutation_check_verifier_input,
        )?;

        let truncated_activator_id = verifier.peek_next_id();
        let truncated_activator_tracked_poly =
            verifier.track_mv_com_by_id(truncated_activator_id)?;

        // TODO: Do the predicate limit check verification

        let diff_col_oracle = TrackedColOracle::new(
            &shifted_col.data_tracked_oracle() - &new_col.data_tracked_oracle(),
            Some(truncated_activator_tracked_poly),
            new_col.field_ref().clone(),
        );
        // Rememeber to change the activator and do a contigous check

        let sign_check_verifier_input = match (input.ascending, input.strict) {
            (true, true) => SignCheckVerifierInput {
                tracked_col_oracle: diff_col_oracle,
                sign: crate::sign_check::Sign::Positive,
            },
            (true, false) => SignCheckVerifierInput {
                tracked_col_oracle: diff_col_oracle,
                sign: crate::sign_check::Sign::NoneNegative,
            },
            (false, true) => SignCheckVerifierInput {
                tracked_col_oracle: diff_col_oracle,
                sign: crate::sign_check::Sign::Negative,
            },
            (false, false) => SignCheckVerifierInput {
                tracked_col_oracle: diff_col_oracle,
                sign: crate::sign_check::Sign::NonePositive,
            },
        };
        SignCheckPIOP::<F, MvPCS, UvPCS>::verify(verifier, sign_check_verifier_input)?;
        Ok(())
    }
}

impl<F, MvPCS, UvPCS> SortCheck<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn p_prep(in_col: &TrackedCol<F, MvPCS, UvPCS>) -> SnarkResult<MLE<F>> {
        let activator_tracked_poly = in_col.activator_tracked_poly().unwrap();
        let mut data_evals = in_col.data_tracked_poly().evaluations();
        let activator_evals = activator_tracked_poly.evaluations();
        debug_assert_eq!(data_evals.len(), activator_evals.len());
        let mut next_active_value: Option<F> = None;
        let mut trailing_inactive_count: usize = 0;
        for idx in (0..data_evals.len()).rev() {
            let activator = activator_evals[idx];
            if activator.is_zero() {
                if let Some(next_val) = next_active_value {
                    data_evals[idx] = next_val;
                } else {
                    trailing_inactive_count += 1;
                }
            } else {
                next_active_value = Some(data_evals[idx]);
                trailing_inactive_count = 0;
            }
        }
        if trailing_inactive_count > 0 {
            let base = if let Some(active_val) = next_active_value {
                active_val
            } else if let Some(first_active_idx) =
                activator_evals.iter().position(|eval| eval.is_one())
            {
                data_evals[first_active_idx]
            } else {
                F::zero()
            };
            let mut current = base;
            for idx in (data_evals.len() - trailing_inactive_count)..data_evals.len() {
                current += F::one();
                data_evals[idx] = current;
            }
        }
        Ok(MLE::from_evaluations_vec(
            in_col.data_tracked_poly().log_size(),
            data_evals,
        ))
    }
    fn truncate_activator_mle(
        _prover: &mut ArgProver<F, MvPCS, UvPCS>,
        col: &TrackedCol<F, MvPCS, UvPCS>,
    ) -> MLE<F> {
        if let Some(activator) = col.activator_tracked_poly() {
            let log_size = activator.log_size();
            let mut activator_evals = activator.evaluations();
            if let Some(pos) = activator_evals.iter().rposition(|eval| eval.is_one()) {
                activator_evals[pos] = F::zero();
            } else if let Some(last) = activator_evals.last_mut() {
                *last = F::zero();
            }
            MLE::from_evaluations_vec(log_size, activator_evals)
        } else {
            let log_size = col.data_tracked_poly().log_size();
            let mut activator_evals = vec![F::one(); 1 << log_size];
            if let Some(last) = activator_evals.last_mut() {
                *last = F::zero();
            }
            MLE::from_evaluations_vec(log_size, activator_evals)
        }
    }

    pub fn circular_shift_col(col: &TrackedCol<F, MvPCS, UvPCS>) -> MLE<F> {
        let data_tracked_poly = col.data_tracked_poly();
        let log_size = data_tracked_poly.log_size();
        let mut shifted_evals = data_tracked_poly.evaluations();
        shifted_evals.rotate_left(1);
        MLE::from_evaluations_vec(log_size, shifted_evals)
    }
}
