use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::ArgProver,
    verifier::ArgVerifier,
};
use derivative::Derivative;
use std::marker::PhantomData;

use crate::{
    prescribed_permutation_check::{
        PrescribedPermutationPIOP, PrescribedPermutationPIOPProverInput,
        PrescribedPermutationPIOPVerifierInput, shift_permutation_mle, shift_permutation_oracle,
    },
    sign_check::{Sign, SignCheckPIOP, SignCheckProverInput, SignCheckVerifierInput},
};

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct LocalSingleColSortCheckProverInput<B: SnarkBackend> {
    pub tracked_col: TrackedCol<B>,
    pub tie_indicator_col: TrackedCol<B>,
    pub shift_col: TrackedCol<B>,
    pub ascending: bool,
    pub strict: bool,
    pub is_last_col: bool,
}

impl<B> DeepClone<B> for LocalSingleColSortCheckProverInput<B>
where
    B: SnarkBackend,
{
    fn deep_clone(&self, prover: ArgProver<B>) -> Self {
        Self {
            tracked_col: self.tracked_col.deep_clone(prover.clone()),
            tie_indicator_col: self.tie_indicator_col.deep_clone(prover.clone()),
            shift_col: self.shift_col.deep_clone(prover),
            ascending: self.ascending,
            strict: self.strict,
            is_last_col: self.is_last_col,
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct LocalSingleColSortCheckVerifierInput<B: SnarkBackend> {
    pub tracked_col_oracle: TrackedColOracle<B>,
    pub tie_indicator_col_oracle: Option<TrackedColOracle<B>>,
    pub shift_col_oracle: TrackedColOracle<B>,
    pub ascending: bool,
    pub strict: bool,
    pub is_last_col_oracle: bool,
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct LocalSingleColSortCheckProverOutput<B: SnarkBackend> {
    pub diff_col: TrackedCol<B>,
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct LocalSingleColSortCheckVerifierOutput<B: SnarkBackend> {
    pub diff_col_oracle: TrackedColOracle<B>,
}

pub struct LocalSingleColSortCheckPIOP<B: SnarkBackend>(PhantomData<B>);

impl<B> PIOP<B> for LocalSingleColSortCheckPIOP<B>
where
    B: SnarkBackend,
{
    type ProverInput = LocalSingleColSortCheckProverInput<B>;
    type ProverOutput = LocalSingleColSortCheckProverOutput<B>;
    type VerifierInput = LocalSingleColSortCheckVerifierInput<B>;
    type VerifierOutput = LocalSingleColSortCheckVerifierOutput<B>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(_input: Self::ProverInput) -> SnarkResult<()> {
        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<B>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let LocalSingleColSortCheckProverInput {
            tracked_col,
            tie_indicator_col,
            shift_col,
            ascending,
            strict,
            is_last_col,
        } = input;
        let shift_permutation_mle =
            shift_permutation_mle(tracked_col.data_tracked_poly().log_size(), 1, true);
        let shift_permutation_tracked_poly = prover.track_mat_mv_poly(shift_permutation_mle);
        let prescribed_permutation_check_prover_input = PrescribedPermutationPIOPProverInput {
            left_tracked_poly: tracked_col.data_tracked_poly().clone(),
            right_tracked_poly: shift_col.data_tracked_poly().clone(),
            permutation_tracked_poly: shift_permutation_tracked_poly,
        };
        PrescribedPermutationPIOP::<B>::prove(prover, prescribed_permutation_check_prover_input)?;

        let diff_activator_tracked_poly = match shift_col.activator_tracked_poly() {
            Some(poly) => Some(&poly * &tie_indicator_col.data_tracked_poly()),
            None => Some(tie_indicator_col.data_tracked_poly()),
        };

        let diff_col = TrackedCol::new(
            &shift_col.data_tracked_poly() - &tracked_col.data_tracked_poly(),
            diff_activator_tracked_poly,
            tracked_col.field_ref(),
        );
        let sign = match (is_last_col, ascending, strict) {
            (true, true, true) => Sign::Positive,
            (true, true, false) => Sign::NoneNegative,
            (true, false, true) => Sign::Negative,
            (true, false, false) => Sign::NonePositive,
            (false, true, _) => Sign::NoneNegative,
            (false, false, _) => Sign::NonePositive,
        };

        let sign_check_prover_input = SignCheckProverInput {
            col: diff_col.clone(),
            sign,
        };
        SignCheckPIOP::<B>::prove(prover, sign_check_prover_input)?;
        Ok(Self::ProverOutput { diff_col })
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let LocalSingleColSortCheckVerifierInput {
            tracked_col_oracle,
            tie_indicator_col_oracle,
            shift_col_oracle,
            ascending,
            strict,
            is_last_col_oracle,
        } = input;

        let shift_permutation_oracle = shift_permutation_oracle::<B::F>(
            tracked_col_oracle.data_tracked_oracle().log_size(),
            1,
            true,
        );
        let shift_permutation_tracked_oracle = verifier.track_oracle(shift_permutation_oracle);
        let prescribed_permutation_check_verifier_input = PrescribedPermutationPIOPVerifierInput {
            left_tracked_oracle: tracked_col_oracle.data_tracked_oracle().clone(),
            right_tracked_oracle: shift_col_oracle.data_tracked_oracle().clone(),
            permutation_tracked_oracle: shift_permutation_tracked_oracle,
        };
        PrescribedPermutationPIOP::<B>::verify(
            verifier,
            prescribed_permutation_check_verifier_input,
        )?;

        let tie_indicator_col_oracle = tie_indicator_col_oracle.expect(
            "tie indicator column oracle must be provided for local single column sort check",
        );

        let mut diff_data_oracle = shift_col_oracle.data_tracked_oracle();
        diff_data_oracle -= &tracked_col_oracle.data_tracked_oracle();

        let diff_activator_tracked_oracle = match shift_col_oracle.activator_tracked_oracle() {
            Some(poly) => Some(&poly * &tie_indicator_col_oracle.data_tracked_oracle()),
            None => Some(tie_indicator_col_oracle.data_tracked_oracle()),
        };

        let diff_col_oracle = TrackedColOracle::new(
            diff_data_oracle,
            diff_activator_tracked_oracle,
            tracked_col_oracle.field_ref(),
        );

        let sign = match (is_last_col_oracle, ascending, strict) {
            (true, true, true) => Sign::Positive,
            (true, true, false) => Sign::NoneNegative,
            (true, false, true) => Sign::Negative,
            (true, false, false) => Sign::NonePositive,
            (false, true, _) => Sign::NoneNegative,
            (false, false, _) => Sign::NonePositive,
        };

        let sign_check_input = SignCheckVerifierInput {
            tracked_col_oracle: diff_col_oracle.clone(),
            sign,
        };

        SignCheckPIOP::<B>::verify(verifier, sign_check_input)?;
        Ok(Self::VerifierOutput { diff_col_oracle })
    }
}
