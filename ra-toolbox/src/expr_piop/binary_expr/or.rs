use super::{BinaryExprPIOPProverInput, BinaryExprPIOPVerifierInput};
use crate::expr_piop::binary_expr::utils::invert_or_one_in_place;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::Prover,
    verifier::Verifier,
};
use col_toolbox::binary_check::{
    BinaryCheckPIOP, BinaryCheckProverInput, BinaryCheckVerifierInput,
};
use std::marker::PhantomData;

pub struct OrBinaryExprPIOP<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(PhantomData<F>, PhantomData<MvPCS>, PhantomData<UvPCS>);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for OrBinaryExprPIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = BinaryExprPIOPProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = BinaryExprPIOPVerifierInput<F, MvPCS, UvPCS>;

    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        //TODO: implement honest prover check
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let binary_check_prover_input = BinaryCheckProverInput {
            predicate: input.output_col.activated_data_tracked_poly().clone(),
        };
        BinaryCheckPIOP::prove(prover, binary_check_prover_input)?;

        let col_left_right_sum =
            &input.left_col.data_tracked_poly() + &input.right_col.data_tracked_poly();
        let mut p_evals = col_left_right_sum.evaluations().to_vec();
        invert_or_one_in_place(&mut p_evals);
        let p_poly = MLE::from_evaluations_vec(col_left_right_sum.log_size(), p_evals);
        let p_tracked = prover.track_and_commit_mat_mv_poly(&p_poly)?;
        let zero_poly = match (
            input.left_col.activator_tracked_poly(),
            input.output_col.activator_tracked_poly(),
        ) {
            (Some(in_activator_tracked_poly), Some(out_activator_tracked_poly)) => {
                &(&(&in_activator_tracked_poly * &p_tracked)
                    * &(&input.left_col.data_tracked_poly() + &input.right_col.data_tracked_poly()))
                    - &(&input.output_col.data_tracked_poly() * &out_activator_tracked_poly)
            },
            (Some(in_activator_tracked_poly), None) => {
                &(&(&in_activator_tracked_poly * &p_tracked)
                    * &(&input.left_col.data_tracked_poly() + &input.right_col.data_tracked_poly()))
                    - &input.output_col.data_tracked_poly()
            },
            (None, Some(out_activator_tracked_poly)) => {
                &(&p_tracked
                    * &(&input.left_col.data_tracked_poly() + &input.right_col.data_tracked_poly()))
                    - &(&input.output_col.data_tracked_poly() * &out_activator_tracked_poly)
            },
            (None, None) => {
                &(&p_tracked
                    * &(&input.left_col.data_tracked_poly() + &input.right_col.data_tracked_poly()))
                    - &input.output_col.data_tracked_poly()
            },
        };
        prover.add_mv_zerocheck_claim(zero_poly.id())?;
        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let binary_check_verifier_input = BinaryCheckVerifierInput {
            predicate_oracle: input
                .output_col_oracle
                .activated_data_tracked_oracle()
                .clone(),
        };
        BinaryCheckPIOP::verify(verifier, binary_check_verifier_input)?;

        let p_id = verifier.peek_next_id();
        let p_tracked = verifier.track_mv_com_by_id(p_id)?;
        let zero_poly = match (
            input.left_col_oracle.activator_tracked_oracle(),
            input.output_col_oracle.activator_tracked_oracle(),
        ) {
            (Some(in_activator_tracked_poly), Some(out_activator_tracked_poly)) => {
                &(&(&in_activator_tracked_poly * &p_tracked)
                    * &(&input.left_col_oracle.data_tracked_oracle()
                        + &input.right_col_oracle.data_tracked_oracle()))
                    - &(&input.output_col_oracle.data_tracked_oracle()
                        * &out_activator_tracked_poly)
            },
            (Some(in_activator_tracked_poly), None) => {
                &(&(&in_activator_tracked_poly * &p_tracked)
                    * &(&input.left_col_oracle.data_tracked_oracle()
                        + &input.right_col_oracle.data_tracked_oracle()))
                    - &input.output_col_oracle.data_tracked_oracle()
            },
            (None, Some(out_activator_tracked_poly)) => {
                &(&p_tracked
                    * &(&input.left_col_oracle.data_tracked_oracle()
                        + &input.right_col_oracle.data_tracked_oracle()))
                    - &(&input.output_col_oracle.data_tracked_oracle()
                        * &out_activator_tracked_poly)
            },
            (None, None) => {
                &(&p_tracked
                    * &(&input.left_col_oracle.data_tracked_oracle()
                        + &input.right_col_oracle.data_tracked_oracle()))
                    - &input.output_col_oracle.data_tracked_oracle()
            },
        };
        verifier.add_zerocheck_claim(zero_poly.id());
        Ok(())
    }
}
