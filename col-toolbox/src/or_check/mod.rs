//! A PIOP for checking that a new activator is the AND of the input activators

#[cfg(test)]
mod test;

use arithmetic::col::ArithCol;
use arithmetic::col::ColCom;
use ark_ff::{batch_inversion, PrimeField};
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{Prover, errors::ProverError::HonestProverError, structs::TrackedPoly},
    timed,
    verifier::{Verifier, structs::oracle::TrackedOracle},
};
use datafusion::{arrow::ipc::Binary, functions_aggregate::sum};
use std::marker::PhantomData;

use crate::no_zeros_check::{NoZerosCheck, NoZerosCheckProverInput, NoZerosCheckVerifierInput};
use crate::binary_check::{BinaryCheckPIOP, BinaryCheckProverInput, BinaryCheckVerifierInput};

pub struct OrCheckPIOP<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

pub struct OrCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub in_activator_polys: Vec<TrackedPoly<F, MvPCS, UvPCS>>,
    pub res_activator_poly: TrackedPoly<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for OrCheckProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        let mut in_activator_polys_cloned = Vec::new();
        for activator_oply in &self.in_activator_polys {
            in_activator_polys_cloned.push(activator_oply.deep_clone(prover.clone()));
        }
        Self {
            in_activator_polys: in_activator_polys_cloned,
            res_activator_poly: self.res_activator_poly.deep_clone(prover),
        }
    }
}

pub struct OrCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub in_activator_orcls: Vec<TrackedOracle<F, MvPCS, UvPCS>>,
    pub res_activator_orcl: TrackedOracle<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for OrCheckPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = OrCheckProverInput<F, MvPCS, UvPCS>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = OrCheckVerifierInput<F, MvPCS, UvPCS>;

    #[timed]
    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        let mut sum_poly = input.in_activator_polys[0].clone();
        for in_poly in &input.in_activator_polys {
            sum_poly = sum_poly.add_poly(&in_poly);
        }

        let sum_evals = sum_poly.evaluations();
        let res_evals = input.res_activator_poly.evaluations();

        for (sum_eval, res_eval) in sum_evals.iter().zip(res_evals.iter()) {
            if *sum_eval == F::zero() && *res_eval != F::zero() {
                return Err(ark_piop::errors::SnarkError::ProverError(
                ark_piop::prover::errors::ProverError::HonestProverError(
                    ark_piop::prover::errors::HonestProverError::FalseClaim,
                ),
            ));
            }
            else if *sum_eval != F::zero() && *res_eval != F::one() {
                return Err(ark_piop::errors::SnarkError::ProverError(
                ark_piop::prover::errors::ProverError::HonestProverError(
                    ark_piop::prover::errors::HonestProverError::FalseClaim,
                ),
            ));
            }
        }

        return Ok(());


        // let legit_activator_poly = MLE
        // let check_poly = sum_poly.sub_poly(&input.res_activator_poly);
        // if (check_poly.evaluations().iter().all(|&elem| elem.is_zero())) {
        //     return Ok(());
        // } else {
        //     return Err(ark_piop::errors::SnarkError::ProverError(
        //         ark_piop::prover::errors::ProverError::HonestProverError(
        //             ark_piop::prover::errors::HonestProverError::FalseClaim,
        //         ),
        //     ));
        
    }
    #[timed]
    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<()> {
        // Rust Ownership and borrow rules
        let mut sum_poly = input.in_activator_polys[0].clone();
        for in_poly in &input.in_activator_polys {
            sum_poly = sum_poly.add_poly(in_poly);
        }

        let mut sum_evals = sum_poly.evaluations().clone();
        batch_inversion(&mut sum_evals);
        let inverted_sum_poly =
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
                sum_poly.get_log_size(),
                 sum_evals,
            ))?;


        let q = inverted_sum_poly.mul_poly(&sum_poly);
        let p = q.add_scalar(-F::one()).mul_scalar(-F::one()).add_poly(&inverted_sum_poly);


        // NoZerosCheck::<F, MvPCS, UvPCS>::prove(
        //     prover,
        //     NoZerosCheckProverInput {
        //         col: ArithCol::new(None, p.clone(), None),
        //     },
        // )?;

        BinaryCheckPIOP::<F, MvPCS, UvPCS>::prove(
            prover,
            BinaryCheckProverInput {
                activator: q.clone(),
            },
        )?;

        let zero_check_poly: TrackedPoly<F, MvPCS, UvPCS> = p.mul_poly(&sum_poly).sub_poly(&q);
        let zero_check_poly_2 = q.sub_poly(&input.res_activator_poly);

        prover.add_mv_zerocheck_claim(zero_check_poly.get_id())?;
        prover.add_mv_zerocheck_claim(zero_check_poly_2.get_id())?;

        Ok(())
    }

    #[timed]
    fn verify(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<()> {
        let mut sum_orcl = input.in_activator_orcls[0].clone();
        for in_orcl in &input.in_activator_orcls {
            sum_orcl = &sum_orcl + in_orcl;
        }
        let inverted_sum_id = verifier.peek_next_id();
        let inverted_sum_orcl = verifier.track_mv_com_by_id(inverted_sum_id)?;
        let q_orcl = &inverted_sum_orcl * &sum_orcl;
        let p_orcl = &(&inverted_sum_orcl - &q_orcl) + F::one();

        // NoZerosCheck::<F, MvPCS, UvPCS>::verify(
        //     verifier,
        //     NoZerosCheckVerifierInput {
        //         col_comm: ColCom::new(None, p_orcl.clone(), None, 0),
        //     },
        // )?;

        BinaryCheckPIOP::<F, MvPCS, UvPCS>::verify(
            verifier,
            BinaryCheckVerifierInput {
                activator_comm: q_orcl.clone(),
            },
        )?;

        let zero_check_orcl = &(&p_orcl * &sum_orcl) - &q_orcl;
        let zero_check_orcl_2 = &q_orcl - &input.res_activator_orcl;

        verifier.add_zerocheck_claim(zero_check_orcl.id);
        verifier.add_zerocheck_claim(zero_check_orcl_2.id);

        Ok(())
    }
}
