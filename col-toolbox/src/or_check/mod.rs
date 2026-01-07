//! A PIOP for checking that a new activator is the AND of the input activators

#[cfg(test)]
mod test;

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::{One, batch_inversion};
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::SnarkResult,
    piop::{DeepClone, PIOP},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};
use derivative::Derivative;
use std::marker::PhantomData;

use crate::{
    binary_check::{BinaryCheckPIOP, BinaryCheckProverInput, BinaryCheckVerifierInput},
    no_zeros_check::{NoZerosCheck, NoZerosCheckProverInput, NoZerosCheckVerifierInput},
};
pub struct OrCheckPIOP<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct OrCheckProverInput<B: SnarkBackend> {
    pub in_activator_tracked_polys: Vec<TrackedPoly<B>>,
    pub res_activator_tracked_poly: TrackedPoly<B>,
}

impl<B: SnarkBackend> DeepClone<B> for OrCheckProverInput<B> {
    fn deep_clone(&self, prover: ArgProver<B>) -> Self {
        let mut in_activator_tracked_polys_cloned = Vec::new();
        for activator_oply in &self.in_activator_tracked_polys {
            in_activator_tracked_polys_cloned.push(activator_oply.deep_clone(prover.clone()));
        }
        Self {
            in_activator_tracked_polys: in_activator_tracked_polys_cloned,
            res_activator_tracked_poly: self.res_activator_tracked_poly.deep_clone(prover),
        }
    }
}

pub struct OrCheckVerifierInput<B: SnarkBackend> {
    pub in_activator_orcls: Vec<TrackedOracle<B>>,
    pub res_activator_orcl: TrackedOracle<B>,
}

impl<B: SnarkBackend> PIOP<B> for OrCheckPIOP<B> {
    type ProverInput = OrCheckProverInput<B>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = OrCheckVerifierInput<B>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        use ark_ff::Zero;
        let mut sum_poly = input.in_activator_tracked_polys[0].clone();
        for in_poly in &input.in_activator_tracked_polys {
            sum_poly += in_poly;
        }

        let sum_evals = sum_poly.evaluations();
        let res_evals = input.res_activator_tracked_poly.evaluations();

        for (sum_eval, res_eval) in sum_evals.iter().zip(res_evals.iter()) {
            if *sum_eval == B::F::zero() && *res_eval != B::F::zero() {
                return Err(ark_piop::errors::SnarkError::ProverError(
                    ark_piop::prover::errors::ProverError::HonestProverError(
                        ark_piop::prover::errors::HonestProverError::FalseClaim,
                    ),
                ));
            }
            if *sum_eval != B::F::zero() && *res_eval != B::F::one() {
                return Err(ark_piop::errors::SnarkError::ProverError(
                    ark_piop::prover::errors::ProverError::HonestProverError(
                        ark_piop::prover::errors::HonestProverError::FalseClaim,
                    ),
                ));
            }
        }

        Ok(())

        // let legit_activator_tracked_poly = MLE
        // let check_poly =
        // sum_poly.sub_poly(&input.res_activator_tracked_poly);
        // if (check_poly.evaluations().iter().all(|&elem| elem.is_zero())) {
        //     return Ok(());
        // } else {
        //     return Err(ark_piop::errors::SnarkError::ProverError(
        //         ark_piop::prover::errors::ProverError::HonestProverError(
        //             ark_piop::prover::errors::HonestProverError::FalseClaim,
        //         ),
        //     ));
    }
    fn prove_inner(prover: &mut ArgProver<B>, input: Self::ProverInput) -> SnarkResult<()> {
        // Rust Ownership and borrow rules
        let mut sum_poly = input.in_activator_tracked_polys[0].clone();
        for in_poly in &input.in_activator_tracked_polys {
            sum_poly += in_poly;
        }

        let mut sum_evals = sum_poly.evaluations().clone();
        batch_inversion(&mut sum_evals);
        let inverted_sum_poly = prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
            sum_poly.log_size(),
            sum_evals,
        ))?;

        let q = &inverted_sum_poly * &sum_poly;
        let p = (&inverted_sum_poly - &q) + B::F::one();

        NoZerosCheck::<B>::prove(
            prover,
            NoZerosCheckProverInput {
                col: TrackedCol::new(p.clone(), None, None),
            },
        )?;

        BinaryCheckPIOP::<B>::prove(
            prover,
            BinaryCheckProverInput {
                predicate: q.clone(),
            },
        )?;

        let zero_check_poly: TrackedPoly<B> = &(&p * &sum_poly) - &q;
        let zero_check_poly_2 = &q - &input.res_activator_tracked_poly;

        prover.add_mv_zerocheck_claim(zero_check_poly.id())?;
        prover.add_mv_zerocheck_claim(zero_check_poly_2.id())?;

        Ok(())
    }

    fn verify_inner(verifier: &mut ArgVerifier<B>, input: Self::VerifierInput) -> SnarkResult<()> {
        let mut sum_orcl = input.in_activator_orcls[0].clone();
        for in_orcl in &input.in_activator_orcls {
            sum_orcl = &sum_orcl + in_orcl;
        }
        let inverted_sum_id = verifier.peek_next_id();
        let inverted_sum_orcl = verifier.track_mv_com_by_id(inverted_sum_id)?;
        let q_orcl = &inverted_sum_orcl * &sum_orcl;
        let p_orcl = (&inverted_sum_orcl - &q_orcl) + B::F::one();

        NoZerosCheck::<B>::verify(
            verifier,
            NoZerosCheckVerifierInput {
                tracked_col_oracle: TrackedColOracle::new(p_orcl.clone(), None, None),
            },
        )?;

        BinaryCheckPIOP::<B>::verify(
            verifier,
            BinaryCheckVerifierInput {
                predicate_oracle: q_orcl.clone(),
            },
        )?;

        let zero_check_orcl = &(&p_orcl * &sum_orcl) - &q_orcl;
        let zero_check_orcl_2 = &q_orcl - &input.res_activator_orcl;

        verifier.add_zerocheck_claim(zero_check_orcl.id());
        verifier.add_zerocheck_claim(zero_check_orcl_2.id());

        Ok(())
    }
}
