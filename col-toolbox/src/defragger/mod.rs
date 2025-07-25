//! A tool to defragment a column by removing the non-activated elements
use std::marker::PhantomData;

use arithmetic::col::{ArithCol, ColCom};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::Prover,
    timed,
    verifier::Verifier,
};
use ark_std::{end_timer, log2};
use num_bigint::BigUint;

use crate::perm_check::{PermPIOP, PermPIOPProverInput, PermPIOPVerifierInput};

/// A tool to defragment a column by removing the non-activated rows and
/// reducing the size of the underlying polynomial (as much as possible). It
/// internally invokes the permutation-check to ensure that the defragmented
/// column is still consistent with the original column.
pub struct Defragmenter<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> Defragmenter<F, MvPCS, UvPCS>
where
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    F: PrimeField,
{
    #[timed]
    pub fn defrag_col(
        tracker: &mut Prover<F, MvPCS, UvPCS>,
        col: &ArithCol<F, MvPCS, UvPCS>,
    ) -> SnarkResult<ArithCol<F, MvPCS, UvPCS>> {
        if col.get_actvtr_poly().is_none() {
            return Ok(col.clone());
        }
        let new_col_size_f: F = col
            .get_actvtr_poly()
            .as_ref()
            .unwrap()
            .evaluations()
            .iter()
            .sum();
        let new_col_size_biguint: BigUint = new_col_size_f.into();
        let new_col_size: usize = new_col_size_biguint.try_into().unwrap();
        let new_nv: usize = log2(new_col_size) as usize;
        // if new_nv == old_nv {
        //     return Ok(col.clone());
        // }

        let mut new_actv_evals: Vec<F> = Vec::with_capacity(1 << new_nv);
        let mut new_inner_evals: Vec<F> = Vec::with_capacity(1 << new_nv);
        col.get_data_poly()
            .evaluations()
            .iter()
            .zip(col.get_actvtr_poly().as_ref().unwrap().evaluations().iter())
            .for_each(|(val, actv)| {
                if actv.is_one() {
                    new_actv_evals.push(F::one());
                    new_inner_evals.push(*val);
                }
            });
        new_actv_evals.resize(1 << new_nv, F::zero());
        new_inner_evals.resize(1 << new_nv, F::zero());
        let new_col = ArithCol::new(
            col.get_data_type(),
            tracker.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
                new_nv,
                new_inner_evals,
            ))?,
            Some(
                tracker.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
                    new_nv,
                    new_actv_evals,
                ))?,
            ),
        );

        let perm_piop_prover_input = PermPIOPProverInput {
            left_col: col.clone(),
            right_col: new_col.clone(),
        };

        PermPIOP::<F, MvPCS, UvPCS>::prove(tracker, perm_piop_prover_input)?;
        Ok(new_col)
    }

    #[timed]
    pub fn defrag_col_com(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        col_com: &ColCom<F, MvPCS, UvPCS>,
    ) -> SnarkResult<ColCom<F, MvPCS, UvPCS>> {
        if col_com.actv.is_none() {
            return Ok(col_com.clone());
        }

        let new_col_inner_id = verifier.peek_next_id();
        let new_col_inner_tr = verifier.track_mv_com_by_id(new_col_inner_id)?;
        let new_col_actv_id = verifier.peek_next_id();
        let new_col_actv_tr = verifier.track_mv_com_by_id(new_col_actv_id)?;

        let new_col_com = ColCom::new(
            col_com.data_type.clone(),
            new_col_inner_tr.clone(),
            Some(new_col_actv_tr),
            verifier.get_commitment_num_vars(new_col_inner_id)?,
        );

        let perm_piop_verifier_input = PermPIOPVerifierInput {
            left_col_com: col_com.clone(),
            right_col_com: new_col_com.clone(),
        };

        PermPIOP::<F, MvPCS, UvPCS>::verify(verifier, perm_piop_verifier_input)?;
        Ok(new_col_com)
    }
}
