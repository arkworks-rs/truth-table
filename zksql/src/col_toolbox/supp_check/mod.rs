#[cfg(test)]
mod test;

pub(crate) mod utils;

use arithmetic::ark_ff;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use crypto::{ark_ec, pcs::PolynomialCommitmentScheme};
use std::marker::PhantomData;

use crate::{
    col_toolbox::{
        inclusion_check::{utils::calc_inclusion_check_advice_from_col, InclusionCheck},
        no_zeros_check::NoZerosCheck,
        sort_check::StrictSortPIOP,
    },
    tracker::prelude::*,
};

use super::no_dup_check::NoDupPIOP;

pub struct SuppCheckPIOP<F:PrimeField, PCS: PolynomialCommitmentScheme<F>>(
    PhantomData<F>,
    PhantomData<PCS>,
);

// The range_col should be static and globally available to all PIOPs

/// A PIOP to prove that a column is a suport of another column, i.e. has all
/// the elements but deduplicated
///
/// It 1st: shows that support is included in the column with a certain
/// multiplicity, 2nd: shows that this multiplicity is all non-zero, 3rd: shows
/// that there is no duplicate in the support (The best way we know to do this
/// is to show that it's strictly sorted)
/// IMPORTANT: The supp column should be sorted
impl<F:PrimeField, PCS: PolynomialCommitmentScheme<F>> SuppCheckPIOP<F, PCS>
where
    PCS: PolynomialCommitmentScheme<F>,
    F:PrimeField
{
    pub fn prove(
        prover_tracker: &mut ProverTrackerRef<F, PCS>,
        col: &Col<F, PCS>,
        supp: &Col<F, PCS>,
        range_col: &Col<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {


        let common_mset_supp_m_mle = calc_inclusion_check_advice_from_col(col, supp);
        let common_mset_supp_m = prover_tracker.track_and_commit_poly(common_mset_supp_m_mle)?;
        
        SuppCheckPIOP::prove_with_advice(prover_tracker, col, supp, &common_mset_supp_m, range_col)?;

        Ok(())
    }

    pub fn prove_with_advice(
        prover_tracker: &mut ProverTrackerRef<F, PCS>,
        col: &Col<F, PCS>,
        supp: &Col<F, PCS>,
        common_mset_supp_m: &TrackedPoly<F, PCS>,
        range_col: &Col<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        // Show col \subseteq supp
        InclusionCheck::<F, PCS>::prove_with_advice(
            prover_tracker,
            &col.clone(),
            &supp.clone(),
            &common_mset_supp_m.clone(),
        )?;

        // Show common_mset_supp_m has no zeros, which implies supp \subseteq col
        // common_mset_supp_m will have no zeros becuaes it's the only way to for it to
        // be valid otherwise calc_inclusion_check_advice_from_col would not
        // return something without zeros by default Note: can resuse the
        // supp.selector as the supp_m.selector
        let supp_no_dups_checker = Col::new(common_mset_supp_m.clone(), supp.actv_poly.clone());
        NoZerosCheck::<F, PCS>::prove(prover_tracker, &supp_no_dups_checker)?;
        // (StrictSortPIOP) Show supp is sorted by calling sort_check
        NoDupPIOP::<F, PCS>::prove(prover_tracker, supp, range_col)?;

        Ok(())
    }

    pub fn verify(
        verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
        col: &ColComm<F, PCS>,
        supp: &ColComm<F, PCS>,
        range_col_comm: &ColComm<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let common_mset_supp_m_id = verifier_tracker.get_next_id();
        let common_mset_supp_m = verifier_tracker.transfer_prover_comm(common_mset_supp_m_id);

        SuppCheckPIOP::verify_with_advice(
            verifier_tracker,
            col,
            supp,
            &common_mset_supp_m,
            range_col_comm,
        )?;

        Ok(())
    }

    pub fn verify_with_advice(
        verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
        col: &ColComm<F, PCS>,
        supp: &ColComm<F, PCS>,
        common_mset_supp_m: &TrackedComm<F, PCS>,
        range_col_comm: &ColComm<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        // Use ColMultitool PIOP to show col and supp share a Common Multiset
        InclusionCheck::<F, PCS>::verify_with_advice(
            verifier_tracker,
            &col.clone(),
            &supp.clone(),
            &common_mset_supp_m.clone(),
        )?;

        // col and supp are subsets of each other by showing multiplicity polys have no
        // zeros
        let supp_no_dups_checker = ColComm::new(
            common_mset_supp_m.clone(),
            supp.selector.clone(),
            supp.num_vars(),
        );
        NoZerosCheck::<F, PCS>::verify(verifier_tracker, &supp_no_dups_checker)?;

        // (StrictSortPIOP) Show supp is sorted by calling sort_check
        NoDupPIOP::<F, PCS>::verify(verifier_tracker, supp, range_col_comm)?;

        Ok(())
    }
}
