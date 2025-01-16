#[cfg(test)]
mod test;

use arithmetic::{
    ark_ff::{self, Field, PrimeField},
    ark_poly::{self, DenseMultilinearExtension},
    ff::sort_permute_ff,
    to_field_vec,
};
use ark_std::{One, Zero};
use crypto::{ark_ec, ark_ec::pairing::Pairing, pcs::PolynomialCommitmentScheme};
use datafusion::arrow::compute::kernels::sort;
use kit::ark_std;

// use zksql_macros::same_nv;
use std::{marker::PhantomData, ops::Neg};

use crate::tracker::prelude::*;

use super::{prescr_perm_check::PrescrPermPIOP, sort_check::StrictSortPIOP};

// Convinces the verifier that
pub struct NoDupPIOP<F: PrimeField, PCS: PolynomialCommitmentScheme<F>>(
    PhantomData<F>,
    PhantomData<PCS>,
);

impl<F: PrimeField, PCS: PolynomialCommitmentScheme<F>> NoDupPIOP<F, PCS>
where
    PCS: PolynomialCommitmentScheme<F>,
    F: PrimeField,
{
    // TODO: #[same_nv(fxs, gxs, mfxs, mgxs)]
    pub fn prove(
        tracker: &mut ProverTrackerRef<F, PCS>,
        in_col: &Col<F, PCS>,
        range_col: &Col<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let (sorted_col, perm_tr_poly) = sort_col::<F, PCS>(tracker, in_col)?;
        PrescrPermPIOP::prove(tracker, &sorted_col, in_col, &perm_tr_poly)?;

        StrictSortPIOP::prove(tracker, &sorted_col, range_col)?;
        Ok(())
    }

    pub fn verify(
        tracker: &mut VerifierTrackerRef<F, PCS>,
        in_cm: &ColComm<F, PCS>,
        range_cm: &ColComm<F, PCS>,
    ) -> Result<(), PolyIOPErrors> {
        let sorted_poly_id = tracker.get_next_id();
        let actv_poly_id = TrackerID(sorted_poly_id.0 + 1);
        let perm_poly_id = TrackerID(actv_poly_id.0 + 1);
        let sorted_tr_comm = tracker.transfer_prover_comm(sorted_poly_id);
        let actv_tr_comm = tracker.transfer_prover_comm(actv_poly_id);
        let perm_tr_comm = tracker.transfer_prover_comm(perm_poly_id);
        let sorted_col = ColComm::new(sorted_tr_comm, actv_tr_comm, in_cm.num_vars());
        PrescrPermPIOP::verify(tracker, &sorted_col, in_cm, &perm_tr_comm);
        StrictSortPIOP::verify(tracker, &sorted_col, range_cm);
        Ok(())
    }
}

fn sort_col<F: PrimeField, PCS: PolynomialCommitmentScheme<F>>(
    tracker: &mut ProverTrackerRef<F, PCS>,
    in_col: &Col<F, PCS>,
) -> Result<(Col<F, PCS>, TrackedPoly<F, PCS>), PolyIOPErrors> {
    let in_evals = in_col.inner_poly.evaluations();
    let actv_evals = in_col.actv_poly.evaluations();
    // TODO: There is no need to sort every element, Just sort the activated
    // elements
    let (sorted_col_evals, perm_usize_evals, _) = sort_permute_ff(&in_evals, &actv_evals);
    let sorted_actv_evals: Vec<F> = perm_usize_evals.iter().map(|i| actv_evals[*i]).collect();
    let sorted_col_mle =
        DenseMultilinearExtension::from_evaluations_vec(in_col.num_vars(), sorted_col_evals);
    let sorted_actv_mle =
        DenseMultilinearExtension::from_evaluations_vec(in_col.num_vars(), sorted_actv_evals);
    let sorted_col = Col::new(
        tracker.track_and_commit_poly(sorted_col_mle)?,
        tracker.track_and_commit_poly(sorted_actv_mle)?,
    );
    let perm_mle = DenseMultilinearExtension::from_evaluations_vec(
        in_col.num_vars(),
        to_field_vec!(&perm_usize_evals, F),
    );
    let perm_tr_poly = tracker.track_and_commit_poly(perm_mle)?;
    dbg!(in_col.inner_poly.evaluations());
    dbg!(in_col.actv_poly.evaluations());
    dbg!(sorted_col.inner_poly.evaluations());
    dbg!(sorted_col.actv_poly.evaluations());
    dbg!(perm_tr_poly.evaluations());
    Ok((sorted_col, perm_tr_poly))
}

fn defrag<F: Field + PrimeField>(
    defrag_evals: &[F],
    defrag_actvtr: &[F],
    current_perm: &[usize]
) -> Result<(Vec<F>,Vec<F>,Vec<usize>), PolyIOPErrors> {
    for actv in defrag_actvtr {

    }
    todo!()
}

// fn sort_defrag<F:Field>(evals: &[F], actvs: &[F]) -> (Vec<F>, Vec<F>, Vec<usize>) {
//     let (sorted_evals, perm_usize_evals, _) = sort_permute_ff(evals);
//     let sorted_actvs: Vec<F> = perm_usize_evals.iter().map(|i| actvs[*i]).collect();
    
// }