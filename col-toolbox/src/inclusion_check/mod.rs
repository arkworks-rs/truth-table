//! A PIOP for checing if a column is included in another column
/// More precisely, it checks if the activated elements of a column is included
/// in another column. Internally, this PIOP invokes the `MultiplicityCheck`
/// with the multiplicity polynomial of all 1 for the 'included_col' and a
/// computed advice multiplicity for 'super_col'#[cfg(test)]
#[cfg(test)]
mod test;
pub(crate) mod utils;

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{Prover, structs::polynomial::TrackedPoly},
    verifier::{
        Verifier,
        structs::oracle::{Oracle, TrackedOracle},
    },
};
use ark_std::cfg_iter;
use derivative::Derivative;
use rayon::iter::IntoParallelRefIterator;
use std::{marker::PhantomData, sync::Arc};
use utils::calc_inclusion_multiplicity;

use crate::multiplicity_check::{
    MultiplicityCheck, MultiplicityCheckProverInput, MultiplicityCheckVerifierInput,
};

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct InclusionCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub included_cols: Vec<TrackedCol<F, MvPCS, UvPCS>>,
    pub super_col: TrackedCol<F, MvPCS, UvPCS>,
}

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for InclusionCheckProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            included_cols: self
                .included_cols
                .iter()
                .map(|c| c.deep_clone(prover.clone()))
                .collect(),
            super_col: self.super_col.deep_clone(prover),
        }
    }
}

pub struct InclusionCheckProverOutput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub super_col_ms: Vec<TrackedPoly<F, MvPCS, UvPCS>>,
}

pub struct InclusionCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub included_tracked_col_oracles: Vec<TrackedColOracle<F, MvPCS, UvPCS>>,
    pub super_tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
}

pub struct InclusionCheckVerifierOutput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub super_col_m_comms: Vec<TrackedOracle<F, MvPCS, UvPCS>>,
}

pub struct InclusionCheckPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for InclusionCheckPIOP<F, MvPCS, UvPCS>
where
    MvPCS: Clone,
    UvPCS: Clone,
{
    type ProverInput = InclusionCheckProverInput<F, MvPCS, UvPCS>;

    type ProverOutput = InclusionCheckProverOutput<F, MvPCS, UvPCS>;

    type VerifierOutput = InclusionCheckVerifierOutput<F, MvPCS, UvPCS>;

    type VerifierInput = InclusionCheckVerifierInput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        use std::collections::HashSet;

        use ark_piop::{
            errors::SnarkError,
            prover::errors::{HonestProverError, ProverError},
        };

        let super_col_hash_set: HashSet<F> = input.super_col.effective_hashset();
        for elem in input.included_cols.iter().flat_map(|c| c.effective_iter()) {
            if !super_col_hash_set.contains(&elem) {
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }

        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let super_col_m_mles = input
            .included_cols
            .iter()
            .map(|included_col| calc_inclusion_multiplicity(included_col, &input.super_col))
            .collect::<Vec<_>>();
        let super_col_ms = super_col_m_mles
            .iter()
            .map(|mle| prover.track_and_commit_mat_mv_poly(mle))
            .collect::<SnarkResult<Vec<_>>>()?;

        Self::prove_with_advice(
            prover,
            &input.included_cols,
            &input.super_col,
            &super_col_ms,
        )?;
        Ok(InclusionCheckProverOutput { super_col_ms })
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let super_col_m_comms = input
            .included_tracked_col_oracles
            .iter()
            .map(|_| {
                let id = verifier.peek_next_id();
                verifier.track_mv_com_by_id(id)
            })
            .collect::<SnarkResult<Vec<_>>>()?;

        Self::verify_with_advice(
            verifier,
            &input.included_tracked_col_oracles,
            &input.super_tracked_col_oracle,
            &super_col_m_comms,
        )?;
        Ok(InclusionCheckVerifierOutput { super_col_m_comms })
    }
}

impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> InclusionCheckPIOP<F, MvPCS, UvPCS>
where
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    F: PrimeField,
{
    pub fn prove_with_advice(
        tracker: &mut Prover<F, MvPCS, UvPCS>,
        included_cols: &Vec<TrackedCol<F, MvPCS, UvPCS>>,
        super_col: &TrackedCol<F, MvPCS, UvPCS>,
        super_col_ms: &Vec<TrackedPoly<F, MvPCS, UvPCS>>,
    ) -> SnarkResult<()> {
        let included_col_ms = included_cols
            .iter()
            .map(|included_col| {
                let nv = included_col.log_size();
                let one_const_mle =
                    MLE::from_evaluations_vec(nv, vec![F::one(); 2_usize.pow(nv as u32)]);
                Some(tracker.track_mat_mv_poly(one_const_mle))
            })
            .collect::<Vec<_>>();

        // call the multiplicity_check prover
        let multiplicity_check_prover_input = MultiplicityCheckProverInput {
            fxs: included_cols.clone(),
            gxs: vec![super_col.clone()],
            mfxs: included_col_ms,
            mgxs: super_col_ms.clone().iter().cloned().map(Some).collect(),
        };

        MultiplicityCheck::<F, MvPCS, UvPCS>::prove(tracker, multiplicity_check_prover_input)?;

        Ok(())
    }

    pub fn verify_with_advice(
        tracker: &mut Verifier<F, MvPCS, UvPCS>,
        included_cols: &Vec<TrackedColOracle<F, MvPCS, UvPCS>>,
        super_col: &TrackedColOracle<F, MvPCS, UvPCS>,
        super_col_ms: &Vec<TrackedOracle<F, MvPCS, UvPCS>>,
    ) -> SnarkResult<()> {
        let included_col_ms = included_cols
            .iter()
            .map(|included_col| {
                let nv = included_col.log_size();
                let one_closure = |_: Vec<F>| -> SnarkResult<F> { Ok(F::one()) };
                Some(tracker.track_oracle(Oracle::new_multivariate(nv, one_closure)))
            })
            .collect::<Vec<_>>();

        let multiplicity_check_verifier_input = MultiplicityCheckVerifierInput {
            fxs: included_cols.clone(),
            gxs: vec![super_col.clone()],
            mfxs: included_col_ms,
            mgxs: super_col_ms.iter().cloned().map(Some).collect(),
        };
        MultiplicityCheck::<F, MvPCS, UvPCS>::verify(tracker, multiplicity_check_verifier_input)?;
        Ok(())
    }
}
