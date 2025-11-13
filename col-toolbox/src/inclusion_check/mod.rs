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
use derivative::Derivative;
use std::marker::PhantomData;
use utils::calc_inclusion_multiplicity;

use crate::multiplicity_check::{
    MultiplicityCheck, MultiplicityCheckProverInput, MultiplicityCheckVerifierInput,
};

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct HintedInclusionCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub included_cols: Vec<TrackedCol<F, MvPCS, UvPCS>>,
    pub super_col: TrackedCol<F, MvPCS, UvPCS>,
    pub super_col_multiplicities: Vec<TrackedPoly<F, MvPCS, UvPCS>>,
}

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS>
    for HintedInclusionCheckProverInput<F, MvPCS, UvPCS>
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
            super_col: self.super_col.deep_clone(prover.clone()),
            super_col_multiplicities: self
                .super_col_multiplicities
                .iter()
                .map(|poly| poly.deep_clone(prover.clone()))
                .collect(),
        }
    }
}

pub struct HintedInclusionCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub included_tracked_col_oracles: Vec<TrackedColOracle<F, MvPCS, UvPCS>>,
    pub super_tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    pub super_col_multiplicities: Vec<TrackedOracle<F, MvPCS, UvPCS>>,
}

pub struct HintedInclusionCheckPIOP<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

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
    PIOP<F, MvPCS, UvPCS> for HintedInclusionCheckPIOP<F, MvPCS, UvPCS>
where
    MvPCS: Clone,
    UvPCS: Clone,
{
    type ProverInput = HintedInclusionCheckProverInput<F, MvPCS, UvPCS>;
    type VerifierInput = HintedInclusionCheckVerifierInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierOutput = ();

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
        assert_eq!(
            input.included_cols.len(),
            input.super_col_multiplicities.len(),
            "super column multiplicity hints must align with included columns"
        );
        let included_col_ms = input
            .included_cols
            .iter()
            .map(|included_col| {
                let nv = included_col.log_size();
                let one_const_mle =
                    MLE::from_evaluations_vec(nv, vec![F::one(); 2_usize.pow(nv as u32)]);
                Some(prover.track_mat_mv_poly(one_const_mle))
            })
            .collect::<Vec<_>>();

        let multiplicity_check_prover_input = MultiplicityCheckProverInput {
            fxs: input.included_cols.clone(),
            gxs: vec![input.super_col.clone()],
            mfxs: included_col_ms,
            mgxs: input
                .super_col_multiplicities
                .iter()
                .cloned()
                .map(Some)
                .collect(),
        };

        MultiplicityCheck::<F, MvPCS, UvPCS>::prove(prover, multiplicity_check_prover_input)?;

        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        assert_eq!(
            input.included_tracked_col_oracles.len(),
            input.super_col_multiplicities.len(),
            "super column multiplicity hints must align with included column oracles"
        );
        let included_col_ms = input
            .included_tracked_col_oracles
            .iter()
            .map(|included_col| {
                let nv = included_col.log_size();
                let one_closure = |_: Vec<F>| -> SnarkResult<F> { Ok(F::one()) };
                Some(verifier.track_oracle(Oracle::new_multivariate(nv, one_closure)))
            })
            .collect::<Vec<_>>();

        let multiplicity_check_verifier_input = MultiplicityCheckVerifierInput {
            fxs: input.included_tracked_col_oracles.clone(),
            gxs: vec![input.super_tracked_col_oracle.clone()],
            mfxs: included_col_ms,
            mgxs: input
                .super_col_multiplicities
                .iter()
                .cloned()
                .map(Some)
                .collect(),
        };
        MultiplicityCheck::<F, MvPCS, UvPCS>::verify(verifier, multiplicity_check_verifier_input)?;
        Ok(())
    }
}

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

        let hinted_inclusion_check_prover_input = HintedInclusionCheckProverInput {
            included_cols: input.included_cols,
            super_col: input.super_col,
            super_col_multiplicities: super_col_ms.clone(),
        };
        HintedInclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(
            prover,
            hinted_inclusion_check_prover_input,
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

        let hinted_inclusion_check_verifier_input = HintedInclusionCheckVerifierInput {
            included_tracked_col_oracles: input.included_tracked_col_oracles,
            super_tracked_col_oracle: input.super_tracked_col_oracle,
            super_col_multiplicities: super_col_m_comms.clone(),
        };
        HintedInclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(
            verifier,
            hinted_inclusion_check_verifier_input,
        )?;
        Ok(InclusionCheckVerifierOutput { super_col_m_comms })
    }
}
