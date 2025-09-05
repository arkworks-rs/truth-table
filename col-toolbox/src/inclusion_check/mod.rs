//! A PIOP for checing if a column is included in another column
/// More precisely, it checks if the activated elements of a column is included
/// in another column. Internally, this PIOP invokes the `MultiplicityCheck`
/// with the multiplicity polynomial of all 1 for the 'included_col' and a
/// computed advice multiplicity for 'super_col'#[cfg(test)]

#[cfg(test)]
mod test;
pub(crate) mod utils;

use arithmetic::col::{ArithCol, ColCom};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{Prover, structs::polynomial::TrackedPoly},
    timed,
    verifier::{
        Verifier,
        structs::oracle::{Oracle, TrackedOracle},
    },
};
use std::{marker::PhantomData, sync::Arc};
use utils::calc_inclusion_multiplicity;

use crate::multiplicity_check::{
    MultiplicityCheck, MultiplicityCheckProverInput, MultiplicityCheckVerifierInput,
};
pub struct InclusionCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub included_col: ArithCol<F, MvPCS, UvPCS>,
    pub super_col: ArithCol<F, MvPCS, UvPCS>,
}

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for InclusionCheckProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            included_col: self.included_col.deep_clone(prover.clone()),
            super_col: self.super_col.deep_clone(prover),
        }
    }
}

pub struct InclusionCheckProverOutput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub super_col_m: TrackedPoly<F, MvPCS, UvPCS>,
}

pub struct InclusionCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub included_col_comm: ColCom<F, MvPCS, UvPCS>,
    pub super_col_comm: ColCom<F, MvPCS, UvPCS>,
}

pub struct InclusionCheckVerifierOutput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub super_col_m_comm: TrackedOracle<F, MvPCS, UvPCS>,
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

    #[timed]
    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        use std::collections::HashSet;

        use ark_piop::{
            errors::SnarkError,
            prover::errors::{HonestProverError, ProverError},
        };

        let super_col_hash_set: HashSet<F> = input.super_col.effective_hashset();
        for elem in input.included_col.effective_iter() {
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
        let super_col_m_mle = calc_inclusion_multiplicity(&input.included_col, &input.super_col);
        let super_col_m = prover.track_and_commit_mat_mv_poly(&super_col_m_mle)?;

        Self::prove_with_advice(prover, &input.included_col, &input.super_col, &super_col_m)?;
        Ok(InclusionCheckProverOutput { super_col_m })
    }

    fn verify(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let super_col_m_id = verifier.peek_next_id();
        let super_col_m = verifier.track_mv_com_by_id(super_col_m_id)?;
        Self::verify_with_advice(
            verifier,
            &input.included_col_comm,
            &input.super_col_comm,
            &super_col_m,
        )?;
        Ok(InclusionCheckVerifierOutput {
            super_col_m_comm: super_col_m,
        })
    }
}

impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> InclusionCheckPIOP<F, MvPCS, UvPCS>
where
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    F: PrimeField,
{
    #[timed]
    pub fn prove_with_advice(
        tracker: &mut Prover<F, MvPCS, UvPCS>,
        included_col: &ArithCol<F, MvPCS, UvPCS>,
        super_col: &ArithCol<F, MvPCS, UvPCS>,
        super_col_m: &TrackedPoly<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let nv = included_col.get_num_vars();

        // initialize multiplicity vector
        let one_const_mle = MLE::from_evaluations_vec(nv, vec![F::one(); 2_usize.pow(nv as u32)]);
        let included_col_m = tracker.track_mat_mv_poly(one_const_mle);
        // call the multiplicity_check prover
        let multiplicity_check_prover_input = MultiplicityCheckProverInput {
            fxs: vec![included_col.clone()],
            gxs: vec![super_col.clone()],
            mfxs: vec![Some(included_col_m.clone())],
            mgxs: vec![Some(super_col_m.clone())],
        };

        MultiplicityCheck::<F, MvPCS, UvPCS>::prove(tracker, multiplicity_check_prover_input)?;

        Ok(())
    }

    #[timed]
    pub fn verify_with_advice(
        tracker: &mut Verifier<F, MvPCS, UvPCS>,
        included_col: &ColCom<F, MvPCS, UvPCS>,
        super_col: &ColCom<F, MvPCS, UvPCS>,
        super_col_m: &TrackedOracle<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let one_closure = |_: Vec<F>| -> SnarkResult<F> { Ok(F::one()) };
        let one_comm = tracker.track_oracle(Oracle::Multivariate(Arc::new(one_closure)));

        let multiplicity_check_verifier_input = MultiplicityCheckVerifierInput {
            fxs: vec![included_col.clone()],
            gxs: vec![super_col.clone()],
            mfxs: vec![Some(one_comm.clone())],
            mgxs: vec![Some(super_col_m.clone())],
        };
        MultiplicityCheck::<F, MvPCS, UvPCS>::verify(tracker, multiplicity_check_verifier_input)?;
        Ok(())
    }
}
