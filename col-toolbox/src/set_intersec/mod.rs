//! A PIOP for checking that a column is the intersection of two columns with
//! no duplicates (set)

#[cfg(test)]
mod test;

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::ArgProver,
    verifier::{
        ArgVerifier,
        structs::oracle::{Oracle, TrackedOracle},
    },
};
use derivative::Derivative;
use std::marker::PhantomData;

use crate::{
    multiplicity_check::{
        MultiplicityCheck, MultiplicityCheckProverInput, MultiplicityCheckVerifierInput,
    },
    no_dup_check::{self, NoDupPIOP},
};

pub struct SetInterUnionCheckPIOP<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct SetInterUnionProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
> {
    pub col_left: TrackedCol<F, MvPCS, UvPCS>,
    pub col_right: TrackedCol<F, MvPCS, UvPCS>,
    pub col_inter: TrackedCol<F, MvPCS, UvPCS>,
    pub col_union: TrackedCol<F, MvPCS, UvPCS>,
}

impl<F: PrimeField,     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,>
    DeepClone<F, MvPCS, UvPCS> for SetInterUnionProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: ArgProver<F, MvPCS, UvPCS>) -> Self {
        Self {
            col_left: self.col_left.deep_clone(prover.clone()),
            col_right: self.col_right.deep_clone(prover.clone()),
            col_inter: self.col_inter.deep_clone(prover.clone()),
            col_union: self.col_union.deep_clone(prover),
        }
    }
}
pub struct SetInterUnionVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
> {
    pub col_left: TrackedColOracle<F, MvPCS, UvPCS>,
    pub col_right: TrackedColOracle<F, MvPCS, UvPCS>,
    pub col_inter: TrackedColOracle<F, MvPCS, UvPCS>,
    pub col_union: TrackedColOracle<F, MvPCS, UvPCS>,
}

impl<F: PrimeField,     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,>
    PIOP<F, MvPCS, UvPCS> for SetInterUnionCheckPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = SetInterUnionProverInput<F, MvPCS, UvPCS>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = SetInterUnionVerifierInput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        use ark_piop::{
            errors::SnarkError,
            prover::errors::{HonestProverError, ProverError},
        };
        use std::collections::HashSet;

        // Check if the left column has no duplicates
        let mut seen = HashSet::new();
        if !input
            .col_left
            .effective_iter()
            .into_iter()
            .all(|x| seen.insert(x))
        {
            // panic!();
            return Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::FalseClaim,
            )));
        }

        // Check if the right column has no duplicates
        let mut seen = HashSet::new();
        if !input
            .col_right
            .effective_iter()
            .into_iter()
            .all(|x| seen.insert(x))
        {
            // panic!();
            return Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::FalseClaim,
            )));
        }

        // Check if the intersection column has no duplicates
        let mut seen = HashSet::new();
        if !input
            .col_inter
            .effective_iter()
            .into_iter()
            .all(|x| seen.insert(x))
        {
            // panic!();
            return Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::FalseClaim,
            )));
        }

        // Check if the union column has no duplicates
        let mut seen = HashSet::new();
        if !input
            .col_union
            .effective_iter()
            .into_iter()
            .all(|x| seen.insert(x))
        {
            // panic!();
            return Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::FalseClaim,
            )));
        }

        let left_hashset = input.col_left.effective_hashset();
        let right_hashset = input.col_right.effective_hashset();

        let real_intersection: HashSet<F> =
            left_hashset.intersection(&right_hashset).copied().collect();
        let real_union: HashSet<F> = left_hashset.union(&right_hashset).copied().collect();

        let claimed_intersection: HashSet<F> = input.col_inter.effective_hashset();
        let claimed_union: HashSet<F> = input.col_union.effective_hashset();

        if real_intersection != claimed_intersection {
            // panic!();
            return Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::FalseClaim,
            )));
        }

        if real_union != claimed_union {
            // panic!();
            return Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::FalseClaim,
            )));
        }

        Ok(())
    }
    fn prove_inner(
        prover: &mut ArgProver<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<()> {
        // The union and the intersections should be of the same size, bcause of how
        // this protocol works
        assert_eq!(input.col_inter.log_size(), input.col_union.log_size());
        // The union should not have any duplicates

        let no_dup_prover_input = no_dup_check::NoDupCheckProverInput {
            col: input.col_union.clone(),
        };
        NoDupPIOP::prove(prover, no_dup_prover_input)?;

        let mgx = match (
            input.col_inter.activator_tracked_poly(),
            input.col_union.activator_tracked_poly(),
        ) {
            (Some(mgx), Some(ugx)) => Some(&mgx + &ugx),
            (Some(mgx), None) => Some(&mgx + F::one()),
            (None, Some(ugx)) => Some(&ugx + F::one()),
            (None, None) => Some(prover.track_mat_mv_poly(MLE::from_evaluations_vec(
                input.col_union.log_size(),
                vec![F::from(2); 1 << input.col_union.log_size()],
            ))),
        };

        let multiplicity_check_prover_input = MultiplicityCheckProverInput {
            fxs: vec![input.col_left.clone(), input.col_right.clone()],
            gxs: vec![input.col_union.clone()],
            mfxs: vec![None, None],
            mgxs: vec![mgx],
        };

        MultiplicityCheck::prove(prover, multiplicity_check_prover_input)?;

        let diff_poly = &input.col_union.data_tracked_poly() - &input.col_inter.data_tracked_poly();
        let zero_poly = match input.col_inter.activator_tracked_poly() {
            Some(p) => &p * &diff_poly,
            None => diff_poly,
        };
        prover.add_mv_zerocheck_claim(zero_poly.id())?;

        Ok(())
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<()> {
        assert_eq!(input.col_inter.log_size(), input.col_union.log_size());
        let no_dup_verifier_input = no_dup_check::NoDupCheckVerifierInput {
            tracked_col_oracle: input.col_union.clone(),
        };
        NoDupPIOP::verify(verifier, no_dup_verifier_input)?;
        let mgx = match (
            &input.col_inter.activator_tracked_oracle(),
            &input.col_union.activator_tracked_oracle(),
        ) {
            (Some(mgx), Some(ugx)) => Some(mgx + ugx),
            (Some(mgx), None) => Some(mgx + F::one()),
            (None, Some(ugx)) => Some(ugx + F::one()),
            (None, None) => Some(verifier.track_oracle(Oracle::new_multivariate(
                input.col_union.log_size(),
                move |_| Ok(F::from(2)),
            ))),
        };

        let multiplicity_check_verifier_input = MultiplicityCheckVerifierInput {
            fxs: vec![input.col_left.clone(), input.col_right.clone()],
            gxs: vec![input.col_union.clone()],
            mfxs: vec![None, None],
            mgxs: vec![mgx.clone()],
        };

        MultiplicityCheck::verify(verifier, multiplicity_check_verifier_input)?;

        let diff_poly =
            &input.col_union.data_tracked_oracle() - &input.col_inter.data_tracked_oracle();
        let zero_poly: TrackedOracle<F, MvPCS, UvPCS> =
            match input.col_inter.activator_tracked_oracle() {
                Some(p) => &p * &diff_poly,
                None => diff_poly,
            };
        verifier.add_zerocheck_claim(zero_poly.id());

        Ok(())
    }
}
