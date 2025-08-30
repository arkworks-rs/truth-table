//! A PIOP for checking that a column is the intersection of two columns with
//! no duplicates (set)

#[cfg(test)]
mod test;

use arithmetic::col::{ArithCol, ColCom};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{Prover, structs::TrackedPoly},
    structs::TrackerID,
    timed,
    verifier::{Verifier, structs::oracle::TrackedOracle},
};
use rayon::vec;
use std::marker::PhantomData;

use crate::{
    multiplicity_check::{
        MultiplicityCheck, MultiplicityCheckProverInput, MultiplicityCheckVerifierInput,
    },
    no_dup_check::{self, NoDupPIOP},
};

pub struct SetInterUnionCheckPIOP<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

pub struct SetInterUnionProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub col_left: ArithCol<F, MvPCS, UvPCS>,
    pub col_right: ArithCol<F, MvPCS, UvPCS>,
    pub col_inter: ArithCol<F, MvPCS, UvPCS>,
    pub col_union: ArithCol<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for SetInterUnionProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
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
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub col_left: ColCom<F, MvPCS, UvPCS>,
    pub col_right: ColCom<F, MvPCS, UvPCS>,
    pub col_inter: ColCom<F, MvPCS, UvPCS>,
    pub col_union: ColCom<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for SetInterUnionCheckPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = SetInterUnionProverInput<F, MvPCS, UvPCS>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = SetInterUnionVerifierInput<F, MvPCS, UvPCS>;

    #[timed]
    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        use crate::multiplicity_check::MultiplicityCheckProverInput;

        // TODO
        Ok(())
    }
    #[timed]
    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<()> {
        // The union and the intersections should be of the same size, bcause of how
        // this protocol works
        assert_eq!(
            input.col_inter.get_num_vars(),
            input.col_union.get_num_vars()
        );
        // The union should not have any duplicates

        NoDupPIOP::prove(prover, &input.col_union)?;

        let mgx = match (
            input.col_inter.get_actvtr_poly(),
            input.col_union.get_actvtr_poly(),
        ) {
            (Some(mgx), Some(ugx)) => Some(mgx.add_poly(ugx)),
            (Some(mgx), None) => Some(mgx.add_scalar(F::one())),
            (None, Some(ugx)) => Some(ugx.add_scalar(F::one())),
            (None, None) => None,
        };

        let multiplicity_check_prover_input = MultiplicityCheckProverInput {
            fxs: vec![input.col_left.clone(), input.col_right.clone()],
            gxs: vec![input.col_union.clone()],
            mfxs: vec![None, None],
            mgxs: vec![mgx],
        };

        MultiplicityCheck::prove(prover, multiplicity_check_prover_input)?;

        let diff_poly = input
            .col_union
            .get_data_poly()
            .sub_poly(input.col_inter.get_data_poly());
        let zero_poly = match input.col_inter.get_actvtr_poly() {
            Some(p) => p.mul_poly(&diff_poly),
            None => diff_poly,
        };
        prover.add_mv_zerocheck_claim(zero_poly.get_id())?;

        Ok(())
    }

    #[timed]
    fn verify(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<()> {
        assert_eq!(input.col_inter.num_vars, input.col_union.num_vars);
        NoDupPIOP::verify(verifier, &input.col_union)?;
        let mgx = match (&input.col_inter.actv, &input.col_union.actv) {
            (Some(mgx), Some(ugx)) => Some(mgx + ugx),
            (Some(mgx), None) => Some(mgx + F::one()),
            (None, Some(ugx)) => Some(ugx + F::one()),
            (None, None) => None,
        };

        let multiplicity_check_verifier_input = MultiplicityCheckVerifierInput {
            fxs: vec![input.col_left.clone(), input.col_right.clone()],
            gxs: vec![input.col_union.clone()],
            mfxs: vec![None, None],
            mgxs: vec![mgx],
        };
        MultiplicityCheck::verify(verifier, multiplicity_check_verifier_input)?;

        let diff_poly = &input.col_union.inner - &input.col_inter.inner;
        let zero_poly: TrackedOracle<F, MvPCS, UvPCS> = match input.col_inter.actv {
            Some(p) => &p * &diff_poly,
            None => diff_poly,
        };
        verifier.add_zerocheck_claim(zero_poly.id);

        Ok(())
    }
}
