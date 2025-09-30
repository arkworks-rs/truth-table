//! A PIOP to check if two columns are a permutation of each other.
// More precisely, this PIOP checks if the activated elements of one column
// are a permutation of the activated elements of another column.
#[cfg(test)]
mod test;

use arithmetic::{col::ArithCol, col_oracle::ArithColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::Prover,
    verifier::Verifier,
};
use derivative::Derivative;
use std::marker::PhantomData;

use crate::multiplicity_check::{
    MultiplicityCheck, MultiplicityCheckProverInput, MultiplicityCheckVerifierInput,
};
use std::collections::BTreeMap;

// Convinces the verifier that
pub struct PermPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct PermPIOPProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub left_col: ArithCol<F, MvPCS, UvPCS>,
    pub right_col: ArithCol<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for PermPIOPProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            left_col: self.left_col.deep_clone(prover.clone()),
            right_col: self.right_col.deep_clone(prover),
        }
    }
}

pub struct PermPIOPVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub left_arith_col_oracle: ArithColOracle<F, MvPCS, UvPCS>,
    pub right_arith_col_oracle: ArithColOracle<F, MvPCS, UvPCS>,
}
impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for PermPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = PermPIOPProverInput<F, MvPCS, UvPCS>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = PermPIOPVerifierInput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        let mut bookkeeping_map: BTreeMap<F, isize> = BTreeMap::new();
        for elem in input.left_col.effective_iter() {
            *bookkeeping_map.entry(elem).or_insert(0) += 1;
        }
        for elem in input.right_col.effective_iter() {
            *bookkeeping_map.entry(elem).or_insert(-1) -= 1;
        }
        for (_, count) in bookkeeping_map.iter() {
            if *count != 0 {
                return Err(ark_piop::errors::SnarkError::ProverError(
                    ark_piop::prover::errors::ProverError::HonestProverError(
                        ark_piop::prover::errors::HonestProverError::FalseClaim,
                    ),
                ));
            }
        }

        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let multiplicity_check_prover_input = MultiplicityCheckProverInput {
            fxs: vec![input.left_col],
            gxs: vec![input.right_col],
            mfxs: vec![None],
            mgxs: vec![None],
        };

        MultiplicityCheck::<F, MvPCS, UvPCS>::prove(prover, multiplicity_check_prover_input)?;
        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let multiplicity_check_vierifier_input = MultiplicityCheckVerifierInput {
            fxs: vec![input.left_arith_col_oracle],
            gxs: vec![input.right_arith_col_oracle],
            mfxs: vec![None],
            mgxs: vec![None],
        };

        MultiplicityCheck::<F, MvPCS, UvPCS>::verify(verifier, multiplicity_check_vierifier_input)?;
        Ok(())
    }
}
