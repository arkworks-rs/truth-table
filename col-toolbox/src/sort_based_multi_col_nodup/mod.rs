
#[cfg(test)]
mod test;

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{SnarkError::ProverError, SnarkResult},
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{
        Prover,
        errors::{HonestProverError::FalseClaim, ProverError::HonestProverError},
        structs::polynomial::TrackedPoly,
    },
    verifier::{
        Verifier,
        structs::oracle::{InnerOracle, TrackedOracle},
    },
};
use derivative::Derivative;
use std::{cmp::Ordering, marker::PhantomData};

use crate::{
    predicate_limit_check::{PredicateLimitCheck, PredicateLimitCheckProverInput},
    prescribed_permutation_check::{
        PrescribedPermutationPIOP, PrescribedPermutationPIOPProverInput,
        PrescribedPermutationPIOPVerifierInput, shift_permutation_mle, shift_permutation_oracle,
    },
    sign_check::{SignCheckPIOP, SignCheckProverInput, SignCheckVerifierInput},
};
// Convinces the verifier that
pub struct SortBasedMultiNoDup<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct SortBasedMultiNoDupProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub tracked_table: TrackedTable<F, MvPCS, UvPCS>,
    pub contig_lex_sorted_tracked_table: TrackedTable<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for SortBasedMultiNoDupProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            tracked_table: self.tracked_table.deep_clone(prover.clone()),
            contig_lex_sorted_tracked_table: self
                .contig_lex_sorted_tracked_table
                .deep_clone(prover),
        }
    }
}

pub struct SortBasedMultiNoDupVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub contig_lex_sorted_tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>, 
}
impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for SortBasedMultiNoDup<F, MvPCS, UvPCS>
{
    type ProverInput = SortBasedMultiNoDupProverInput<F, MvPCS, UvPCS>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = SortBasedMultiNoDupVerifierInput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        //TODO
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        
        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        Ok(())
    }
}