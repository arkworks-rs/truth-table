#[cfg(test)]
mod test;

use arithmetic::{
    col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
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
    transcript::Tr,
    verifier::{
        Verifier,
        structs::oracle::{InnerOracle, TrackedOracle},
    },
};
use derivative::Derivative;
use std::{cmp::Ordering, marker::PhantomData};

use crate::{
    contig_lex_sort_check::{ContigLexSortCheckPIOP, ContigLexSortCheckProverInput}, perm_check::{PermPIOP, PermPIOPProverInput}, predicate_limit_check::{PredicateLimitCheck, PredicateLimitCheckProverInput}, prescribed_permutation_check::{
        PrescribedPermutationPIOP, PrescribedPermutationPIOPProverInput,
        PrescribedPermutationPIOPVerifierInput, shift_permutation_mle, shift_permutation_oracle,
    }, sign_check::{SignCheckPIOP, SignCheckProverInput, SignCheckVerifierInput}
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
        // TODO
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let challenges = (0..input.tracked_table.num_data_tracked_cols())
            .map(|_| prover.get_and_append_challenge(b"fold").unwrap())
            .collect::<Vec<_>>();
        let tracked_table_folded_col = input.tracked_table.fold_all_data_columns(&challenges);
        let contig_lex_sorted_tracked_table_folded_col = input
            .contig_lex_sorted_tracked_table
            .fold_all_data_columns(&challenges);
        let perm_piop_prover_input = PermPIOPProverInput {
            left_col: tracked_table_folded_col,
            right_col: contig_lex_sorted_tracked_table_folded_col,
        };
        PermPIOP::<F, MvPCS, UvPCS>::prove(prover, perm_piop_prover_input)?;
        

        let contig_lex_sort_check_prover_input = ContigLexSortCheckProverInput {
            tracked_table: todo!(),
            tie_indicator_tracked_polys: todo!(),
            shift_tracked_table: todo!(),
            ascending: todo!(),
            strict: todo!(),
        };
        ContigLexSortCheckPIOP::<F, MvPCS, UvPCS>::prove(
            prover,
            contig_lex_sort_check_prover_input,
        )?;
        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        Ok(())
    }
}
