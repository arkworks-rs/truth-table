//! A PIOP for checking if a column is a support of another column
//!
//! More precisely, this PIOP checks if the activated elements of a column
//! are the support of another column's activated elements, meaning it has all
//! the elements but deduplicated.

#[cfg(test)]
mod test;
pub(crate) mod utils;

use super::no_dup_check::NoDupPIOP;
use crate::{
    inclusion_check::{
        HintedInclusionCheckPIOP, HintedInclusionCheckProverInput,
        HintedInclusionCheckVerifierInput, InclusionCheckPIOP, utils::calc_inclusion_multiplicity,
    },
    no_dup_check::{NoDupCheckProverInput, NoDupCheckVerifierInput},
    no_zeros_check::{NoZerosCheck, NoZerosCheckProverInput, NoZerosCheckVerifierInput},
};
use std::{collections::BTreeMap, hint};

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{SnarkError, SnarkResult},
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{
        Prover,
        errors::{HonestProverError, ProverError},
        structs::polynomial::TrackedPoly,
    },
    verifier::{Verifier, structs::oracle::TrackedOracle},
};
use derivative::Derivative;
use std::marker::PhantomData;

pub struct HintedSuppCheckPIOP<
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
pub struct HintedSuppCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub col: TrackedCol<F, MvPCS, UvPCS>,
    pub supp: TrackedCol<F, MvPCS, UvPCS>,
    pub multiplicity: TrackedPoly<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for HintedSuppCheckProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, new_prover: Prover<F, MvPCS, UvPCS>) -> Self {
        HintedSuppCheckProverInput {
            col: self.col.deep_clone(new_prover.clone()),
            supp: self.supp.deep_clone(new_prover.clone()),
            multiplicity: self.multiplicity.deep_clone(new_prover),
        }
    }
}

pub struct HintedSuppCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub col: TrackedColOracle<F, MvPCS, UvPCS>,
    pub supp: TrackedColOracle<F, MvPCS, UvPCS>,
    pub multiplicity: TrackedOracle<F, MvPCS, UvPCS>,
}

pub struct SuppCheckPIOP<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);
#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct SuppCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub col: TrackedCol<F, MvPCS, UvPCS>,
    pub supp: TrackedCol<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for SuppCheckProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, new_prover: Prover<F, MvPCS, UvPCS>) -> Self {
        SuppCheckProverInput {
            col: self.col.deep_clone(new_prover.clone()),
            supp: self.supp.deep_clone(new_prover),
        }
    }
}

pub struct SuppCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub col: TrackedColOracle<F, MvPCS, UvPCS>,
    pub supp: TrackedColOracle<F, MvPCS, UvPCS>,
}

pub struct SuppCheckProverOutput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub super_set_multiplicity_tr_p: TrackedPoly<F, MvPCS, UvPCS>,
}

pub struct SuppCheckVerifierOutput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub super_set_multiplicity_tr_com: TrackedOracle<F, MvPCS, UvPCS>,
}

// TODO: The range_col should be static and globally available to all PIOPs

/// A PIOP to prove that a column is a suport of another column, i.e. has all
/// the elements but deduplicated
///
/// It 1st: shows that support is included in the column with a certain
/// multiplicity, 2nd: shows that this multiplicity is all non-zero, 3rd: shows
/// that there is no duplicate in the support (The best way we know to do this
/// is to show that it's strictly sorted)
/// IMPORTANT: The supp column should be sorted
impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for HintedSuppCheckPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = HintedSuppCheckProverInput<F, MvPCS, UvPCS>;
    type VerifierInput = HintedSuppCheckVerifierInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        let mut bookkeeping_map: BTreeMap<F, isize> = BTreeMap::new();
        for elem in input.supp.effective_iter() {
            *bookkeeping_map.entry(elem).or_insert(0) += 1;
        }
        for key in bookkeeping_map.keys() {
            if *bookkeeping_map.get(key).unwrap() != 1 {
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }
        for elem in input.col.effective_hashset().iter() {
            *bookkeeping_map.entry(*elem).or_insert(-1) -= 1;
        }
        for (_, count) in bookkeeping_map.iter() {
            if *count != 0 {
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }

        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        prover_input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let hinted_inclusion_check_prover_input = HintedInclusionCheckProverInput {
            included_cols: vec![prover_input.col.clone()],
            super_col: prover_input.supp.clone(),
            super_col_multiplicities: vec![prover_input.multiplicity.clone()],
        };

        HintedInclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(
            prover,
            hinted_inclusion_check_prover_input,
        )?;

        let supp_no_dups_checker = TrackedCol::new(
            prover_input.multiplicity.clone(),
            prover_input.supp.activator_tracked_poly(),
            None,
        );
        let no_zeros_check_prover_input = NoZerosCheckProverInput {
            col: supp_no_dups_checker,
        };
        NoZerosCheck::<F, MvPCS, UvPCS>::prove(prover, no_zeros_check_prover_input)?;
        let no_dup_prover_input = NoDupCheckProverInput {
            col: prover_input.supp.clone(),
        };
        NoDupPIOP::<F, MvPCS, UvPCS>::prove(prover, no_dup_prover_input)?;
        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        verifier_input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let hinted_inclusion_check_verifier_input = HintedInclusionCheckVerifierInput {
            included_tracked_col_oracles: vec![verifier_input.col.clone()],
            super_tracked_col_oracle: verifier_input.supp.clone(),
            super_col_multiplicities: vec![verifier_input.multiplicity.clone()],
        };

        HintedInclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(
            verifier,
            hinted_inclusion_check_verifier_input,
        )?;

        let supp_no_dups_checker = TrackedColOracle::new(
            verifier_input.multiplicity.clone(),
            verifier_input.supp.activator_tracked_oracle(),
            None,
        );
        let no_zeros_check_verifier_input = NoZerosCheckVerifierInput {
            tracked_col_oracle: supp_no_dups_checker,
        };
        NoZerosCheck::<F, MvPCS, UvPCS>::verify(verifier, no_zeros_check_verifier_input)?;
        let no_dup_verifier_input = NoDupCheckVerifierInput {
            tracked_col_oracle: verifier_input.supp.clone(),
        };
        NoDupPIOP::<F, MvPCS, UvPCS>::verify(verifier, no_dup_verifier_input)?;

        Ok(())
    }
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for SuppCheckPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = SuppCheckProverInput<F, MvPCS, UvPCS>;
    type VerifierInput = SuppCheckVerifierInput<F, MvPCS, UvPCS>;
    type ProverOutput = SuppCheckProverOutput<F, MvPCS, UvPCS>;
    type VerifierOutput = SuppCheckVerifierOutput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        let mut bookkeeping_map: BTreeMap<F, isize> = BTreeMap::new();
        for elem in input.supp.effective_iter() {
            *bookkeeping_map.entry(elem).or_insert(0) += 1;
        }
        for key in bookkeeping_map.keys() {
            if *bookkeeping_map.get(key).unwrap() != 1 {
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }
        for elem in input.col.effective_hashset().iter() {
            *bookkeeping_map.entry(*elem).or_insert(-1) -= 1;
        }
        for (_, count) in bookkeeping_map.iter() {
            if *count != 0 {
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }

        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        prover_input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let super_set_multiplicity_p =
            calc_inclusion_multiplicity(&prover_input.col, &prover_input.supp);

        let super_set_multiplicity_tr_p =
            prover.track_and_commit_mat_mv_poly(&super_set_multiplicity_p)?;

        let hinted_supp_check_prover_input = HintedSuppCheckProverInput {
            col: prover_input.col,
            supp: prover_input.supp,
            multiplicity: super_set_multiplicity_tr_p.clone(),
        };

        HintedSuppCheckPIOP::<F, MvPCS, UvPCS>::prove(prover, hinted_supp_check_prover_input)?;

        Ok(SuppCheckProverOutput {
            super_set_multiplicity_tr_p,
        })
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        verifier_input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let super_set_multiplicity_com_id = verifier.peek_next_id();
        let super_set_multiplicity_tr_com =
            verifier.track_mv_com_by_id(super_set_multiplicity_com_id)?;

        let hinted_supp_check_verifier_input = HintedSuppCheckVerifierInput {
            col: verifier_input.col,
            supp: verifier_input.supp,
            multiplicity: super_set_multiplicity_tr_com.clone(),
        };
        HintedSuppCheckPIOP::<F, MvPCS, UvPCS>::verify(verifier, hinted_supp_check_verifier_input)?;

        Ok(SuppCheckVerifierOutput {
            super_set_multiplicity_tr_com,
        })
    }
}
