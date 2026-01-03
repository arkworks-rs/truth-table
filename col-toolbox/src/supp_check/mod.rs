//! A PIOP for checking if a column is a support of another column
//!
//! More precisely, this PIOP checks if the activated elements of a column
//! are the support of another column's activated elements, meaning it has all
//! the elements but deduplicated.

#[cfg(test)]
mod test;

use super::no_dup_check::NoDupPIOP;
use crate::{
    lookup::{
        HintedLookupPIOP, HintedLookupProverInput,
        HintedLookupVerifierInput, utils::calc_inclusion_multiplicity,
    },
    no_dup_check::{NoDupCheckProverInput, NoDupCheckVerifierInput},
    no_zeros_check::{NoZerosCheck, NoZerosCheckProverInput, NoZerosCheckVerifierInput},
};

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_piop::{
    SnarkBackend,
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};
use derivative::Derivative;
use std::marker::PhantomData;

pub struct HintedSuppCheckPIOP<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct HintedSuppCheckProverInput<B: SnarkBackend> {
    pub col: TrackedCol<B>,
    pub supp: TrackedCol<B>,
    pub multiplicity: TrackedPoly<B>,
}

impl<B: SnarkBackend> DeepClone<B> for HintedSuppCheckProverInput<B> {
    fn deep_clone(&self, new_prover: ArgProver<B>) -> Self {
        HintedSuppCheckProverInput {
            col: self.col.deep_clone(new_prover.clone()),
            supp: self.supp.deep_clone(new_prover.clone()),
            multiplicity: self.multiplicity.deep_clone(new_prover),
        }
    }
}

pub struct HintedSuppCheckVerifierInput<B: SnarkBackend> {
    pub col: TrackedColOracle<B>,
    pub supp: TrackedColOracle<B>,
    pub multiplicity: TrackedOracle<B>,
}

pub struct SuppCheckPIOP<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);
#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct SuppCheckProverInput<B: SnarkBackend> {
    pub col: TrackedCol<B>,
    pub supp: TrackedCol<B>,
}

impl<B: SnarkBackend> DeepClone<B> for SuppCheckProverInput<B> {
    fn deep_clone(&self, new_prover: ArgProver<B>) -> Self {
        SuppCheckProverInput {
            col: self.col.deep_clone(new_prover.clone()),
            supp: self.supp.deep_clone(new_prover),
        }
    }
}

pub struct SuppCheckVerifierInput<B: SnarkBackend> {
    pub col: TrackedColOracle<B>,
    pub supp: TrackedColOracle<B>,
}

pub struct SuppCheckProverOutput<B: SnarkBackend> {
    pub super_set_multiplicity_tr_p: TrackedPoly<B>,
}

pub struct SuppCheckVerifierOutput<B: SnarkBackend> {
    pub super_set_multiplicity_tr_com: TrackedOracle<B>,
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
impl<B: SnarkBackend> PIOP<B> for HintedSuppCheckPIOP<B> {
    type ProverInput = HintedSuppCheckProverInput<B>;
    type VerifierInput = HintedSuppCheckVerifierInput<B>;
    type ProverOutput = ();
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        use std::collections::BTreeMap;

        let mut bookkeeping_map: BTreeMap<B::F, isize> = BTreeMap::new();
        for elem in input.supp.effective_iter() {
            *bookkeeping_map.entry(elem).or_insert(0) += 1;
        }
        for key in bookkeeping_map.keys() {
            if *bookkeeping_map.get(key).unwrap() != 1 {
                use ark_piop::errors::SnarkError;
                use ark_piop::prover::errors::HonestProverError;
                use ark_piop::prover::errors::ProverError;
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
                use ark_piop::{
                    errors::SnarkError,
                    prover::errors::{HonestProverError, ProverError},
                };

                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }

        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<B>,
        prover_input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let hinted_lookup_prover_input = HintedLookupProverInput {
            included_cols: vec![prover_input.col.clone()],
            super_col: prover_input.supp.clone(),
            super_col_multiplicities: vec![prover_input.multiplicity.clone()],
        };

        HintedLookupPIOP::<B>::prove(prover, hinted_lookup_prover_input)?;

        let supp_no_dups_checker = TrackedCol::new(
            prover_input.multiplicity.clone(),
            prover_input.supp.activator_tracked_poly(),
            None,
        );
        let no_zeros_check_prover_input = NoZerosCheckProverInput {
            col: supp_no_dups_checker,
        };
        NoZerosCheck::<B>::prove(prover, no_zeros_check_prover_input)?;
        let no_dup_prover_input = NoDupCheckProverInput {
            col: prover_input.supp.clone(),
        };
        NoDupPIOP::<B>::prove(prover, no_dup_prover_input)?;
        Ok(())
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        verifier_input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let hinted_lookup_verifier_input = HintedLookupVerifierInput {
            included_tracked_col_oracles: vec![verifier_input.col.clone()],
            super_tracked_col_oracle: verifier_input.supp.clone(),
            super_col_multiplicities: vec![verifier_input.multiplicity.clone()],
        };

        HintedLookupPIOP::<B>::verify(verifier, hinted_lookup_verifier_input)?;

        let supp_no_dups_checker = TrackedColOracle::new(
            verifier_input.multiplicity.clone(),
            verifier_input.supp.activator_tracked_oracle(),
            None,
        );
        let no_zeros_check_verifier_input = NoZerosCheckVerifierInput {
            tracked_col_oracle: supp_no_dups_checker,
        };
        NoZerosCheck::<B>::verify(verifier, no_zeros_check_verifier_input)?;
        let no_dup_verifier_input = NoDupCheckVerifierInput {
            tracked_col_oracle: verifier_input.supp.clone(),
        };
        NoDupPIOP::<B>::verify(verifier, no_dup_verifier_input)?;

        Ok(())
    }
}

impl<B: SnarkBackend> PIOP<B> for SuppCheckPIOP<B> {
    type ProverInput = SuppCheckProverInput<B>;
    type VerifierInput = SuppCheckVerifierInput<B>;
    type ProverOutput = SuppCheckProverOutput<B>;
    type VerifierOutput = SuppCheckVerifierOutput<B>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        use std::collections::BTreeMap;

        let mut bookkeeping_map: BTreeMap<B::F, isize> = BTreeMap::new();
        for elem in input.supp.effective_iter() {
            *bookkeeping_map.entry(elem).or_insert(0) += 1;
        }
        for key in bookkeeping_map.keys() {
            if *bookkeeping_map.get(key).unwrap() != 1 {
                use ark_piop::{
                    errors::SnarkError,
                    prover::errors::{HonestProverError, ProverError},
                };

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
                use ark_piop::{
                    errors::SnarkError,
                    prover::errors::{HonestProverError, ProverError},
                };

                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }

        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<B>,
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

        HintedSuppCheckPIOP::<B>::prove(prover, hinted_supp_check_prover_input)?;

        Ok(SuppCheckProverOutput {
            super_set_multiplicity_tr_p,
        })
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
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
        HintedSuppCheckPIOP::<B>::verify(verifier, hinted_supp_check_verifier_input)?;

        Ok(SuppCheckVerifierOutput {
            super_set_multiplicity_tr_com,
        })
    }
}
