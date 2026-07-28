//! A PIOP for checking that a character-level activator is consistent with a
//! string-level activator + length column.
//!
//! Given `src` (character → owning-string index) with char-level activator `ac`,
//! and `ind` (string identity) with string-level activator `ah` plus length
//! column `l`, this PIOP proves for every string row `i`:
//!
//!   #{ c : src[c] = ind[i] and ac[c] = 1 } = ah[i] · l[i]
//!
//! i.e. the number of active characters owned by string `i` equals its
//! stored length when active and zero when inactive.
//!
//! Following §4.2 of the TruthTable++ paper (PIOP 2), this reduces to a
//! single KeyedSumcheck on the pair
//!   L: key=src, val=1, activator=ac    (LHS: count active chars per src)
//!   R: key=ind, val=l, activator=ah    (RHS: string length gated by ah)
//! which, evaluated at a random `γ`, forces the two multiplicity vectors
//! (indexed by key) to agree row-wise via Schwartz–Zippel.
//!
//! `ind` is expected to be distinct across active string rows; that is a
//! well-formedness precondition on the caller (the natural instantiation
//! is the identity poly).
use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_piop::{
    SnarkBackend,
    errors::SnarkResult,
    piop::{DeepClone, PIOP},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};
use derivative::Derivative;
use std::marker::PhantomData;

use crate::keyed_sumcheck::{
    KeyedSumcheck, KeyedSumcheckProverInput, KeyedSumcheckVerifierInput,
};

/// A PIOP for the activator-consistency relation
/// `#{c : src[c] = i, ac[c] = 1} = ah[i] · l[i]`.
pub struct ActivatorConsistencyCheckPIOP<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct ActivatorConsistencyCheckProverInput<B: SnarkBackend> {
    /// Character-level column with `data = src`, `activator = ac`.
    pub src_col: TrackedCol<B>,
    /// String-level column with `data = ind`, `activator = ah`.
    pub ind_col: TrackedCol<B>,
    /// String-level length polynomial `l`.
    pub length_poly: TrackedPoly<B>,
}

impl<B: SnarkBackend> DeepClone<B> for ActivatorConsistencyCheckProverInput<B> {
    fn deep_clone(&self, prover: ArgProver<B>) -> Self {
        Self {
            src_col: self.src_col.deep_clone(prover.clone()),
            ind_col: self.ind_col.deep_clone(prover.clone()),
            length_poly: self.length_poly.deep_clone(prover),
        }
    }
}

pub struct ActivatorConsistencyCheckVerifierInput<B: SnarkBackend> {
    pub src_col_oracle: TrackedColOracle<B>,
    pub ind_col_oracle: TrackedColOracle<B>,
    pub length_oracle: TrackedOracle<B>,
}

impl<B: SnarkBackend> PIOP<B> for ActivatorConsistencyCheckPIOP<B> {
    type ProverInput = ActivatorConsistencyCheckProverInput<B>;
    type ProverOutput = ();
    type VerifierInput = ActivatorConsistencyCheckVerifierInput<B>;
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        use ark_ff::Zero;
        use ark_piop::{
            errors::SnarkError,
            prover::errors::{HonestProverError, ProverError},
        };
        use indexmap::IndexMap;

        let src_data = input.src_col.data_tracked_poly().evaluations();
        let src_act = input
            .src_col
            .activator_tracked_poly()
            .map(|a| a.evaluations());
        let ind_data = input.ind_col.data_tracked_poly().evaluations();
        let ind_act = input
            .ind_col
            .activator_tracked_poly()
            .map(|a| a.evaluations());
        let length_evals = input.length_poly.evaluations();

        // LHS: per src-key active-char count.
        let mut lhs_counts: IndexMap<B::F, u64> = IndexMap::with_capacity(src_data.len());
        for (c, &src_c) in src_data.iter().enumerate() {
            let active = src_act.as_ref().map(|a| !a[c].is_zero()).unwrap_or(true);
            if !active {
                continue;
            }
            *lhs_counts.entry(src_c).or_insert(0) += 1;
        }

        // RHS: per ind-key expected count (l[i] when ah[i]=1, 0 otherwise).
        // Collect duplicates by summing, mirroring what KeyedSumcheck aggregates.
        let mut rhs_counts: IndexMap<B::F, B::F> = IndexMap::with_capacity(ind_data.len());
        for (i, (&ind_i, &l_i)) in ind_data.iter().zip(length_evals.iter()).enumerate() {
            let active = ind_act.as_ref().map(|a| !a[i].is_zero()).unwrap_or(true);
            if !active {
                continue;
            }
            let entry = rhs_counts.entry(ind_i).or_insert_with(B::F::zero);
            *entry += l_i;
        }

        // Compare: every key present on either side must have equal counts.
        // (The KeyedSumcheck it reduces to only sees these aggregate values.)
        let all_keys: indexmap::IndexSet<B::F> = lhs_counts
            .keys()
            .chain(rhs_counts.keys())
            .copied()
            .collect();
        for key in all_keys {
            let lhs = B::F::from(*lhs_counts.get(&key).unwrap_or(&0));
            let rhs = *rhs_counts.get(&key).unwrap_or(&B::F::zero());
            if lhs != rhs {
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }
        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<B>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        // L side: key=src, multiplicity=1 (None), activator carried by src_col.
        // R side: key=ind, multiplicity=length, activator carried by ind_col.
        KeyedSumcheck::<B>::prove(
            prover,
            KeyedSumcheckProverInput {
                fxs: vec![input.src_col],
                gxs: vec![input.ind_col],
                mfxs: vec![None],
                mgxs: vec![Some(input.length_poly)],
            },
        )?;
        Ok(())
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        KeyedSumcheck::<B>::verify(
            verifier,
            KeyedSumcheckVerifierInput {
                fxs: vec![input.src_col_oracle],
                gxs: vec![input.ind_col_oracle],
                mfxs: vec![None],
                mgxs: vec![Some(input.length_oracle)],
            },
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
