//! A PIOP for checking that the activated elements of one or more columns are
//! included in another column. It invokes the `KeyedSumcheck` with every
//! active row of every included column counted once, against one advice
//! multiplicity for `super_col`: the count over all included columns
//! together.
mod multiplicity_count;
pub(crate) mod utils;
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
use utils::calc_inclusion_multiplicity;

use crate::irs::nodes::utils::keyed_sumcheck::piop::{
    KeyedSumcheck, KeyedSumcheckProverInput, KeyedSumcheckVerifierInput,
};

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct HintedLookupProverInput<B: SnarkBackend> {
    pub included_cols: Vec<TrackedCol<B>>,
    pub super_col: TrackedCol<B>,
    pub super_col_multiplicity: TrackedPoly<B>,
}

impl<B: SnarkBackend> DeepClone<B> for HintedLookupProverInput<B> {
    fn deep_clone(&self, prover: ArgProver<B>) -> Self {
        Self {
            included_cols: self
                .included_cols
                .iter()
                .map(|c| c.deep_clone(prover.clone()))
                .collect(),
            super_col: self.super_col.deep_clone(prover.clone()),
            super_col_multiplicity: self.super_col_multiplicity.deep_clone(prover),
        }
    }
}

pub struct HintedLookupVerifierInput<B: SnarkBackend> {
    pub included_tracked_col_oracles: Vec<TrackedColOracle<B>>,
    pub super_tracked_col_oracle: TrackedColOracle<B>,
    pub super_col_multiplicity: TrackedOracle<B>,
}

pub struct HintedLookupPIOP<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct LookupProverInput<B: SnarkBackend> {
    pub included_cols: Vec<TrackedCol<B>>,
    pub super_col: TrackedCol<B>,
}

impl<B: SnarkBackend> DeepClone<B> for LookupProverInput<B> {
    fn deep_clone(&self, prover: ArgProver<B>) -> Self {
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

pub struct LookupProverOutput<B: SnarkBackend> {
    pub super_col_m: TrackedPoly<B>,
}

pub struct LookupVerifierInput<B: SnarkBackend> {
    pub included_tracked_col_oracles: Vec<TrackedColOracle<B>>,
    pub super_tracked_col_oracle: TrackedColOracle<B>,
}

pub struct LookupVerifierOutput<B: SnarkBackend> {
    pub super_col_m_comm: TrackedOracle<B>,
}

pub struct LookupPIOP<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

impl<B: SnarkBackend> PIOP<B> for HintedLookupPIOP<B> {
    type ProverInput = HintedLookupProverInput<B>;
    type VerifierInput = HintedLookupVerifierInput<B>;
    type ProverOutput = ();
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        use indexmap::IndexSet;

        use ark_piop::{
            errors::SnarkError,
            prover::errors::{HonestProverError, ProverError},
        };

        let super_col_hash_set: IndexSet<B::F> = input.super_col.effective_hashset();
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
        prover: &mut ArgProver<B>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        // Every active row of an included column counts once: no
        // multiplicity, the activator alone is the numerator.
        let keyed_sumcheck_prover_input = KeyedSumcheckProverInput {
            mfxs: vec![None; input.included_cols.len()],
            fxs: input.included_cols,
            gxs: vec![input.super_col],
            mgxs: vec![Some(input.super_col_multiplicity)],
        };

        KeyedSumcheck::<B>::prove(prover, keyed_sumcheck_prover_input)?;

        Ok(())
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let keyed_sumcheck_verifier_input = KeyedSumcheckVerifierInput {
            mfxs: vec![None; input.included_tracked_col_oracles.len()],
            fxs: input.included_tracked_col_oracles,
            gxs: vec![input.super_tracked_col_oracle],
            mgxs: vec![Some(input.super_col_multiplicity)],
        };
        KeyedSumcheck::<B>::verify(verifier, keyed_sumcheck_verifier_input)?;
        Ok(())
    }
}

impl<B: SnarkBackend> PIOP<B> for LookupPIOP<B> {
    type ProverInput = LookupProverInput<B>;

    type ProverOutput = LookupProverOutput<B>;

    type VerifierOutput = LookupVerifierOutput<B>;

    type VerifierInput = LookupVerifierInput<B>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        use indexmap::IndexSet;

        use ark_piop::{
            errors::SnarkError,
            prover::errors::{HonestProverError, ProverError},
        };

        let super_col_hash_set: IndexSet<B::F> = input.super_col.effective_hashset();
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
        prover: &mut ArgProver<B>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let super_col_m = prover.track_and_commit_mat_mv_poly(&calc_inclusion_multiplicity(
            &input.included_cols,
            &input.super_col,
        ))?;
        let hinted_lookup_prover_input = HintedLookupProverInput {
            included_cols: input.included_cols,
            super_col: input.super_col,
            super_col_multiplicity: super_col_m.clone(),
        };
        HintedLookupPIOP::<B>::prove(prover, hinted_lookup_prover_input)?;
        Ok(LookupProverOutput { super_col_m })
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let super_col_m_comm = verifier.track_next_mv_com()?;
        let hinted_lookup_verifier_input = HintedLookupVerifierInput {
            included_tracked_col_oracles: input.included_tracked_col_oracles,
            super_tracked_col_oracle: input.super_tracked_col_oracle,
            super_col_multiplicity: super_col_m_comm.clone(),
        };
        HintedLookupPIOP::<B>::verify(verifier, hinted_lookup_verifier_input)?;
        Ok(LookupVerifierOutput { super_col_m_comm })
    }
}

#[cfg(test)]
mod tests;
