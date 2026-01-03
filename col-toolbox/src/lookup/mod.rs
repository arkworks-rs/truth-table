//! A PIOP for checing if a column is included in another column
/// More precisely, it checks if the activated elements of a column is included
/// in another column. Internally, this PIOP invokes the `KeyedSumcheck`
/// with the multiplicity polynomial of all 1 for the 'included_col' and a
/// computed advice multiplicity for 'super_col'#[cfg(test)]
#[cfg(test)]
mod test;
pub(crate) mod utils;
use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::One;
use ark_ff::PrimeField;
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{
        ArgVerifier,
        structs::oracle::{Oracle, TrackedOracle},
    },
};
use derivative::Derivative;
use std::marker::PhantomData;
use utils::calc_inclusion_multiplicity;

use crate::keyed_sumcheck::{KeyedSumcheck, KeyedSumcheckProverInput, KeyedSumcheckVerifierInput};

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct HintedLookupProverInput<B: SnarkBackend> {
    pub included_cols: Vec<TrackedCol<B>>,
    pub super_col: TrackedCol<B>,
    pub super_col_multiplicities: Vec<TrackedPoly<B>>,
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
            super_col_multiplicities: self
                .super_col_multiplicities
                .iter()
                .map(|poly| poly.deep_clone(prover.clone()))
                .collect(),
        }
    }
}

pub struct HintedLookupVerifierInput<B: SnarkBackend> {
    pub included_tracked_col_oracles: Vec<TrackedColOracle<B>>,
    pub super_tracked_col_oracle: TrackedColOracle<B>,
    pub super_col_multiplicities: Vec<TrackedOracle<B>>,
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
    pub super_col_ms: Vec<TrackedPoly<B>>,
}

pub struct LookupVerifierInput<B: SnarkBackend> {
    pub included_tracked_col_oracles: Vec<TrackedColOracle<B>>,
    pub super_tracked_col_oracle: TrackedColOracle<B>,
}

pub struct LookupVerifierOutput<B: SnarkBackend> {
    pub super_col_m_comms: Vec<TrackedOracle<B>>,
}

pub struct LookupPIOP<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

impl<B: SnarkBackend> PIOP<B> for HintedLookupPIOP<B> {
    type ProverInput = HintedLookupProverInput<B>;
    type VerifierInput = HintedLookupVerifierInput<B>;
    type ProverOutput = ();
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        use std::collections::HashSet;

        use ark_piop::{
            errors::SnarkError,
            prover::errors::{HonestProverError, ProverError},
        };

        let super_col_hash_set: HashSet<B::F> = input.super_col.effective_hashset();
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
        assert_eq!(
            input.included_cols.len(),
            input.super_col_multiplicities.len(),
            "super column multiplicity hints must align with included columns"
        );
        let included_col_ms = input
            .included_cols
            .iter()
            .map(|included_col| {
                let nv = included_col.log_size();
                let one_const_mle =
                    MLE::from_evaluations_vec(nv, vec![B::F::one(); 2_usize.pow(nv as u32)]);
                Some(prover.track_mat_mv_poly(one_const_mle))
            })
            .collect::<Vec<_>>();

        let keyed_sumcheck_prover_input = KeyedSumcheckProverInput {
            fxs: input.included_cols.clone(),
            gxs: vec![input.super_col.clone()],
            mfxs: included_col_ms,
            mgxs: input
                .super_col_multiplicities
                .iter()
                .cloned()
                .map(Some)
                .collect(),
        };

        KeyedSumcheck::<B>::prove(prover, keyed_sumcheck_prover_input)?;

        Ok(())
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        assert_eq!(
            input.included_tracked_col_oracles.len(),
            input.super_col_multiplicities.len(),
            "super column multiplicity hints must align with included column oracles"
        );
        let included_col_ms = input
            .included_tracked_col_oracles
            .iter()
            .map(|included_col| {
                let nv = included_col.log_size();
                let one_closure = |_: Vec<B::F>| -> SnarkResult<B::F> { Ok(B::F::one()) };
                Some(verifier.track_oracle(Oracle::new_multivariate(nv, one_closure)))
            })
            .collect::<Vec<_>>();

        let keyed_sumcheck_verifier_input = KeyedSumcheckVerifierInput {
            fxs: input.included_tracked_col_oracles.clone(),
            gxs: vec![input.super_tracked_col_oracle.clone()],
            mfxs: included_col_ms,
            mgxs: input
                .super_col_multiplicities
                .iter()
                .cloned()
                .map(Some)
                .collect(),
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
        use std::collections::HashSet;

        use ark_piop::{
            errors::SnarkError,
            prover::errors::{HonestProverError, ProverError},
        };

        let super_col_hash_set: HashSet<B::F> = input.super_col.effective_hashset();
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
        let super_col_m_mles = input
            .included_cols
            .iter()
            .map(|included_col| calc_inclusion_multiplicity(included_col, &input.super_col))
            .collect::<Vec<_>>();
        let super_col_ms = super_col_m_mles
            .iter()
            .map(|mle| prover.track_and_commit_mat_mv_poly(mle))
            .collect::<SnarkResult<Vec<_>>>()?;

        let hinted_lookup_prover_input = HintedLookupProverInput {
            included_cols: input.included_cols,
            super_col: input.super_col,
            super_col_multiplicities: super_col_ms.clone(),
        };
        HintedLookupPIOP::<B>::prove(prover, hinted_lookup_prover_input)?;
        Ok(LookupProverOutput { super_col_ms })
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let super_col_m_comms = input
            .included_tracked_col_oracles
            .iter()
            .map(|_| {
                let id = verifier.peek_next_id();
                verifier.track_mv_com_by_id(id)
            })
            .collect::<SnarkResult<Vec<_>>>()?;

        let hinted_lookup_verifier_input = HintedLookupVerifierInput {
            included_tracked_col_oracles: input.included_tracked_col_oracles,
            super_tracked_col_oracle: input.super_tracked_col_oracle,
            super_col_multiplicities: super_col_m_comms.clone(),
        };
        HintedLookupPIOP::<B>::verify(verifier, hinted_lookup_verifier_input)?;
        Ok(LookupVerifierOutput { super_col_m_comms })
    }
}
