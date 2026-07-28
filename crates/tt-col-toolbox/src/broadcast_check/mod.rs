//! A PIOP for checking that a character-level column broadcasts a string-level
//! column, i.e. every character carries the value of its own string.
//!
//! Given `x` on the string domain and `x'` on the character domain, together
//! with `src` (character → owning-string index) and `ind` (string identity),
//! this PIOP proves `x'[c] = x[src[c]]` for every active character `c`.
//!
//! Following §4.3 of the TruthTable++ paper, the check is a single Lookup
//! Check on the fingerprinted pairs `(src[c], x'[c])` and `(ind[i], x[i])`:
//! sampling a challenge `r` collapses the pair into `src + r * x'` and
//! `ind + r * x`, and by Schwartz–Zippel `src + r * x' ⊑ ind + r * x` at a
//! random `r` forces `x'[c] = x[src[c]]` (the string identities `ind` being
//! distinct is a well-formedness precondition on the caller).
use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_piop::{
    SnarkBackend,
    errors::SnarkResult,
    piop::{DeepClone, PIOP},
    prover::ArgProver,
    verifier::ArgVerifier,
};
use derivative::Derivative;
use std::marker::PhantomData;

use crate::lookup::{LookupPIOP, LookupProverInput, LookupVerifierInput};

/// A PIOP for the broadcast relation `x'[c] = x[src[c]]`.
pub struct BroadcastCheckPIOP<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct BroadcastCheckProverInput<B: SnarkBackend> {
    /// String-level column `x` (one entry per string).
    pub str_col: TrackedCol<B>,
    /// Character-level column `x'` claimed to equal `x[src[·]]`.
    pub char_col: TrackedCol<B>,
    /// Character-level column `src`: index of the owning string per character.
    pub src_col: TrackedCol<B>,
    /// String-level column `ind`: distinct string identifier per string row.
    pub ind_col: TrackedCol<B>,
}

impl<B: SnarkBackend> DeepClone<B> for BroadcastCheckProverInput<B> {
    fn deep_clone(&self, prover: ArgProver<B>) -> Self {
        Self {
            str_col: self.str_col.deep_clone(prover.clone()),
            char_col: self.char_col.deep_clone(prover.clone()),
            src_col: self.src_col.deep_clone(prover.clone()),
            ind_col: self.ind_col.deep_clone(prover),
        }
    }
}

pub struct BroadcastCheckVerifierInput<B: SnarkBackend> {
    pub str_col_oracle: TrackedColOracle<B>,
    pub char_col_oracle: TrackedColOracle<B>,
    pub src_col_oracle: TrackedColOracle<B>,
    pub ind_col_oracle: TrackedColOracle<B>,
}

impl<B: SnarkBackend> PIOP<B> for BroadcastCheckPIOP<B> {
    type ProverInput = BroadcastCheckProverInput<B>;
    type ProverOutput = ();
    type VerifierInput = BroadcastCheckVerifierInput<B>;
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        use ark_ff::Zero;
        use ark_piop::{
            errors::SnarkError,
            prover::errors::{HonestProverError, ProverError},
        };
        use indexmap::IndexMap;

        let str_data = input.str_col.data_tracked_poly().evaluations();
        let str_act = input
            .str_col
            .activator_tracked_poly()
            .map(|a| a.evaluations());
        let ind_data = input.ind_col.data_tracked_poly().evaluations();

        // Build ind_value -> str_value over active string rows. Distinct `ind`
        // is a precondition; a duplicate here already breaks the relation.
        let mut ind_to_str: IndexMap<B::F, B::F> = IndexMap::with_capacity(str_data.len());
        for (i, (&ind_i, &x_i)) in ind_data.iter().zip(str_data.iter()).enumerate() {
            let active = str_act.as_ref().map(|a| !a[i].is_zero()).unwrap_or(true);
            if !active {
                continue;
            }
            if ind_to_str.insert(ind_i, x_i).is_some() {
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }

        let char_data = input.char_col.data_tracked_poly().evaluations();
        let char_act = input
            .char_col
            .activator_tracked_poly()
            .map(|a| a.evaluations());
        let src_data = input.src_col.data_tracked_poly().evaluations();

        for (c, (&x_prime_c, &src_c)) in char_data.iter().zip(src_data.iter()).enumerate() {
            let active = char_act.as_ref().map(|a| !a[c].is_zero()).unwrap_or(true);
            if !active {
                continue;
            }
            let expected = ind_to_str.get(&src_c).copied().unwrap_or_else(|| {
                // Encode "no matching string" as a mismatch below.
                x_prime_c + B::F::from(1u64)
            });
            if x_prime_c != expected {
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
        let r = prover.get_and_append_challenge(b"broadcast_check_r")?;

        // Fingerprint: char side `src + r * x'`, string side `ind + r * x`.
        // Each virtual data poly shares its side's activator so the Lookup
        // subroutine correctly restricts to active characters/strings.
        let looked_up_data = &input.src_col.data_tracked_poly()
            + &(input.char_col.data_tracked_poly() * r);
        let looked_up_col = TrackedCol::new(
            looked_up_data,
            input.char_col.activator_tracked_poly(),
            input.char_col.field_ref(),
        );

        let super_data = &input.ind_col.data_tracked_poly()
            + &(input.str_col.data_tracked_poly() * r);
        let super_col = TrackedCol::new(
            super_data,
            input.str_col.activator_tracked_poly(),
            input.str_col.field_ref(),
        );

        LookupPIOP::<B>::prove(
            prover,
            LookupProverInput {
                included_cols: vec![looked_up_col],
                super_col,
            },
        )?;
        Ok(())
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let r = verifier.get_and_append_challenge(b"broadcast_check_r")?;

        let looked_up_data = &input.src_col_oracle.data_tracked_oracle()
            + &(input.char_col_oracle.data_tracked_oracle() * r);
        let looked_up_oracle = TrackedColOracle::new(
            looked_up_data,
            input.char_col_oracle.activator_tracked_oracle(),
            input.char_col_oracle.field_ref(),
        );

        let super_data = &input.ind_col_oracle.data_tracked_oracle()
            + &(input.str_col_oracle.data_tracked_oracle() * r);
        let super_oracle = TrackedColOracle::new(
            super_data,
            input.str_col_oracle.activator_tracked_oracle(),
            input.str_col_oracle.field_ref(),
        );

        LookupPIOP::<B>::verify(
            verifier,
            LookupVerifierInput {
                included_tracked_col_oracles: vec![looked_up_oracle],
                super_tracked_col_oracle: super_oracle,
            },
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
