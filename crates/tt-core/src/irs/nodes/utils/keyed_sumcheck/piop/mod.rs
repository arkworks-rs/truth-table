//! A PIOP to check if the multisets of two sets of columns are equal
//! considering their multiplicities.
//!
//! More precisely, this PIOP checks that the union of the multisets of the
//! activated elements in a set of columns, each under a multiplicity
//! polynomial, equals the union for another set of columns under other
//! multiplicity polynomials:
//!
//! `sum_i sum_x mf_i(x) * Af_i(x) / (f_i(x) - gamma)
//!     = sum_j sum_x mg_j(x) * Ag_j(x) / (g_j(x) - gamma)`.
//!
//! It is a generalization of the [LogUp](https://eprint.iacr.org/2022/1530.pdf)
//! protocol and is heavily used throughout the other PIOPs.
//!
//! The protocol itself lives in ark-piop
//! ([`ark_piop::piop::keyed_sumcheck`]). This module only says what a
//! column with an activator means there: the column's data is the key, and
//! its activator multiplies the multiplicity. The claim is recorded with
//! [`ArgProver::add_mv_keyed_sum_claim`] and discharged when the proof is
//! built, in one batch with every other keyed sum and lookup of the proof,
//! so both sides have to claim in the same order.

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_piop::{
    SnarkBackend,
    errors::SnarkResult,
    piop::{DeepClone, PIOP, keyed_sumcheck as ark_keyed_sumcheck},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};
use derivative::Derivative;
use std::marker::PhantomData;
pub struct KeyedSumcheck<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct KeyedSumcheckProverInput<B: SnarkBackend> {
    pub fxs: Vec<TrackedCol<B>>,
    pub gxs: Vec<TrackedCol<B>>,
    pub mfxs: Vec<Option<TrackedPoly<B>>>,
    pub mgxs: Vec<Option<TrackedPoly<B>>>,
}

pub struct KeyedSumcheckVerifierInput<B: SnarkBackend> {
    pub fxs: Vec<TrackedColOracle<B>>,
    pub gxs: Vec<TrackedColOracle<B>>,
    pub mfxs: Vec<Option<TrackedOracle<B>>>,
    pub mgxs: Vec<Option<TrackedOracle<B>>>,
}

impl<B: SnarkBackend> DeepClone<B> for KeyedSumcheckProverInput<B> {
    fn deep_clone(&self, prover: ArgProver<B>) -> Self {
        let cols = |cols: &[TrackedCol<B>]| {
            cols.iter()
                .map(|col| col.deep_clone(prover.clone()))
                .collect()
        };
        let mults = |mults: &[Option<TrackedPoly<B>>]| {
            mults
                .iter()
                .map(|m| m.as_ref().map(|m| m.deep_clone(prover.clone())))
                .collect()
        };
        Self {
            fxs: cols(&self.fxs),
            gxs: cols(&self.gxs),
            mfxs: mults(&self.mfxs),
            mgxs: mults(&self.mgxs),
        }
    }
}

/// What multiplies `1 / (column - gamma)`: the multiplicity times the
/// activator, whichever of the two there is. The product is taken in this
/// order on both sides, which track a polynomial for it.
fn numerator<P>(
    multiplicity: Option<P>,
    activator: Option<P>,
    product: impl Fn(&P, &P) -> P,
) -> Option<P> {
    match (multiplicity, activator) {
        (Some(multiplicity), Some(activator)) => Some(product(&multiplicity, &activator)),
        (Some(numerator), None) | (None, Some(numerator)) => Some(numerator),
        (None, None) => None,
    }
}

/// The claim as ark-piop states it: the keys are the columns' data and the
/// numerators their multiplicities times their activators.
fn ark_prover_input<B: SnarkBackend>(
    input: KeyedSumcheckProverInput<B>,
) -> ark_keyed_sumcheck::KeyedSumcheckProverInput<B> {
    let side = |cols: &[TrackedCol<B>], mults: Vec<Option<TrackedPoly<B>>>| {
        let numerators = cols
            .iter()
            .zip(mults)
            .map(|(col, m)| numerator(m, col.activator_tracked_poly(), |m, a| m * a))
            .collect::<Vec<_>>();
        let keys = cols.iter().map(TrackedCol::data_tracked_poly).collect();
        (keys, numerators)
    };
    let (fxs, mfxs) = side(&input.fxs, input.mfxs);
    let (gxs, mgxs) = side(&input.gxs, input.mgxs);
    ark_keyed_sumcheck::KeyedSumcheckProverInput {
        fxs,
        gxs,
        mfxs,
        mgxs,
    }
}

impl<B: SnarkBackend> PIOP<B> for KeyedSumcheck<B> {
    type ProverInput = KeyedSumcheckProverInput<B>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = KeyedSumcheckVerifierInput<B>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        ark_keyed_sumcheck::KeyedSumcheck::<B>::honest_prover_check(ark_prover_input(input))
    }

    /// Records the claim without ark-piop's own honest-prover check: that
    /// check is [`Self::honest_prover_check`], which `prove` has run and a
    /// caller of `prove_inner` chose to skip.
    fn prove_inner(
        prover: &mut ArgProver<B>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        prover.add_mv_keyed_sum_claim_unchecked(ark_prover_input(input))
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let side = |cols: &[TrackedColOracle<B>], mults: Vec<Option<TrackedOracle<B>>>| {
            let numerators = cols
                .iter()
                .zip(mults)
                .map(|(col, m)| numerator(m, col.activator_tracked_oracle(), |m, a| m * a))
                .collect::<Vec<_>>();
            let keys = cols
                .iter()
                .map(TrackedColOracle::data_tracked_oracle)
                .collect();
            (keys, numerators)
        };
        let (fxs, mfxs) = side(&input.fxs, input.mfxs);
        let (gxs, mgxs) = side(&input.gxs, input.mgxs);
        verifier.add_mv_keyed_sum_claim(ark_keyed_sumcheck::KeyedSumcheckVerifierInput {
            fxs,
            gxs,
            mfxs,
            mgxs,
        })
    }
}
