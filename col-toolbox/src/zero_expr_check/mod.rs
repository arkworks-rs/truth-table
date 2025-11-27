use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_piop::{
    SnarkBackend,
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::ArgProver,
    verifier::ArgVerifier,
};
use derivative::Derivative;
use std::marker::PhantomData;

use crate::{
    binary_check::{BinaryCheckPIOP, BinaryCheckProverInput, BinaryCheckVerifierInput},
    no_zeros_check::{NoZerosCheck, NoZerosCheckProverInput, NoZerosCheckVerifierInput},
};
use ark_ff::One;
#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct ZeroExprCheckProverInput<B: SnarkBackend> {
    pub tracked_col: TrackedCol<B>,
    pub selector_col: TrackedCol<B>,
}
use std::ops::Neg;
impl<B> DeepClone<B> for ZeroExprCheckProverInput<B>
where
    B: SnarkBackend,
{
    fn deep_clone(&self, prover: ArgProver<B>) -> Self {
        Self {
            tracked_col: self.tracked_col.deep_clone(prover.clone()),
            selector_col: self.selector_col.deep_clone(prover),
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct ZeroExprCheckVerifierInput<B: SnarkBackend> {
    pub tracked_col_oracle: TrackedColOracle<B>,
    pub selector_col_oracle: TrackedColOracle<B>,
}

pub struct ZeroExprCheckPIOP<B: SnarkBackend>(PhantomData<B>);

impl<B: SnarkBackend> PIOP<B> for ZeroExprCheckPIOP<B> {
    type ProverInput = ZeroExprCheckProverInput<B>;
    type ProverOutput = ();
    type VerifierInput = ZeroExprCheckVerifierInput<B>;
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(_input: Self::ProverInput) -> SnarkResult<()> {
        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<B>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let ZeroExprCheckProverInput {
            tracked_col,
            selector_col,
        } = input;
        BinaryCheckPIOP::<B>::prove(
            prover,
            BinaryCheckProverInput {
                predicate: selector_col.activated_data_tracked_poly(),
            },
        )?;

        let activator = tracked_col.activator_tracked_poly();
        let tracked_data = tracked_col.data_tracked_poly();
        let selector_data = selector_col.data_tracked_poly();

        let zero_poly = match activator.as_ref() {
            Some(act) => &(&tracked_data * &selector_data) * act,
            None => &tracked_data * &selector_data,
        };
        prover.add_mv_zerocheck_claim(zero_poly.id())?;

        let one_minus_selector = (selector_data.clone() * B::F::one().neg()) + B::F::one();
        let gated_activator = match activator {
            Some(act) => Some(&act * &one_minus_selector),
            None => Some(one_minus_selector.clone()),
        };

        let non_zero_col = TrackedCol::new(tracked_data, gated_activator, tracked_col.field_ref());

        NoZerosCheck::<B>::prove(prover, NoZerosCheckProverInput { col: non_zero_col })?;
        Ok(())
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let ZeroExprCheckVerifierInput {
            tracked_col_oracle,
            selector_col_oracle,
        } = input;

        BinaryCheckPIOP::<B>::verify(
            verifier,
            BinaryCheckVerifierInput {
                predicate_oracle: selector_col_oracle.activated_data_tracked_oracle(),
            },
        )?;

        let activator = tracked_col_oracle.activator_tracked_oracle();
        let tracked_data = tracked_col_oracle.data_tracked_oracle();
        let selector_data = selector_col_oracle.data_tracked_oracle();

        let zero_oracle = match activator.as_ref() {
            Some(act) => &(&tracked_data * &selector_data) * act,
            None => &tracked_data * &selector_data,
        };
        verifier.add_zerocheck_claim(zero_oracle.id());

        let one_minus_selector = (selector_data.clone() * B::F::one().neg()) + B::F::one();
        let gated_activator = match activator {
            Some(act) => Some(&act * &one_minus_selector),
            None => Some(one_minus_selector.clone()),
        };

        let non_zero_col = TrackedColOracle::new(
            tracked_data,
            gated_activator,
            tracked_col_oracle.field_ref(),
        );

        NoZerosCheck::<B>::verify(
            verifier,
            NoZerosCheckVerifierInput {
                tracked_col_oracle: non_zero_col,
            },
        )?;

        Ok(())
    }
}
