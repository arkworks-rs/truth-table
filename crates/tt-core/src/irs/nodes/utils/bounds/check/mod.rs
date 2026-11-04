//! Every active value of a column lies in the range of its data type
//! (`bounds::numeric`), by one range check (`sign::range`, PIOP 22) of the
//! value plus a public offset:
//! - an unsigned integer of `w` bits: `v ∈ [0, 2^w)`;
//! - a signed integer of `w` bits: `v + 2^(w-1) ∈ [0, 2^w)`;
//! - `Decimal128(P, S)` with `b` the bits of `10^P`: `v + 2^b ∈ [0, 2^(b+1))`,
//!   which admits `[-2^b, 2^b)`, a looser range than `|v| < 10^P`.
//!
//! The check speaks of the field element; it bounds the integer the element
//! stands for when that integer is within `2^S` (`bounds`).

use arithmetic::col::TrackedCol;
use arithmetic::col_oracle::TrackedColOracle;
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_piop::{
    SnarkBackend,
    arithmetic::errors::DataTypeError,
    errors::{SnarkError, SnarkResult},
    prover::{
        ArgProver,
        errors::{HonestProverError, ProverError},
        structs::polynomial::TrackedPoly,
    },
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};
use datafusion::arrow::datatypes::DataType;

use super::{Numeric, numeric, pow10_bits};
use crate::irs::nodes::utils::sign::range;

/// The exponent of the offset (none for unsigned) and the range width.
fn offset_and_width(data_type: &DataType) -> SnarkResult<(Option<usize>, usize)> {
    Ok(match numeric(data_type) {
        Some(Numeric::Int {
            bits,
            signed: false,
        }) => (None, bits),
        Some(Numeric::Int { bits, signed: true }) => (Some(bits - 1), bits),
        Some(Numeric::Decimal { precision, .. }) => {
            let bits = pow10_bits(precision.into());
            (Some(bits), bits + 1)
        }
        None => {
            return Err(SnarkError::DataTypeError(DataTypeError::NotSupported(
                format!("a range check of {data_type}"),
            )));
        }
    })
}

fn offset<F: PrimeField>(exp: Option<usize>) -> F {
    exp.map_or(F::zero(), |e| F::from(2u64).pow([e as u64]))
}

pub fn prove<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    activator: Option<&TrackedPoly<B>>,
    value: &TrackedPoly<B>,
    data_type: &DataType,
) -> SnarkResult<()> {
    let (exp, width) = offset_and_width(data_type)?;
    let shifted = value.add_scalar_poly(offset(exp));
    range::prove(
        prover,
        &TrackedCol::new(shifted, activator.cloned(), None),
        width,
    )
}

pub fn verify<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    activator: Option<&TrackedOracle<B>>,
    value: &TrackedOracle<B>,
    data_type: &DataType,
) -> SnarkResult<()> {
    let (exp, width) = offset_and_width(data_type)?;
    let shifted = value.add_scalar_oracle(offset(exp));
    range::verify(
        verifier,
        &TrackedColOracle::new(shifted, activator.cloned(), None),
        width,
    )
}

/// Checks on the prover's column that every active value is in range;
/// `gadget` names the caller in the log.
pub fn honest_check<B: SnarkBackend>(
    activator: Option<&TrackedPoly<B>>,
    value: &TrackedPoly<B>,
    data_type: &DataType,
    gadget: &str,
) -> SnarkResult<()> {
    let (exp, width) = offset_and_width(data_type)?;
    let shift: B::F = offset(exp);
    let active = activator.map(|a| a.evaluations());
    for (row, v) in value.evaluations().into_iter().enumerate() {
        if active.as_ref().is_some_and(|a| a[row].is_zero()) {
            continue;
        }
        if (v + shift).into_bigint().num_bits() as usize > width {
            tracing::error!(
                target: "tt_core::prover::passes::honest_prover",
                gadget,
                row,
                value = %v,
                data_type = %data_type,
                "honest prover type range check failed"
            );
            return Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::FalseClaim,
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
