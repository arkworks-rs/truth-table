//! Every bound the checks put on a value: what each type admits, how each
//! operation grows a bound, and the one rule that keeps values inside the
//! field.
//!
//! A field element names one integer only near zero. Every integer a check
//! reasons about is kept to `|v| ≤ 2^S` with `S = MODULUS_BIT_SIZE - 4`
//! ([`safe_bits`]). Since `p > 2^(S+3)`, any three such values add up to
//! less than `p/2`, so an identity among them in the field holds over the
//! integers. That is what a range check of width `w ≤ S` ([`check`],
//! `sign::range`) and the division check need.
//!
//! An operand is within its type's [`Bound`] by induction: scanned columns
//! and literals are, and every operation whose output could leave its type
//! range-checks that output ([`check`]): `+`, `-`, `*`, SUM and a cast that
//! scales up or narrows. A division bounds its quotient itself.

pub mod check;
pub mod plan;

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::errors::DataTypeError,
    errors::{SnarkError, SnarkResult},
};
use datafusion::arrow::datatypes::DataType;
use datafusion_common::ScalarValue;
use datafusion_expr::{Expr, expr::Cast};
use num_bigint::BigUint;

pub(crate) fn safe_bits<F: PrimeField>() -> usize {
    F::MODULUS_BIT_SIZE as usize - 4
}

/// The numeric types the checks support, as the integer each is encoded as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Numeric {
    Int {
        bits: usize,
        signed: bool,
    },
    /// The unscaled integer of `Decimal128(precision, scale)`.
    Decimal {
        precision: u8,
        scale: i8,
    },
}

pub(crate) fn numeric(data_type: &DataType) -> Option<Numeric> {
    let int = |bits, signed| Some(Numeric::Int { bits, signed });
    match data_type {
        DataType::UInt8 => int(8, false),
        DataType::UInt16 => int(16, false),
        DataType::UInt32 => int(32, false),
        DataType::UInt64 => int(64, false),
        DataType::Int8 => int(8, true),
        DataType::Int16 => int(16, true),
        DataType::Int32 | DataType::Date32 => int(32, true),
        DataType::Int64 => int(64, true),
        DataType::Decimal128(precision, scale) => Some(Numeric::Decimal {
            precision: *precision,
            scale: *scale,
        }),
        _ => None,
    }
}

/// The decimal scale of a numeric type; an integer has scale 0.
pub(crate) fn scale(data_type: &DataType) -> SnarkResult<i32> {
    match numeric(data_type) {
        Some(Numeric::Decimal { scale, .. }) => Ok(scale.into()),
        Some(Numeric::Int { .. }) => Ok(0),
        None => Err(unsupported(data_type)),
    }
}

/// Bits that hold `10^exp`.
pub(crate) fn pow10_bits(exp: u32) -> usize {
    (exp as f64 * std::f64::consts::LOG2_10).ceil() as usize
}

fn unsupported(data_type: &DataType) -> SnarkError {
    SnarkError::DataTypeError(DataTypeError::NotSupported(format!(
        "a numeric bound for {data_type}"
    )))
}

/// `|v| ≤ max`, exact: rounding a bound to bits loses whether `10^19` fits
/// a range of `2^64`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Bound {
    max: BigUint,
}

fn pow2(exp: usize) -> BigUint {
    BigUint::from(1u8) << exp
}

impl Bound {
    /// The fewest bits with `|v| ≤ 2^bits`.
    pub(crate) fn bits(&self) -> usize {
        if self.max <= BigUint::from(1u8) {
            return 0;
        }
        (&self.max - 1u8).bits() as usize
    }

    /// The bound every value of the type meets. A boolean is 0 or 1.
    pub(crate) fn of_type(data_type: &DataType) -> SnarkResult<Self> {
        let bits = match (data_type, numeric(data_type)) {
            (DataType::Boolean, _) => 0,
            (_, Some(Numeric::Int { bits, .. })) => bits,
            (_, Some(Numeric::Decimal { precision, .. })) => pow10_bits(precision.into()),
            (_, None) => return Err(unsupported(data_type)),
        };
        Ok(Self { max: pow2(bits) })
    }

    /// A constant operand's bound, from its value. The Cast node proves a
    /// cast, so a cast literal's field value is its cast value's encoding.
    pub(crate) fn of_literal(expr: &Expr) -> Option<Self> {
        fn value(expr: &Expr) -> Option<ScalarValue> {
            match expr {
                Expr::Literal(value) => Some(value.clone()),
                Expr::Alias(alias) => value(&alias.expr),
                Expr::Cast(Cast { expr, data_type }) => value(expr)?.cast_to(data_type).ok(),
                _ => None,
            }
        }
        let raw: i128 = match value(expr)? {
            ScalarValue::Int8(Some(v)) => v.into(),
            ScalarValue::Int16(Some(v)) => v.into(),
            ScalarValue::Int32(Some(v)) => v.into(),
            ScalarValue::Int64(Some(v)) => v.into(),
            ScalarValue::UInt8(Some(v)) => v.into(),
            ScalarValue::UInt16(Some(v)) => v.into(),
            ScalarValue::UInt32(Some(v)) => v.into(),
            ScalarValue::UInt64(Some(v)) => v.into(),
            ScalarValue::Decimal128(Some(v), ..) => v,
            _ => return None,
        };
        Some(Self {
            max: raw.unsigned_abs().into(),
        })
    }

    /// `a ± b`.
    pub(crate) fn add(&self, other: &Self) -> Self {
        Self {
            max: &self.max + &other.max,
        }
    }

    pub(crate) fn mul(&self, other: &Self) -> Self {
        Self {
            max: &self.max * &other.max,
        }
    }

    /// A sum over a domain of `2^log_rows` rows: a public bound on how many
    /// are active.
    pub(crate) fn sum(&self, log_rows: usize) -> Self {
        Self {
            max: &self.max << log_rows,
        }
    }

    /// `v · 10^exp`.
    pub(crate) fn scale_pow10(&self, exp: u32) -> Self {
        Self {
            max: &self.max * BigUint::from(10u8).pow(exp),
        }
    }

    pub(crate) fn fits_field<F: PrimeField>(&self) -> bool {
        self.max <= pow2(safe_bits::<F>())
    }

    /// Refuses a value beyond `2^S`, where the field no longer names one
    /// integer for it; `what` names the value in the error.
    pub(crate) fn ensure_fits_field<F: PrimeField>(&self, what: &str) -> SnarkResult<()> {
        if !self.fits_field::<F>() {
            return Err(SnarkError::DataTypeError(DataTypeError::NotSupported(
                format!("{what}: a {}-bit value does not fit the field", self.bits()),
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;
