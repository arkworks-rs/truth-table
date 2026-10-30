//! Truncated division (Divcheck, §6.1), run inline: on every active row
//! the quotient column `Q` is `trunc(X / D)`, where `X = N·10^a` and
//! `D = M·10^b` rescale the numerator `N` and denominator `M` so that the
//! three decimal scales agree (`a - b = s_Q + s_M - s_N`). Arrow's decimal
//! division truncates toward zero, and so does its decimal AVG.
//!
//! The prover commits the sign bits `σ_X` and `σ_D` (`σ_D` is dropped when
//! the denominator is positive by construction), with `s = 1 - 2σ`. The
//! remainder `R = s_X·(X - Q·D)` is virtual. Range checks (`range`) show
//! - `s_X·X ∈ [0, 2^wX)`, so `s_X` is the sign of `X`;
//! - `s_D·D - 1 ∈ [0, 2^wD)`, so `s_D` is the sign of `D` and `D ≠ 0`;
//! - `R ∈ [0, 2^wD)` and `s_D·D - 1 - R ∈ [0, 2^wD)`, so `0 ≤ R < |D|`;
//! - `Q + 2^wQ ∈ [0, 2^(wQ+1))`.
//!
//! The widths keep `|X| + |Q|·|D| + |D|` below the modulus, so
//! `X - Q·D = s_X·R` holds over the integers. A remainder with the sign of
//! `X` and below `|D|` in magnitude leaves one quotient: the truncated one.
//!
//! A decimal rescale divides by the public `D = 10^k`, which needs neither a
//! sign nor a range check. Arrow rounds that quotient half away from zero:
//! `R = s_X·(X - Q·D) + D/2` in `[0, D)` leaves that one.

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::{BigInteger, Field as _, One, PrimeField, Zero};
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    prover::{
        ArgProver,
        errors::{HonestProverError, ProverError},
        structs::polynomial::TrackedPoly,
    },
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};
use datafusion::arrow::datatypes::DataType;

use super::sign::range;

/// What the quotient divides by.
pub enum Divisor<'a, P> {
    /// `positive` drops `σ_D`; pass it only when the denominator is positive
    /// by construction (a COUNT), since `D - 1 ∈ [0, 2^wD)` is still checked
    /// and fails otherwise.
    Column {
        operand: Operand<'a, P>,
        positive: bool,
    },
    /// The constant 1 of scale 0, which the rescaling makes `10^k`.
    Power10(Rounding),
}

#[derive(Clone, Copy)]
pub enum Rounding {
    TowardZero,
    HalfAwayFromZero,
}

impl<P> Divisor<'_, P> {
    fn data_type(&self) -> Option<&DataType> {
        match self {
            Divisor::Column { operand, .. } => Some(operand.data_type),
            Divisor::Power10(_) => None,
        }
    }
}

/// Range-check widths and rescaling exponents, fixed by the operand types.
struct Widths {
    num_shift: u32,
    den_shift: u32,
    num: usize,
    den: usize,
    quot: usize,
}

/// Bits that hold `10^exp`.
fn pow10_bits(exp: u32) -> usize {
    (exp as f64 * std::f64::consts::LOG2_10).ceil() as usize
}

/// A bound `|v| < 2^bits` on every value of the type, and its decimal scale.
fn magnitude_bits_and_scale(data_type: &DataType) -> SnarkResult<(usize, i32)> {
    let bits = match data_type {
        DataType::Int8 | DataType::UInt8 => 8,
        DataType::Int16 | DataType::UInt16 => 16,
        DataType::Int32 | DataType::UInt32 => 32,
        DataType::Int64 | DataType::UInt64 => 64,
        DataType::Decimal128(precision, scale) => {
            return Ok((pow10_bits(*precision as u32), *scale as i32));
        }
        other => {
            return Err(SnarkError::DataTypeError(
                ark_piop::arithmetic::errors::DataTypeError::NotSupported(format!(
                    "division over {other}"
                )),
            ));
        }
    };
    Ok((bits, 0))
}

impl Widths {
    /// With `C = MODULUS_BIT_SIZE - 4`: `wX ≤ C`, `wD ≤ C/2` and
    /// `wQ + wD < C`, so `|X| + |Q|·|D| + |D| < 2^(C+1) < p/4`. Capping a
    /// width only costs completeness for values the type allows but the
    /// field cannot hold.
    fn new<F: PrimeField>(
        num: &DataType,
        den: Option<&DataType>,
        quot: &DataType,
    ) -> SnarkResult<Self> {
        let (num_bits, num_scale) = magnitude_bits_and_scale(num)?;
        let (den_bits, den_scale) = den.map_or(Ok((1, 0)), magnitude_bits_and_scale)?;
        let (quot_bits, quot_scale) = magnitude_bits_and_scale(quot)?;
        let shift = quot_scale + den_scale - num_scale;
        let num_shift = shift.max(0) as u32;
        let den_shift = (-shift).max(0) as u32;
        let cap = F::MODULUS_BIT_SIZE as usize - 4;
        let den = (den_bits + pow10_bits(den_shift)).min(cap / 2);
        Ok(Self {
            num_shift,
            den_shift,
            num: (num_bits + pow10_bits(num_shift)).min(cap),
            den,
            quot: quot_bits.min(cap - 1 - den),
        })
    }
}

fn pow10<F: PrimeField>(exp: u32) -> F {
    F::from(10u64).pow([exp as u64])
}

/// What `R` adds to `s_X·(X - Q·D)`: `D/2` makes the quotient the one
/// rounded half away from zero.
fn rounding_offset<F: PrimeField>(d: F, rounding: Rounding) -> F {
    match rounding {
        Rounding::TowardZero => F::zero(),
        Rounding::HalfAwayFromZero => d * F::from(2u64).inverse().expect("2 is invertible"),
    }
}

fn is_negative<F: PrimeField>(value: F) -> bool {
    value.into_bigint() > (-value).into_bigint()
}

/// A column of the numerator, denominator or quotient, with its SQL type.
pub struct Operand<'a, P> {
    pub data: &'a P,
    pub data_type: &'a DataType,
}

/// Commits `σ` (1 on the active rows where `value` is negative) and checks
/// it is boolean; returns `1 - 2σ`.
fn commit_sign<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    value: &TrackedPoly<B>,
    activator: Option<&TrackedPoly<B>>,
) -> SnarkResult<TrackedPoly<B>> {
    let values = value.evaluations();
    let active = activator.map(|a| a.evaluations());
    let bits = values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let on = active.as_ref().is_none_or(|a| !a[i].is_zero());
            if on && is_negative(*v) {
                B::F::one()
            } else {
                B::F::zero()
            }
        })
        .collect();
    let sigma =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(value.log_size(), bits))?;
    prover.add_mv_zerocheck_claim((&sigma * &sigma.sub_scalar_poly(B::F::one())).id())?;
    Ok(sigma
        .mul_scalar_poly(-B::F::from(2u64))
        .add_scalar_poly(B::F::one()))
}

fn track_sign<B: SnarkBackend>(verifier: &mut ArgVerifier<B>) -> SnarkResult<TrackedOracle<B>> {
    let sigma = verifier.track_next_mv_com()?;
    verifier.add_mv_zerocheck_claim((&sigma * &sigma.sub_scalar_oracle(B::F::one())).id());
    Ok(sigma
        .mul_scalar_oracle(-B::F::from(2u64))
        .add_scalar_oracle(B::F::one()))
}

pub fn prove<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    activator: Option<&TrackedPoly<B>>,
    num: Operand<'_, TrackedPoly<B>>,
    den: Divisor<'_, TrackedPoly<B>>,
    quot: Operand<'_, TrackedPoly<B>>,
) -> SnarkResult<()> {
    let widths = Widths::new::<B::F>(num.data_type, den.data_type(), quot.data_type)?;
    let x = num.data.mul_scalar_poly(pow10(widths.num_shift));
    let x_sign = commit_sign(prover, &x, activator)?;
    let q = quot.data;
    let mut ranged = vec![(&x_sign * &x, widths.num)];
    let (rem, bound) = match den {
        Divisor::Column { operand, positive } => {
            let d = operand.data.mul_scalar_poly(pow10(widths.den_shift));
            let abs_d = if positive {
                d.clone()
            } else {
                &commit_sign(prover, &d, activator)? * &d
            };
            let abs_d_minus_one = abs_d.sub_scalar_poly(B::F::one());
            ranged.push((abs_d_minus_one.clone(), widths.den));
            let rem = &x_sign * &(&x - &(q * &d));
            let bound = &abs_d_minus_one - &rem;
            (rem, bound)
        }
        Divisor::Power10(rounding) => {
            let d = pow10::<B::F>(widths.den_shift);
            let rem = (&x_sign * &(&x - &q.mul_scalar_poly(d)))
                .add_scalar_poly(rounding_offset(d, rounding));
            let bound = rem
                .mul_scalar_poly(-B::F::one())
                .add_scalar_poly(d - B::F::one());
            (rem, bound)
        }
    };
    ranged.extend([
        (rem, widths.den),
        (bound, widths.den),
        (
            q.add_scalar_poly(B::F::from(2u64).pow([widths.quot as u64])),
            widths.quot + 1,
        ),
    ]);
    for (poly, width) in ranged {
        range::prove(
            prover,
            &TrackedCol::new(poly, activator.cloned(), None),
            width,
        )?;
    }
    Ok(())
}

pub fn verify<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    activator: Option<&TrackedOracle<B>>,
    num: Operand<'_, TrackedOracle<B>>,
    den: Divisor<'_, TrackedOracle<B>>,
    quot: Operand<'_, TrackedOracle<B>>,
) -> SnarkResult<()> {
    let widths = Widths::new::<B::F>(num.data_type, den.data_type(), quot.data_type)?;
    let x = num.data.mul_scalar_oracle(pow10(widths.num_shift));
    let x_sign = track_sign(verifier)?;
    let q = quot.data;
    let mut ranged = vec![(&x_sign * &x, widths.num)];
    let (rem, bound) = match den {
        Divisor::Column { operand, positive } => {
            let d = operand.data.mul_scalar_oracle(pow10(widths.den_shift));
            let abs_d = if positive {
                d.clone()
            } else {
                &track_sign(verifier)? * &d
            };
            let abs_d_minus_one = abs_d.sub_scalar_oracle(B::F::one());
            ranged.push((abs_d_minus_one.clone(), widths.den));
            let rem = &x_sign * &(&x - &(q * &d));
            let bound = &abs_d_minus_one - &rem;
            (rem, bound)
        }
        Divisor::Power10(rounding) => {
            let d = pow10::<B::F>(widths.den_shift);
            let rem = (&x_sign * &(&x - &q.mul_scalar_oracle(d)))
                .add_scalar_oracle(rounding_offset(d, rounding));
            let bound = rem
                .mul_scalar_oracle(-B::F::one())
                .add_scalar_oracle(d - B::F::one());
            (rem, bound)
        }
    };
    ranged.extend([
        (rem, widths.den),
        (bound, widths.den),
        (
            q.add_scalar_oracle(B::F::from(2u64).pow([widths.quot as u64])),
            widths.quot + 1,
        ),
    ]);
    for (oracle, width) in ranged {
        range::verify(
            verifier,
            &TrackedColOracle::new(oracle, activator.cloned(), None),
            width,
        )?;
    }
    Ok(())
}

/// Checks on the prover's columns that every range claim of `prove` holds.
pub fn honest_check<B: SnarkBackend>(
    activator: Option<&TrackedPoly<B>>,
    num: Operand<'_, TrackedPoly<B>>,
    den: Divisor<'_, TrackedPoly<B>>,
    quot: Operand<'_, TrackedPoly<B>>,
) -> SnarkResult<()> {
    let widths = Widths::new::<B::F>(num.data_type, den.data_type(), quot.data_type)?;
    let xs = num.data.evaluations();
    let qs = quot.data.evaluations();
    let active = activator.map(|a| a.evaluations());
    let num_scale: B::F = pow10(widths.num_shift);
    let den_scale: B::F = pow10(widths.den_shift);
    let quot_offset = B::F::from(2u64).pow([widths.quot as u64]);
    fn fits<F: PrimeField>(v: F, width: usize) -> bool {
        v.into_bigint().num_bits() as usize <= width
    }
    fn sign<F: PrimeField>(v: F) -> F {
        if is_negative(v) { -F::one() } else { F::one() }
    }
    // Each row's rescaled denominator, whether `|D| - 1` is range checked,
    // and the remainder's offset.
    let (ds, den_ranged, offset) = match &den {
        Divisor::Column { operand, .. } => (
            operand
                .data
                .evaluations()
                .into_iter()
                .map(|d| d * den_scale)
                .collect::<Vec<_>>(),
            true,
            B::F::zero(),
        ),
        Divisor::Power10(rounding) => (
            vec![den_scale; xs.len()],
            false,
            rounding_offset(den_scale, *rounding),
        ),
    };
    let den_positive = !matches!(
        den,
        Divisor::Column {
            positive: false,
            ..
        }
    );
    for row in 0..xs.len() {
        if active.as_ref().is_some_and(|a| a[row].is_zero()) {
            continue;
        }
        let (x, d, q) = (xs[row] * num_scale, ds[row], qs[row]);
        let abs_d = if den_positive { d } else { sign(d) * d };
        let rem = sign(x) * (x - q * d) + offset;
        let ok = fits(sign(x) * x, widths.num)
            && (!den_ranged || fits(abs_d - B::F::one(), widths.den))
            && fits(rem, widths.den)
            && fits(abs_d - B::F::one() - rem, widths.den)
            && fits(q + quot_offset, widths.quot + 1);
        if !ok {
            tracing::error!(
                target: "tt_core::prover::passes::honest_prover",
                gadget = "Division",
                row,
                numerator = %xs[row],
                denominator = %d,
                quotient = %q,
                "honest prover division check failed"
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
