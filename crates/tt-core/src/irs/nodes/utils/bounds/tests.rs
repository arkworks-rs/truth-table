use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::DataType;
use datafusion_common::ScalarValue;
use datafusion_expr::{Expr, col, expr::Cast, lit};

use super::{Bound, Numeric, numeric, pow2, safe_bits};

type F = <DefaultSnarkBackend as SnarkBackend>::F;

/// A 64-bit field, too small for the 64-bit types.
#[derive(ark_ff::MontConfig)]
#[modulus = "18446744069414584321"]
#[generator = "7"]
pub(crate) struct Goldilocks;
pub(crate) type SmallF = ark_ff::Fp64<ark_ff::MontBackend<Goldilocks, 1>>;

fn bits(data_type: DataType) -> usize {
    Bound::of_type(&data_type).expect("a numeric type").bits()
}

#[test]
fn type_bounds() {
    assert_eq!(bits(DataType::Boolean), 0);
    assert_eq!(bits(DataType::UInt8), 8);
    assert_eq!(bits(DataType::Int64), 64);
    assert_eq!(bits(DataType::Date32), 32);
    // 10^15 < 2^50.
    assert_eq!(bits(DataType::Decimal128(15, 2)), 50);
    assert_eq!(bits(DataType::Decimal128(38, 0)), 127);
    assert!(Bound::of_type(&DataType::Float64).is_err());
    assert!(Bound::of_type(&DataType::Utf8View).is_err());
    assert_eq!(
        numeric(&DataType::Int16),
        Some(Numeric::Int {
            bits: 16,
            signed: true
        })
    );
}

#[test]
fn literal_bounds_follow_the_value() {
    let of = |expr: Expr| Bound::of_literal(&expr).map(|b| b.max);
    assert_eq!(of(lit(0i64)), Some(0u8.into()));
    assert_eq!(of(lit(255u8)), Some(255u8.into()));
    assert_eq!(of(lit(-256i64)), Some(256u16.into()));
    // 100.00 cast to scale 4 is the integer 1_000_000.
    let hundred = Expr::Cast(Cast::new(
        Box::new(lit(ScalarValue::Decimal128(Some(10_000), 5, 2))),
        DataType::Decimal128(38, 4),
    ));
    assert_eq!(of(hundred), Some(1_000_000u32.into()));
    assert_eq!(of(col("a")), None);
    assert_eq!(of(lit(1.5f64)), None);
}

fn exactly(max: u128) -> Bound {
    Bound { max: max.into() }
}

#[test]
fn operation_bounds_are_exact() {
    assert_eq!(exactly(255).add(&exactly(65_535)), exactly(65_790));
    assert_eq!(exactly(255).mul(&exactly(255)), exactly(65_025));
    assert_eq!(exactly(3).sum(4), exactly(48));
    assert_eq!(exactly(7).scale_pow10(3), exactly(7_000));
}

#[test]
fn bits_round_up_to_a_power_of_two() {
    assert_eq!(exactly(0).bits(), 0);
    assert_eq!(exactly(1).bits(), 0);
    assert_eq!(exactly(1 << 20).bits(), 20);
    assert_eq!(exactly((1 << 20) + 1).bits(), 21);
}

#[test]
fn the_field_rule_follows_the_field() {
    let s = safe_bits::<F>();
    assert_eq!(s, 250);
    let pow2 = |bits| Bound { max: pow2(bits) };
    pow2(s).ensure_fits_field::<F>("test").expect("2^S fits");
    assert!(
        pow2(s)
            .add(&exactly(1))
            .ensure_fits_field::<F>("test")
            .is_err()
    );
    let int64 = Bound::of_type(&DataType::Int64).unwrap();
    int64
        .ensure_fits_field::<F>("Int64")
        .expect("Int64 fits BN254");
    assert!(int64.ensure_fits_field::<SmallF>("Int64").is_err());
}
