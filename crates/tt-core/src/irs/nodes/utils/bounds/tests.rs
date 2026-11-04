use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::DataType;
use datafusion_common::ScalarValue;
use datafusion_expr::{Expr, col, expr::Cast, lit};

use super::{Bound, Numeric, numeric, safe_bits};

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
    let of = |expr: Expr| Bound::of_literal(&expr).map(Bound::bits);
    assert_eq!(of(lit(0i64)), Some(0));
    assert_eq!(of(lit(255u8)), Some(8));
    assert_eq!(of(lit(-256i64)), Some(9));
    // 100.00 cast to scale 4 is the integer 1_000_000 < 2^20.
    let hundred = Expr::Cast(Cast::new(
        Box::new(lit(ScalarValue::Decimal128(Some(10_000), 5, 2))),
        DataType::Decimal128(38, 4),
    ));
    assert_eq!(of(hundred), Some(20));
    assert_eq!(of(col("a")), None);
    assert_eq!(of(lit(1.5f64)), None);
}

#[test]
fn operation_bounds() {
    let b = |bits| Bound { bits };
    assert_eq!(b(8).add(b(16)).bits(), 17);
    assert_eq!(b(8).mul(b(16)).bits(), 24);
    assert_eq!(b(50).sum(23).bits(), 73);
    // 10^3 < 2^10.
    assert_eq!(b(50).scale_pow10(3).bits(), 60);
}

#[test]
fn the_field_rule_follows_the_field() {
    let s = safe_bits::<F>();
    assert_eq!(s, 250);
    Bound { bits: s }
        .ensure_fits_field::<F>("test")
        .expect("2^S fits");
    assert!(
        Bound { bits: s + 1 }
            .ensure_fits_field::<F>("test")
            .is_err()
    );
    let int64 = Bound::of_type(&DataType::Int64).unwrap();
    int64
        .ensure_fits_field::<F>("Int64")
        .expect("Int64 fits BN254");
    assert!(int64.ensure_fits_field::<SmallF>("Int64").is_err());
}
