use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion_common::DFSchema;
use datafusion_expr::{Expr, binary_expr, cast, col, lit};

use super::{Consumer, Plan};
use crate::irs::nodes::utils::bounds::tests::SmallF;

type F = <DefaultSnarkBackend as SnarkBackend>::F;

fn schema() -> DFSchema {
    let fields = [
        ("a", DataType::UInt8),
        ("b", DataType::UInt8),
        ("c", DataType::UInt8),
        ("x", DataType::Int64),
        ("y", DataType::Int64),
        ("z", DataType::Int64),
        ("w", DataType::Int64),
        ("price", DataType::Decimal128(15, 2)),
        ("discount", DataType::Decimal128(15, 2)),
        ("wide", DataType::Decimal128(38, 0)),
        ("name", DataType::Utf8),
    ];
    let schema = Schema::new(
        fields
            .into_iter()
            .map(|(name, data_type)| Field::new(name, data_type, false))
            .collect::<Vec<_>>(),
    );
    DFSchema::try_from(schema).unwrap()
}

fn bits(plan: &Plan<F>, expr: &Expr) -> usize {
    plan.unchecked(expr).unwrap().unwrap().bits()
}

#[test]
fn a_u8_product_past_its_type_stays_unchecked() {
    let schema = schema();
    let plan = Plan::<F>::new(&schema);
    let ab = col("a") * col("b");
    let abc = ab.clone() * col("c");
    assert!(!plan.is_checked(&ab, &Consumer::Operand(&abc)).unwrap());
    assert_eq!(bits(&plan, &ab), 16);
    assert_eq!(bits(&plan, &abc), 24);
    // Leaving the expression, it is read by its type.
    assert!(plan.is_checked(&abc, &Consumer::Root).unwrap());
    plan.ensure_fits_field(&abc).unwrap();
}

#[test]
fn a_consumer_past_the_field_checks_its_operands() {
    let schema = schema();
    let plan = Plan::<F>::new(&schema);
    let xy = col("x") * col("y");
    let xyz = xy.clone() * col("z");
    let xyzw = xyz.clone() * col("w");
    // 128 + 64 = 192 bits fit: x·y stays unchecked inside x·y·z.
    assert!(!plan.is_checked(&xy, &Consumer::Operand(&xyz)).unwrap());
    // 192 + 64 = 256 bits do not: x·y·z is checked, back to 64 bits.
    assert!(plan.is_checked(&xyz, &Consumer::Operand(&xyzw)).unwrap());
    assert_eq!(bits(&plan, &xyzw), 128);
    plan.ensure_fits_field(&xyzw).unwrap();
}

#[test]
fn an_operation_past_the_field_on_columns_is_refused() {
    let schema = schema();
    let plan = Plan::<F>::new(&schema);
    // Two Decimal128(38) columns: 127 + 127 bits, and nothing to check.
    assert!(
        plan.ensure_fits_field(&(col("wide") * col("wide")))
            .is_err()
    );
    plan.ensure_fits_field(&(col("wide") + col("wide")))
        .unwrap();
}

#[test]
fn the_field_size_sets_the_limit() {
    let schema = schema();
    let plan = Plan::<SmallF>::new(&schema);
    // S = 60 on a 64-bit field.
    let abc = col("a") * col("b") * col("c");
    plan.ensure_fits_field(&abc).unwrap();
    assert!(plan.ensure_fits_field(&(col("x") * col("y"))).is_err());
}

#[test]
fn a_sum_argument_stays_unchecked_while_the_sum_fits() {
    let schema = schema();
    let plan = Plan::<F>::new(&schema);
    let revenue = col("price") * (lit(1i64) - col("discount"));
    assert!(
        !plan
            .is_checked(&revenue, &Consumer::Sum { log_rows: 23 })
            .unwrap()
    );
    // 192 bits past Int64: summed over 2^60 rows they pass 2^S, and the
    // check brings them back to 64.
    let xyz = col("x") * col("y") * col("z");
    assert!(
        !plan
            .is_checked(&xyz, &Consumer::Sum { log_rows: 23 })
            .unwrap()
    );
    assert!(
        plan.is_checked(&xyz, &Consumer::Sum { log_rows: 60 })
            .unwrap()
    );
}

#[test]
fn a_root_within_its_type_is_not_checked() {
    let schema = schema();
    let plan = Plan::<F>::new(&schema);
    // AVG's widening cast: |v| ≤ 2^50 · 10^4 < 2^64, the range of Decimal(19).
    let widened = cast(col("price"), DataType::Decimal128(19, 6));
    assert!(!plan.is_checked(&widened, &Consumer::Root).unwrap());
    let narrow = cast(col("price"), DataType::Decimal128(16, 6));
    assert!(plan.is_checked(&narrow, &Consumer::Root).unwrap());
    // 2^50 · (1 + 2^50) is within the product's Decimal128(31+).
    let revenue = col("price") * (lit(1i64) - col("discount"));
    assert!(!plan.is_checked(&revenue, &Consumer::Root).unwrap());
    // 2^128 is not within Int64.
    assert!(
        plan.is_checked(&(col("x") * col("y")), &Consumer::Root)
            .unwrap()
    );
    // Nor is any operation on unsigned values, which could be negative.
    assert!(
        plan.is_checked(&(col("a") + col("b")), &Consumer::Root)
            .unwrap()
    );
}

#[test]
fn a_sum_output_within_its_type_is_not_checked() {
    let schema = schema();
    let checked = |arg: Expr, log_rows, output_type| {
        super::sum_output_is_checked::<DefaultSnarkBackend>(&arg, log_rows, &output_type, &schema)
            .unwrap()
    };
    // Decimal(15, 2) summed into Decimal(25, 2), checked to 2^84.
    let sum_type = DataType::Decimal128(25, 2);
    assert!(!checked(col("price"), 19, sum_type.clone()));
    assert!(checked(col("price"), 40, sum_type));
    // Int64 sums into Int64: no room for the rows.
    assert!(checked(col("x"), 1, DataType::Int64));
}

#[test]
fn consumers_that_read_the_type_check_their_operands() {
    let schema = schema();
    let plan = Plan::<F>::new(&schema);
    let ab = col("a") * col("b");
    let compared = binary_expr(ab.clone(), datafusion_expr::Operator::Gt, col("c"));
    assert!(!plan.is_checked(&ab, &Consumer::Operand(&compared)).unwrap());
    let divided = ab.clone() / col("c");
    assert!(plan.is_checked(&ab, &Consumer::Operand(&divided)).unwrap());
    // A cast that scales up reads the integer; one to its own type does not.
    let scaled = cast(ab.clone(), DataType::Decimal128(10, 2));
    assert!(!plan.is_checked(&ab, &Consumer::Operand(&scaled)).unwrap());
    let same = cast(ab.clone(), DataType::UInt8);
    assert!(plan.is_checked(&ab, &Consumer::Operand(&same)).unwrap());
}

#[test]
fn strings_have_no_bound() {
    let schema = schema();
    let plan = Plan::<F>::new(&schema);
    plan.ensure_fits_field(&col("name").eq(lit("FRANCE")))
        .unwrap();
}
