//! The division check on four-row columns, through a gadget that calls it
//! inline.

use std::sync::{Arc, Mutex};

use arithmetic::ACTIVATOR_FIELD;
use ark_ff::Field as _;
use ark_piop::{DefaultSnarkBackend, SnarkBackend, errors::SnarkError};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{Divisor, Operand, Rounding};
use crate::irs::nodes::utils::contig_sort::tests::assert_rejected;
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};
use crate::test_utils::inline_gadget::InlineGadget;

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const LABEL: &str = "__input__";

fn int(v: i64) -> F {
    F::from(v as i128)
}

struct Case {
    types: [DataType; 3],
    num: Vec<i64>,
    den: Vec<i64>,
    quot: Vec<F>,
    activator: Vec<i64>,
    den_positive: bool,
    /// Divides by the public `10^k` instead of the `d` column.
    power10: Option<Rounding>,
}

fn divisor<P>(
    operand: Operand<'_, P>,
    positive: bool,
    power10: Option<Rounding>,
) -> Divisor<'_, P> {
    match power10 {
        Some(rounding) => Divisor::Power10(rounding),
        None => Divisor::Column { operand, positive },
    }
}

impl Case {
    fn int64(num: [i64; 4], den: [i64; 4], quot: [i64; 4]) -> Self {
        Self {
            types: [DataType::Int64, DataType::Int64, DataType::Int64],
            num: num.to_vec(),
            den: den.to_vec(),
            quot: quot.into_iter().map(int).collect(),
            activator: vec![1; 4],
            den_positive: false,
            power10: None,
        }
    }

    /// The verifier's result, and whether `honest_check` accepted the
    /// prover's columns.
    fn run(self) -> (Result<(), SnarkError>, bool) {
        let (den_positive, power10) = (self.den_positive, self.power10);
        let honest = Arc::new(Mutex::new(false));
        let honest_in_prover = honest.clone();
        let gadget = InlineGadget::<B>::node(
            Box::new(move |prover, payload| {
                let table = &payload[LABEL];
                let cols = table
                    .data_tracked_polys_indices()
                    .into_iter()
                    .map(|i| table.tracked_col_by_ind(i))
                    .collect::<Vec<_>>();
                let fields = cols
                    .iter()
                    .map(|c| c.field_ref().expect("a typed column"))
                    .collect::<Vec<_>>();
                let polys = cols
                    .iter()
                    .map(|c| c.data_tracked_poly())
                    .collect::<Vec<_>>();
                let operand = |i: usize| Operand {
                    data: &polys[i],
                    data_type: fields[i].data_type(),
                };
                let activator = table.activator_tracked_poly();
                *honest_in_prover.lock().unwrap() = super::honest_check(
                    activator.as_ref(),
                    operand(0),
                    divisor(operand(1), den_positive, power10),
                    operand(2),
                )
                .is_ok();
                super::prove(
                    prover,
                    activator.as_ref(),
                    operand(0),
                    divisor(operand(1), den_positive, power10),
                    operand(2),
                )
            }),
            Box::new(move |verifier, payload| {
                let table = &payload[LABEL];
                let cols = table
                    .data_tracked_oracles_indices()
                    .into_iter()
                    .map(|i| table.tracked_col_oracle_by_ind(i))
                    .collect::<Vec<_>>();
                let fields = cols
                    .iter()
                    .map(|c| c.field_ref().expect("a typed column"))
                    .collect::<Vec<_>>();
                let oracles = cols
                    .iter()
                    .map(|c| c.data_tracked_oracle())
                    .collect::<Vec<_>>();
                let operand = |i: usize| Operand {
                    data: &oracles[i],
                    data_type: fields[i].data_type(),
                };
                let activator = table.activator_tracked_poly();
                super::verify(
                    verifier,
                    activator.as_ref(),
                    operand(0),
                    divisor(operand(1), den_positive, power10),
                    operand(2),
                )
            }),
        );
        let id = gadget.id();
        let fields = ["n", "d", "q"]
            .iter()
            .zip(&self.types)
            .map(|(name, data_type)| Arc::new(Field::new(*name, data_type.clone(), false)))
            .collect::<Vec<_>>();
        let mut schema_fields = fields
            .iter()
            .map(|f| f.as_ref().clone())
            .collect::<Vec<_>>();
        schema_fields.push(ACTIVATOR_FIELD.as_ref().clone());
        let spec = TableSpec {
            schema: Schema::new(schema_fields),
            log_size: 2,
            cols: vec![
                (fields[0].clone(), self.num.into_iter().map(int).collect()),
                (fields[1].clone(), self.den.into_iter().map(int).collect()),
                (fields[2].clone(), self.quot),
            ],
            activator: Some(self.activator.into_iter().map(int).collect()),
        };
        let result = run_gadget_pipeline(
            GadgetHarness::<B>::builder(16)
                .with_gadget(gadget)
                .with_table(id, LABEL, spec)
                .build(),
        );
        let honest = *honest.lock().unwrap();
        (result, honest)
    }

    fn accepted(self) {
        let (result, honest) = self.run();
        result.expect("the division verifies");
        assert!(honest, "honest_check rejected a true division");
    }

    fn rejected(self) {
        let (result, honest) = self.run();
        assert!(!honest, "honest_check accepted a false division");
        assert_rejected(result);
    }
}

#[test]
fn truncation_toward_zero_accepted() {
    Case::int64([7, -7, 7, -7], [2, 2, -2, -2], [3, -3, -3, 3]).accepted();
    // |X| < |D| gives 0; an exact division has no remainder.
    Case::int64([0, 1, -1, 6], [5, 5, 5, 3], [0, 0, 0, 2]).accepted();
}

#[test]
fn rounding_away_from_zero_rejected() {
    Case::int64([7, 1, 1, 1], [2, 1, 1, 1], [4, 1, 1, 1]).rejected();
    Case::int64([-7, 1, 1, 1], [2, 1, 1, 1], [-4, 1, 1, 1]).rejected();
}

#[test]
fn quotient_too_small_rejected() {
    Case::int64([7, 1, 1, 1], [2, 1, 1, 1], [2, 1, 1, 1]).rejected();
}

#[test]
fn field_quotient_rejected() {
    // `7·2⁻¹` satisfies `X = Q·D` in the field with no remainder.
    let mut case = Case::int64([7, 1, 1, 1], [2, 1, 1, 1], [0, 1, 1, 1]);
    case.quot[0] = int(7) * int(2).inverse().unwrap();
    case.rejected();
}

#[test]
fn zero_denominator_rejected() {
    Case::int64([0, 1, 1, 1], [0, 1, 1, 1], [0, 1, 1, 1]).rejected();
}

#[test]
fn decimal_scales_aligned() {
    // 7.00 / 2 at the quotient scale 6: 7_000_000 / 2 = 3_500_000.
    let mut case = Case::int64([700, -1, 250, 0], [2, 3, 4, 7], [0; 4]);
    case.types = [
        DataType::Decimal128(10, 2),
        DataType::Int64,
        DataType::Decimal128(14, 6),
    ];
    case.quot = [3_500_000i64, -3_333, 625_000, 0]
        .into_iter()
        .map(int)
        .collect();
    let forged = Case {
        quot: [3_500_001i64, -3_333, 625_000, 0]
            .into_iter()
            .map(int)
            .collect(),
        types: case.types.clone(),
        num: case.num.clone(),
        den: case.den.clone(),
        activator: case.activator.clone(),
        den_positive: false,
        power10: None,
    };
    case.accepted();
    forged.rejected();
}

#[test]
fn inactive_rows_are_not_checked() {
    let mut case = Case::int64([7, 5, -9, 1], [2, 0, 4, 1], [3, 99, -2, 1]);
    case.activator = vec![1, 0, 1, 1];
    // The row with a zero denominator is inactive.
    case.accepted();
}

#[test]
fn positive_denominator_must_be_positive() {
    let mut case = Case::int64([7, 4, 1, 1], [2, 2, 1, 1], [3, 2, 1, 1]);
    case.den_positive = true;
    case.accepted();
    let mut case = Case::int64([7, 4, 1, 1], [-2, 2, 1, 1], [-3, 2, 1, 1]);
    case.den_positive = true;
    case.rejected();
}

/// A decimal rescale from scale `from` to scale `to`, by the public `10^k`.
fn rescale(from: DataType, to: DataType, num: [i64; 4], quot: [i64; 4]) -> Case {
    let rounding = if matches!(to, DataType::Decimal128(..)) {
        Rounding::HalfAwayFromZero
    } else {
        Rounding::TowardZero
    };
    let mut case = Case::int64(num, [1; 4], quot);
    case.types = [from, DataType::Int64, to];
    case.power10 = Some(rounding);
    case
}

#[test]
fn rescale_rounds_half_away_from_zero() {
    let (from, to) = (DataType::Decimal128(10, 4), DataType::Decimal128(10, 2));
    // 1.2345, 1.2350, -1.2350, -1.2349 at scale 2.
    let num = [12345, 12350, -12350, -12349];
    rescale(from.clone(), to.clone(), num, [123, 124, -124, -123]).accepted();
    // Ties rounded toward zero.
    rescale(from.clone(), to.clone(), num, [123, 123, -124, -123]).rejected();
    rescale(from, to, num, [123, 124, -123, -123]).rejected();
}

#[test]
fn rescale_to_an_integer_truncates() {
    let from = DataType::Decimal128(10, 2);
    let num = [799, -799, 50, 0];
    rescale(from.clone(), DataType::Int64, num, [7, -7, 0, 0]).accepted();
    rescale(from, DataType::Int64, num, [8, -7, 0, 0]).rejected();
}
