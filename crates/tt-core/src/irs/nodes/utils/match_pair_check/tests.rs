//! A string key is sorted on its hash limbs, so a duplicated union row is a
//! duplicated row of range-checked integers, which the strict sort rejects.

use std::sync::Arc;

use arithmetic::encoding::{encode_arrow_array_to_field, hash_slot_limb_widths, hash_slot_limbs};
use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use ark_ff::Zero;
use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::array::{
    Array, ArrayRef, BooleanArray, Int64Array, StringArray, UInt8Array, UInt16Array,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::prelude::DataFrame;

use super::hints::{UnionLayout, build_union_hint_df};
use crate::irs::nodes::utils::contig_sort::tests::{assert_rejected, run};
use crate::irs::nodes::utils::contig_sort::{SortConfig, UniformConfig};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const KEY: &str = "__mp_key_0";

/// The sort check MatchPair runs on `û`.
fn strict_ascending() -> SortConfig {
    SortConfig::Uniform(UniformConfig {
        asc: true,
        strict: true,
    })
}

fn hash_slots(strings: &[&str]) -> Vec<F> {
    let array: ArrayRef = Arc::new(StringArray::from(strings.to_vec()));
    encode_arrow_array_to_field::<F>(&array).unwrap()[0]
        .iter_values()
        .collect()
}

/// The strict sort over the limb columns of `strings`' hashes, in the given
/// row order, with honest ties.
fn sort_on_limbs(strings: &[&str]) -> Result<(), ark_piop::errors::SnarkError> {
    let limbs: Vec<Vec<u16>> = hash_slots(strings)
        .into_iter()
        .map(hash_slot_limbs::<F>)
        .collect();
    let widths = hash_slot_limb_widths::<F>();
    let names: Vec<String> = (0..widths.len()).map(|j| format!("limb{j}")).collect();
    let keys: Vec<(&str, DataType, Vec<F>)> = widths
        .iter()
        .enumerate()
        .map(|(j, width)| {
            let dtype = if *width == 8 {
                DataType::UInt8
            } else {
                DataType::UInt16
            };
            let values = limbs.iter().map(|row| F::from(row[j])).collect();
            (names[j].as_str(), dtype, values)
        })
        .collect();
    let tie_names: Vec<String> = (1..widths.len()).map(|k| format!("tie_{k}")).collect();
    let ties: Vec<(&str, Vec<F>)> = tie_names
        .iter()
        .enumerate()
        .map(|(idx, name)| {
            let k = idx + 1;
            let values = (0..limbs.len())
                .map(|row| {
                    let tied = row + 1 < limbs.len() && limbs[row][..k] == limbs[row + 1][..k];
                    F::from(u64::from(tied))
                })
                .collect();
            (name.as_str(), values)
        })
        .collect();
    run(strict_ascending(), &keys, &ties, &[])
}

/// `strings` in the order of their hash limbs.
fn in_limb_order(mut strings: Vec<&str>) -> Vec<&str> {
    strings.sort_by_key(|s| hash_slot_limbs(hash_slots(&[s])[0]));
    strings
}

#[test]
fn distinct_strings_sorted_on_their_hash_limbs_verify() {
    let strings = in_limb_order(vec!["FRANCE", "GERMANY", "JAPAN", "PERU"]);
    sort_on_limbs(&strings).expect("distinct hashes sorted on their limbs verify");
}

#[test]
fn a_duplicated_string_key_is_rejected() {
    let mut strings = in_limb_order(vec!["FRANCE", "GERMANY", "JAPAN"]);
    strings.insert(1, strings[0]);
    assert_rejected(sort_on_limbs(&strings));
}

#[test]
fn a_string_key_sorts_on_range_checked_limbs() {
    let keys = [
        Field::new(KEY, DataType::Utf8, true),
        Field::new("__mp_key_1", DataType::Int64, true),
    ];
    let layout = UnionLayout::new::<F>(&keys).unwrap();
    let names: Vec<&str> = layout
        .sort_fields
        .iter()
        .map(|f| f.name().as_str())
        .collect();
    assert_eq!(names[0], "__mp_key_1");
    assert_eq!(names.len(), 1 + hash_slot_limb_widths::<F>().len());
    assert!(!names.contains(&KEY));
    assert!(
        layout.sort_fields[1..]
            .iter()
            .all(|f| matches!(f.data_type(), DataType::UInt8 | DataType::UInt16))
    );
}

#[test]
fn a_key_without_an_order_preserving_encoding_is_an_error() {
    let keys = [Field::new(KEY, DataType::Float64, true)];
    assert!(UnionLayout::new::<F>(&keys).is_err());
}

fn keys_df(strings: &[&str]) -> DataFrame {
    let n = strings.len();
    let schema = Arc::new(Schema::new(vec![
        Field::new(KEY, DataType::Utf8, true),
        Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
        Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
    ]));
    let batch = RecordBatch::try_new(
        schema,
        vec![
            Arc::new(StringArray::from(strings.to_vec())),
            Arc::new(Int64Array::from_iter_values(0..n as i64)),
            Arc::new(BooleanArray::from(vec![true; n])),
        ],
    )
    .unwrap();
    crate::session::session_context().read_batch(batch).unwrap()
}

#[test]
fn the_union_is_distinct_strictly_sorted_and_carries_the_limbs() {
    let layout = UnionLayout::new::<F>(&[Field::new(KEY, DataType::Utf8, true)]).unwrap();
    let (union, t) = build_union_hint_df::<F>(
        keys_df(&["PERU", "JAPAN", "JAPAN"]),
        keys_df(&["JAPAN", "FRANCE"]),
        &layout,
    )
    .unwrap();
    assert_eq!(t, 3);
    let batches = crate::session::block_on(union.collect()).unwrap();
    let batch = &batches[0];
    assert_eq!(batch.num_rows(), 4);

    let key = batch.column_by_name(KEY).unwrap();
    let slots: Vec<F> = encode_arrow_array_to_field::<F>(key).unwrap()[0]
        .iter_values()
        .collect();
    let limbs: Vec<Vec<u16>> = (0..4)
        .map(|row| {
            layout.slots[0]
                .limbs
                .iter()
                .map(|(field, _)| {
                    let column = batch.column_by_name(field.name()).unwrap();
                    match column.data_type() {
                        DataType::UInt8 => u16::from(
                            column
                                .as_any()
                                .downcast_ref::<UInt8Array>()
                                .unwrap()
                                .value(row),
                        ),
                        _ => column
                            .as_any()
                            .downcast_ref::<UInt16Array>()
                            .unwrap()
                            .value(row),
                    }
                })
                .collect()
        })
        .collect();
    for row in 0..4 {
        assert_eq!(limbs[row], hash_slot_limbs(slots[row]));
    }
    assert!(limbs[0] < limbs[1] && limbs[1] < limbs[2]);
    assert!(key.is_null(3));
    assert!(slots[3].is_zero());
}
