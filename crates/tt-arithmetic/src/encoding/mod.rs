// Segment types: `EncodedSegment`, `SideSegmentInfo`, `SideColData`, plus the
// internal `auto_segments` wrapper used by encoders that don't assign
// role-specific names.
mod segment;

// Segment-name conventions: the `STRING_*_SUFFIX` constants, the master
// `CHAR_LEVEL_SIDE_POLYS_ENABLED` toggle, and the helpers that recognize /
// enumerate segment names for a given Arrow data type.
mod suffixes;

// The `Encodable` trait every Arrow array implements, plus the two
// `impl_col_adapter_map!` / `impl_col_adapter_unsupported!` macros that reduce
// the boilerplate of adding a new type.
mod encodable;

// Internal helpers shared across encoders: hashing bytes into field elements,
// computing field byte capacity, and shape-shifting per-row vectors into
// per-column ones. Not part of the public API.
mod util;

// `Encodable` implementations for scalar-like Arrow arrays that map
// element-wise via `impl_col_adapter_map!` — bool, all int / uint widths,
// timestamp, date, time, duration, interval-year-month, decimals. Floats
// are intentionally excluded; see `mod other` for the rejection.
mod primitives;

// `Encodable` implementations for string-like Arrow arrays: the
// `encode_utf8_like` core plus `StringArray`, `LargeStringArray`,
// `StringViewArray`. Emits row-domain `{hash, __length}` segments and
// (when `CHAR_LEVEL_SIDE_POLYS_ENABLED`) side-domain `{__chars, __orig_ind,
// __int_ind, __bnd}` segments.
mod strings;

// `Encodable` implementations for everything else — binary array variants,
// `NullArray`, `IntervalDayTime` / `IntervalMonthDayNano`, `DictionaryArray`
// — plus the `impl_col_adapter_unsupported!` invocations that reject
// Float16 / Float32 / Float64 (IEEE bit-cast into a field is not
// arithmetic-meaningful) and list / struct / union / map / run-end arrays.
mod other;

// The top-level dispatcher: `encode_arrow_array_to_field` matches on Arrow
// `DataType` and forwards to the right `Encodable::encode`, plus the
// `scalar_to_fields` / `scalar_to_field` helpers for encoding literals.
mod dispatch;

pub use dispatch::{encode_arrow_array_to_field, scalar_to_field, scalar_to_fields};
pub use encodable::Encodable;
pub use segment::{EncodedSegment, SideColData, SideSegmentInfo};
pub use suffixes::{
    is_segment_of, segment_base_name, segment_suffixes_for_type, side_segment_suffixes_for_type,
    CHAR_LEVEL_SIDE_POLYS_ENABLED, STRING_BND_SUFFIX, STRING_CHARS_SUFFIX, STRING_INT_IND_SUFFIX,
    STRING_LENGTH_SUFFIX, STRING_ORIG_IND_SUFFIX,
};

#[cfg(test)]
mod tests {
    use super::util::encode_hashed_bytes;
    use super::*;
    use ark_ff::Zero;
    use ark_test_curves::bls12_381::Fr;
    use datafusion::arrow::array::{Array, StringArray};
    use datafusion_common::ScalarValue;

    #[test]
    fn single_character_strings_are_inlined() {
        let array = StringArray::from(vec![Some("a"), Some(""), None, Some("Z")]);
        let encoded = <StringArray as Encodable<Fr>>::encode(&array).unwrap();

        // 2 row-domain segments (inlined hash + length) plus, when the
        // char-level toggle is on, 4 side-domain segments (chars,
        // orig_ind, int_ind, bnd). This test asserts only the row-domain
        // shape; the side-domain shape is exercised elsewhere.
        let expected_len = if CHAR_LEVEL_SIDE_POLYS_ENABLED { 6 } else { 2 };
        assert_eq!(encoded.len(), expected_len);
        assert_eq!(encoded[0].suffix, "");
        assert_eq!(encoded[1].suffix, STRING_LENGTH_SUFFIX);
        let hash_col = &encoded[0].values;
        let length_col = &encoded[1].values;
        assert_eq!(hash_col.len(), array.len());
        assert_eq!(length_col.len(), array.len());
        assert_eq!(hash_col[0], Fr::from(97u64));
        assert_eq!(hash_col[1], Fr::zero());
        assert_eq!(hash_col[2], Fr::zero());
        assert_eq!(hash_col[3], Fr::from(90u64));
        assert_eq!(length_col[0], Fr::from(1u64));
        assert_eq!(length_col[1], Fr::zero());
        assert_eq!(length_col[2], Fr::zero());
        assert_eq!(length_col[3], Fr::from(1u64));
    }

    #[test]
    fn multi_character_strings_are_hashed() {
        let array = StringArray::from(vec![Some("foo"), Some("bar"), None, Some("baz")]);
        let encoded = <StringArray as Encodable<Fr>>::encode(&array).unwrap();

        let expected_len = if CHAR_LEVEL_SIDE_POLYS_ENABLED { 6 } else { 2 };
        assert_eq!(encoded.len(), expected_len);
        assert_eq!(encoded[0].suffix, "");
        assert_eq!(encoded[1].suffix, STRING_LENGTH_SUFFIX);
        let hash_col = &encoded[0].values;
        let length_col = &encoded[1].values;
        assert_eq!(hash_col.len(), array.len());
        assert_eq!(length_col.len(), array.len());
        assert_eq!(hash_col[0], encode_hashed_bytes::<Fr>(b"foo")[0]);
        assert_eq!(hash_col[1], encode_hashed_bytes::<Fr>(b"bar")[0]);
        assert_eq!(hash_col[2], Fr::zero());
        assert_eq!(hash_col[3], encode_hashed_bytes::<Fr>(b"baz")[0]);
        assert_eq!(length_col[0], Fr::from(3u64));
        assert_eq!(length_col[1], Fr::from(3u64));
        assert_eq!(length_col[2], Fr::zero());
        assert_eq!(length_col[3], Fr::from(3u64));
    }

    #[test]
    fn string_scalar_encodes_to_multiple_segments() {
        let scalar = ScalarValue::Utf8(Some("hello".to_string()));
        let segments = scalar_to_fields::<Fr>(&scalar).expect("scalar should encode");
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].suffix, "");
        assert_eq!(segments[1].suffix, STRING_LENGTH_SUFFIX);
        assert_eq!(segments[1].values, vec![Fr::from(5u64)]);
        // scalar_to_field's single-field convenience refuses multi-segment scalars
        assert!(scalar_to_field::<Fr>(&scalar).is_none());
    }

    // #[test]
    // fn large_string_array_follows_same_rules() {
    //     let array = LargeStringArray::from(vec![Some("x"), Some("yz"),
    // None]);     let encoded = <LargeStringArray as
    // Encodable<Fr>>::encode(&array).unwrap();

    //     assert_eq!(encoded.len(), 1);
    //     let column = &encoded[0];
    //     assert_eq!(column[0], Fr::from(120u64));
    //     assert_eq!(column[1], encode_hashed_bytes::<Fr>(b"yz")[0]);
    //     assert_eq!(column[2], Fr::zero());
    // }

    // #[test]
    // fn string_view_array_matches_behavior() {
    //     let array = StringViewArray::from(vec![Some("m"), Some("no"), None]);
    //     let encoded = <StringViewArray as
    // Encodable<Fr>>::encode(&array).unwrap();

    //     assert_eq!(encoded.len(), 1);
    //     let column = &encoded[0];
    //     assert_eq!(column[0], Fr::from(109u64));
    //     assert_eq!(column[1], encode_hashed_bytes::<Fr>(b"no")[0]);
    //     assert_eq!(column[2], Fr::zero());
    // }
}
