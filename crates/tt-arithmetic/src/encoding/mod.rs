// Segment types + naming infrastructure. Value side: `EncodedSegment`,
// `SideSegmentInfo`, `SideColData`, plus the internal `auto_segments`
// wrapper for encoders that don't assign role-specific names. Name side:
// the `""` primary convention, the `__enc<N>` auto-numbered convention,
// and the type-family dispatchers (`segment_base_name`, `is_segment_of`,
// `segment_suffixes_for_type`, `side_segment_suffixes_for_type`).
// Family-specific suffix constants live with their encoders — see
// `mod strings` for the string family.
mod segment;

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

// String-family: `Encodable` implementations for `StringArray`,
// `LargeStringArray`, `StringViewArray` (via the shared `encode_utf8_like`
// core) plus the string-specific suffix constants and dispatcher helpers
// (`STRING_LENGTH_SUFFIX`, `STRING_CHARS_SUFFIX`, `STRING_ORIG_IND_SUFFIX`,
// `STRING_INT_IND_SUFFIX`, `STRING_BND_SUFFIX`). Emits row-domain
// `{hash, __length}` segments and side-domain
// `{__chars, __orig_ind, __int_ind, __bnd}` segments.
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

pub use dispatch::{
    encode_arrow_array_to_field, encode_arrow_array_to_field_with_side, scalar_to_field,
    scalar_to_fields,
};
pub use encodable::Encodable;
pub use segment::{
    EncodedSegment, SideColData, SideSegmentInfo, is_segment_of, segment_base_name,
    segment_suffixes_for_type, side_segment_suffixes_for_type,
};
pub use strings::{
    STRING_BND_SUFFIX, STRING_CHARS_SUFFIX, STRING_INT_IND_SUFFIX, STRING_LENGTH_SUFFIX,
    STRING_ORIG_IND_SUFFIX,
};
pub use util::validate_fixed_width_encoding_safety;

#[cfg(test)]
mod tests {
    use super::util::encode_hashed_bytes;
    use super::*;
    use crate::errors::EncodeError;
    use ark_bn254::Fr as Bn254Fr;
    use ark_ff::{Fp64, MontBackend, MontConfig, PrimeField, Zero};
    use ark_test_curves::bls12_381::{Fq, Fr};
    use datafusion::arrow::array::{
        Array, ArrayRef, Decimal128Array, Decimal256Array, IntervalMonthDayNanoArray, StringArray,
    };
    use datafusion::arrow::datatypes::{DataType, Field, IntervalMonthDayNanoType, i256};
    use datafusion_common::ScalarValue;
    use std::sync::Arc;

    #[derive(MontConfig)]
    #[modulus = "17"]
    #[generator = "3"]
    struct TinyFieldConfig;
    type TinyField = Fp64<MontBackend<TinyFieldConfig, 1>>;

    fn assert_type_not_supported<T>(result: Result<T, EncodeError>, expected: &str) {
        assert!(
            matches!(result, Err(EncodeError::TypeNotSupported(ref name)) if name == expected),
            "expected unsupported type {expected}"
        );
    }

    #[test]
    fn single_character_strings_are_inlined() {
        let array = StringArray::from(vec![Some("a"), Some(""), None, Some("Z")]);
        let encoded = <StringArray as Encodable<Fr>>::encode(&array).unwrap();

        // 2 row-domain segments (inlined hash + length) plus, when the
        // char-level toggle is on, 4 side-domain segments (chars,
        // orig_ind, int_ind, bnd). This test asserts only the row-domain
        // shape; the side-domain shape is exercised elsewhere.
        let expected_len = 6; // {hash, __length} + 4 side segments
        assert_eq!(encoded.len(), expected_len);
        assert_eq!(encoded[0].suffix, "");
        assert_eq!(encoded[1].suffix, STRING_LENGTH_SUFFIX);
        // Materialize through the new accessor so the test survives whatever
        // native backing the encoder picks (string hashes stay Fs; the
        // length column may compress to U8s).
        let hash_col: Vec<Fr> = encoded[0].iter_values().collect();
        let length_col: Vec<Fr> = encoded[1].iter_values().collect();
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

        let expected_len = 6; // {hash, __length} + 4 side segments
        assert_eq!(encoded.len(), expected_len);
        assert_eq!(encoded[0].suffix, "");
        assert_eq!(encoded[1].suffix, STRING_LENGTH_SUFFIX);
        let hash_col: Vec<Fr> = encoded[0].iter_values().collect();
        let length_col: Vec<Fr> = encoded[1].iter_values().collect();
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
        assert_eq!(
            segments[1].iter_values().collect::<Vec<_>>(),
            vec![Fr::from(5u64)]
        );
        // scalar_to_field's single-field convenience refuses multi-segment scalars
        assert!(scalar_to_field::<Fr>(&scalar).is_none());
    }

    #[test]
    fn decimal256_requires_a_wider_field_for_injective_encoding() {
        // This is exactly `(2^256 mod p) - 1` for the BN254 scalar-field
        // modulus, in little-endian form. It is a positive, precision-76
        // Decimal256 value and is distinct from -1.
        let colliding_positive = i256::from_le_bytes([
            0xfa, 0xff, 0xff, 0x4f, 0x1c, 0x34, 0x96, 0xac, 0x29, 0xcd, 0x60, 0x9f, 0x95, 0x76,
            0xfc, 0x36, 0x2e, 0x46, 0x79, 0x78, 0x6f, 0xa3, 0x6e, 0x66, 0x2f, 0xdf, 0x07, 0x9a,
            0xc1, 0x77, 0x0a, 0x0e,
        ]);
        let minus_one = i256::MINUS_ONE;
        assert_ne!(minus_one, colliding_positive);

        // Document the old, unsafe encoding precisely: reducing both raw
        // 256-bit representations modulo p produces the same field element.
        assert_eq!(
            Bn254Fr::from_le_bytes_mod_order(&minus_one.to_le_bytes()),
            Bn254Fr::from_le_bytes_mod_order(&colliding_positive.to_le_bytes())
        );

        let decimal = Decimal256Array::from(vec![Some(minus_one), Some(colliding_positive)])
            .with_precision_and_scale(76, 0)
            .expect("both values fit Decimal256(76, 0)");
        decimal
            .validate_decimal_precision(76)
            .expect("both values are valid precision-76 decimals");

        // Reject schema-only validation, direct trait use, and the public
        // Arrow dispatcher. Keeping the rejection at the trait boundary also
        // protects any future nested encoder that delegates to `Encodable`.
        assert_type_not_supported(
            validate_fixed_width_encoding_safety::<Bn254Fr>(decimal.data_type()),
            "Decimal256 requires a field modulus wider than 256 bits",
        );
        assert_type_not_supported(
            validate_fixed_width_encoding_safety::<Fr>(decimal.data_type()),
            "Decimal256 requires a field modulus wider than 256 bits",
        );
        let nested_decimal = DataType::List(Arc::new(Field::new(
            "item",
            DataType::Decimal256(76, 0),
            false,
        )));
        assert_type_not_supported(
            validate_fixed_width_encoding_safety::<Bn254Fr>(&nested_decimal),
            "Decimal256 requires a field modulus wider than 256 bits",
        );
        assert_type_not_supported(
            <Decimal256Array as Encodable<Bn254Fr>>::encode(&decimal),
            "Decimal256 requires a field modulus wider than 256 bits",
        );
        let array: ArrayRef = Arc::new(decimal);
        assert_type_not_supported(
            encode_arrow_array_to_field::<Bn254Fr>(&array),
            "Decimal256 requires a field modulus wider than 256 bits",
        );

        // A modulus wider than the complete 256-bit source representation
        // makes the raw-byte conversion injective. BLS12-381's base field is
        // wide enough, so the same distinct inputs remain distinct.
        validate_fixed_width_encoding_safety::<Fq>(array.data_type())
            .expect("BLS12-381 base field is wider than Decimal256");
        let encoded = encode_arrow_array_to_field::<Fq>(&array)
            .expect("Decimal256 encoding should succeed in a field wider than 256 bits");
        assert_eq!(encoded.len(), 1);
        assert_ne!(encoded[0].value_as_field(0), encoded[0].value_as_field(1));

        // Scalar/literal encoding goes through the same dispatcher and must
        // fail closed rather than reintroducing the modular reduction.
        let scalar = ScalarValue::Decimal256(Some(minus_one), 76, 0);
        assert!(scalar_to_fields::<Bn254Fr>(&scalar).is_none());
        assert!(scalar_to_field::<Bn254Fr>(&scalar).is_none());
    }

    #[test]
    fn raw_128_bit_encodings_require_a_wider_modulus() {
        let decimal = Decimal128Array::from(vec![1_i128, -2_i128])
            .with_precision_and_scale(38, 0)
            .expect("values fit Decimal128(38, 0)");
        assert_type_not_supported(
            validate_fixed_width_encoding_safety::<TinyField>(decimal.data_type()),
            "Decimal128 requires a field modulus wider than 128 bits",
        );
        assert_type_not_supported(
            <Decimal128Array as Encodable<TinyField>>::encode(&decimal),
            "Decimal128 requires a field modulus wider than 128 bits",
        );
        assert!(<Decimal128Array as Encodable<Fr>>::encode(&decimal).is_ok());

        let interval = IntervalMonthDayNanoArray::from(vec![
            IntervalMonthDayNanoType::make_value(1, 2, 3),
            IntervalMonthDayNanoType::make_value(-1, -2, -3),
        ]);
        assert_type_not_supported(
            validate_fixed_width_encoding_safety::<TinyField>(interval.data_type()),
            "IntervalMonthDayNano requires a field modulus wider than 128 bits",
        );
        assert_type_not_supported(
            <IntervalMonthDayNanoArray as Encodable<TinyField>>::encode(&interval),
            "IntervalMonthDayNano requires a field modulus wider than 128 bits",
        );
        assert!(<IntervalMonthDayNanoArray as Encodable<Fr>>::encode(&interval).is_ok());
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
