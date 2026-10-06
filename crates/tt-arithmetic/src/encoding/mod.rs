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
// `{hash, __length}` segments, optionally the fingerprint limbs
// `{__fp0 … __fp31}` and the side-domain
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
    encode_arrow_array_to_field, encode_arrow_array_to_field_with_options, scalar_to_field,
    scalar_to_fields,
};
pub use encodable::{
    Encodable, EncodeOptions, FingerprintLimbs, FingerprintSelection, selected_limbs,
};
pub use segment::{
    EncodedSegment, SideColData, SideSegmentInfo, is_segment_of, segment_base_name,
    segment_suffixes_for_type, side_segment_suffixes_for_type,
};
pub use strings::{
    STRING_BND_SUFFIX, STRING_CHARS_SUFFIX, STRING_FINGERPRINT_LIMB_PREFIX, STRING_INT_IND_SUFFIX,
    STRING_LENGTH_SUFFIX, STRING_ORIG_IND_SUFFIX, fingerprint_limb_of, fingerprint_limb_suffix,
    fingerprint_segment_suffixes,
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

        // 2 row-domain value segments (inlined hash + length) and 4
        // side-domain segments (chars, orig_ind, int_ind, bnd); a column
        // with no name has no rule, so no fingerprint limbs. This test
        // asserts only the value segments; the other shapes are exercised
        // elsewhere.
        let expected_len = 2 + 4;
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

        let expected_len = 2 + 4;
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

    /// Each string column is fingerprinted under its OWN rule, and a column
    /// the table's rules do not mention emits no limbs at all. The rules are
    /// process-global, so this test owns them for its duration.
    #[test]
    fn each_column_is_fingerprinted_under_its_own_rule() {
        use crate::fingerprint::{
            FingerprintConfig, FingerprintRules, FingerprintScheme, NUM_BINS, NUM_LIMBS,
            configure_rules, limb, reset_rules,
        };
        use datafusion::arrow::array::ArrayRef;
        use std::collections::BTreeMap;
        use std::sync::{Arc, Mutex, OnceLock};

        static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
        let _held = GUARD.get_or_init(|| Mutex::new(())).lock();
        reset_rules();

        // `mine` puts every character in bin 0; `other` is a different table's
        // column and must not be confused with it.
        let only_bin_0 = |name: &str| FingerprintConfig {
            name: name.to_string(),
            bins: NUM_BINS,
            chars: ('a'..='z').map(|c| (c.to_string(), 0usize)).collect(),
            bigrams: BTreeMap::new(),
            trigrams: BTreeMap::new(),
            precedence: BTreeMap::new(),
        };
        let mut rules = FingerprintRules::default();
        rules.columns.insert("mine".into(), only_bin_0("mine"));
        configure_rules(rules).unwrap();

        let strings = [Some("quickly final"), None, Some(""), Some("deposits")];
        let array: ArrayRef = Arc::new(StringArray::from(strings.to_vec()));
        let encode = |column| {
            encode_arrow_array_to_field_with_options::<Fr>(
                &array,
                EncodeOptions {
                    side: false,
                    fingerprint: FingerprintLimbs::All,
                    column,
                },
            )
            .unwrap()
        };

        // The ruled column commits every limb its rule reaches, each
        // holding that limb of the rule's fingerprint.
        let mine = encode(Some("mine"));
        assert_eq!(mine.len(), 2 + NUM_LIMBS);
        let scheme = FingerprintScheme::from_config(only_bin_0("mine")).unwrap();
        for j in 0..NUM_LIMBS {
            let segment = &mine[2 + j];
            assert_eq!(segment.suffix, fingerprint_limb_suffix(j));
            assert_eq!(
                segment_base_name(&format!("c{}", segment.suffix)),
                Some("c")
            );
            for (row, s) in strings.iter().enumerate() {
                let expected = scheme.fingerprint(s.unwrap_or("").as_bytes());
                assert_eq!(
                    segment.value_as_field(row),
                    Fr::from(u64::from(limb(&expected, j)))
                );
            }
        }

        // A query's selection emits only the chosen limbs, in order; limbs
        // past the rule's width are ignored.
        let chosen: std::collections::BTreeSet<usize> = [5, 0, NUM_LIMBS + 7].into();
        let some = encode_arrow_array_to_field_with_options::<Fr>(
            &array,
            EncodeOptions {
                side: false,
                fingerprint: FingerprintLimbs::Only(&chosen),
                column: Some("mine"),
            },
        )
        .unwrap();
        let suffixes: Vec<&str> = some[2..].iter().map(|s| s.suffix.as_str()).collect();
        assert_eq!(
            suffixes,
            [fingerprint_limb_suffix(0), fingerprint_limb_suffix(5)]
        );

        // A column with no rule is not fingerprinted at all.
        assert_eq!(encode(Some("unruled")).len(), 2);
        reset_rules();
    }

    #[test]
    fn fingerprint_limbs_need_the_flag_and_a_ruled_column() {
        use crate::fingerprint::NUM_LIMBS;
        use datafusion::arrow::array::ArrayRef;
        use std::sync::Arc;

        let strings = [Some("quickly final"), None, Some(""), Some("deposits")];
        let array: ArrayRef = Arc::new(StringArray::from(strings.to_vec()));
        let without =
            encode_arrow_array_to_field_with_options::<Fr>(&array, EncodeOptions::NONE).unwrap();
        assert_eq!(without.len(), 2);
        // A string with no column has no rule, so no limbs either.
        let unnamed = encode_arrow_array_to_field_with_options::<Fr>(
            &array,
            EncodeOptions {
                side: false,
                fingerprint: FingerprintLimbs::All,
                column: None,
            },
        )
        .unwrap();
        assert_eq!(unnamed.len(), 2);
        assert_eq!(segment_base_name(&format!("c__fp{NUM_LIMBS}")), None);
        assert_eq!(segment_base_name("c__fp01"), None);
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
