// Segment types and the segment naming conventions (`""` primary, `__enc<N>`).
mod segment;

mod encodable;
mod util;

// Bool, integers, dates, times, durations, decimals.
mod primitives;

// Row-domain `{hash, __length}`, optional fingerprint limbs `__fp{j}`, and the
// char-level side segments `{__chars, __orig_ind, __int_ind, __bnd}`.
mod strings;

// Binary, null and interval arrays; rejects floats and nested types.
mod other;

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
    fn negative_decimals_encode_as_field_negations() {
        use datafusion::arrow::array::Decimal128Array;
        let array = Decimal128Array::from(vec![Some(-1234), Some(5), None, Some(0)])
            .with_precision_and_scale(15, 2)
            .unwrap();
        let encoded = <Decimal128Array as Encodable<Fr>>::encode(&array).unwrap();
        let values: Vec<Fr> = encoded[0].iter_values().collect();
        assert_eq!(
            values,
            vec![-Fr::from(1234u64), Fr::from(5u64), Fr::zero(), Fr::zero()]
        );
    }

    #[test]
    fn decimal256_is_not_supported() {
        use datafusion::arrow::array::{ArrayRef, Decimal256Array};
        use datafusion::arrow::datatypes::i256;
        let array: ArrayRef = std::sync::Arc::new(
            Decimal256Array::from(vec![Some(i256::MINUS_ONE), Some(i256::ONE)])
                .with_precision_and_scale(76, 0)
                .unwrap(),
        );
        assert!(matches!(
            encode_arrow_array_to_field::<Fr>(&array),
            Err(crate::errors::EncodeError::TypeNotSupported(_))
        ));
        let scalar = ScalarValue::Decimal256(Some(i256::MINUS_ONE), 76, 0);
        assert!(scalar_to_field::<Fr>(&scalar).is_none());
    }

    #[test]
    fn single_character_strings_are_inlined() {
        let array = StringArray::from(vec![Some("a"), Some(""), None, Some("Z")]);
        let encoded = <StringArray as Encodable<Fr>>::encode(&array).unwrap();

        // 2 row-domain value segments (inlined hash + length) and 4
        // side-domain segments (chars, orig_ind, int_ind, bnd); a column
        // with no name has no rule, so no fingerprint limbs.
        let expected_len = 2 + 4;
        assert_eq!(encoded.len(), expected_len);
        assert_eq!(encoded[0].suffix, "");
        assert_eq!(encoded[1].suffix, STRING_LENGTH_SUFFIX);
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
        // `scalar_to_field` refuses multi-segment scalars.
        assert!(scalar_to_field::<Fr>(&scalar).is_none());
    }

    /// Each string column is fingerprinted under its own rule, and a column
    /// the table's rules do not mention emits no limbs. The rules are
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
}
