// Segment types and the segment naming conventions (`""` primary, `__enc<N>`).
mod segment;

mod encodable;
mod util;

// Bool, integers, dates, times, durations, decimals.
mod primitives;

// Row-domain `{hash, __length}`, optional fingerprint limbs `__fp{j}` and rank
// `__rank`, and the char-level side segments
// `{__chars, __orig_ind, __int_ind, __bnd}`.
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
    STRING_LENGTH_SUFFIX, STRING_ORIG_IND_SUFFIX, STRING_RANK_SUFFIX, dense_byte_ranks,
    fingerprint_limb_of, fingerprint_limb_suffix, fingerprint_segment_suffixes,
};
pub use util::{hash_slot_limb_widths, hash_slot_limbs, is_hashed_type};

#[cfg(test)]
mod tests {
    use super::util::encode_hashed_bytes;
    use super::*;
    use ark_ff::Zero;
    use ark_test_curves::bls12_381::Fr;
    use datafusion::arrow::array::{Array, StringArray};
    use datafusion::arrow::datatypes::DataType;
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
    fn a_hash_takes_one_slot_split_into_16_bit_limbs() {
        assert_eq!(
            segment_suffixes_for_type::<Fr>(&DataType::Binary),
            vec![String::new()]
        );
        let widths = hash_slot_limb_widths::<Fr>();
        assert_eq!(widths.len(), 16);
        assert_eq!(widths.iter().sum::<u32>(), 8 * util::HASH_BYTES as u32);
        assert_eq!(widths[0], 8);
    }

    #[test]
    fn hash_slot_limbs_recompose_the_slot() {
        let slot = encode_hashed_bytes::<Fr>(b"a string longer than one byte")[0];
        let limbs = hash_slot_limbs(slot);
        let recomposed = hash_slot_limb_widths::<Fr>()
            .into_iter()
            .zip(&limbs)
            .fold(Fr::zero(), |acc, (width, limb)| {
                acc * Fr::from(1u64 << width) + Fr::from(*limb)
            });
        assert_eq!(recomposed, slot);
        assert!(limbs[0] < 1 << 8);
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
                    rank: false,
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
                rank: false,
            },
        )
        .unwrap();
        let suffixes: Vec<&str> = some[2..].iter().map(|s| s.suffix.as_str()).collect();
        assert_eq!(
            suffixes,
            [fingerprint_limb_suffix(0), fingerprint_limb_suffix(5)]
        );

        // The rank follows the selected limbs.
        let ranked = encode_arrow_array_to_field_with_options::<Fr>(
            &array,
            EncodeOptions {
                side: false,
                fingerprint: FingerprintLimbs::Only(&chosen),
                column: Some("mine"),
                rank: true,
            },
        )
        .unwrap();
        let suffixes: Vec<&str> = ranked.iter().map(|s| s.suffix.as_str()).collect();
        assert_eq!(
            suffixes,
            [
                "",
                STRING_LENGTH_SUFFIX,
                &fingerprint_limb_suffix(0),
                &fingerprint_limb_suffix(5),
                STRING_RANK_SUFFIX
            ]
        );

        // A column with no rule is not fingerprinted at all.
        assert_eq!(encode(Some("unruled")).len(), 2);
        reset_rules();
    }

    #[test]
    fn ranks_follow_byte_order() {
        let values: Vec<Option<&[u8]>> = [
            Some("b"),
            Some("abc"),
            Some(""),
            Some("ab"),
            None,
            Some("abc"),
            Some("B"),
            Some("\u{e9}"),
        ]
        .into_iter()
        .map(|s| s.map(str::as_bytes))
        .collect();
        let ranks = dense_byte_ranks(values.iter().copied());
        // "" < "B" < "ab" < "abc" < "b" < "é": a prefix ranks below its
        // extensions and equal strings share a rank.
        assert_eq!(ranks, vec![4, 3, 0, 2, 0, 3, 1, 5]);
        for (i, a) in values.iter().enumerate() {
            for (j, b) in values.iter().enumerate() {
                if let (Some(a), Some(b)) = (a, b) {
                    assert_eq!(ranks[i].cmp(&ranks[j]), a.cmp(b), "{a:?} vs {b:?}");
                }
            }
        }
    }

    #[test]
    fn null_padding_does_not_shift_ranks() {
        let unpadded = dense_byte_ranks([Some(&b"x"[..]), Some(&b"y"[..])]);
        let padded = dense_byte_ranks([None, Some(&b"x"[..]), None, Some(&b"y"[..])]);
        assert_eq!(unpadded, vec![0, 1]);
        assert_eq!(padded, vec![0, 0, 0, 1]);
    }

    /// The rank comes after the row-domain value segments and before the
    /// side segments, and only when asked for: no default set, nor a type's
    /// suffix list, has it.
    #[test]
    fn rank_segment_is_opt_in_and_placed_after_the_values() {
        use datafusion::arrow::array::ArrayRef;
        use std::sync::Arc;

        // NULL padding is not counted, and a column of one-byte strings
        // (whose hash slot is the byte) is ranked too.
        for (strings, ranks) in [
            (
                vec![Some("pear"), None, Some("apple"), None],
                [1u64, 0, 0, 0],
            ),
            (vec![Some("b"), None, Some(""), Some("a")], [2, 0, 0, 1]),
        ] {
            let array: ArrayRef = Arc::new(StringArray::from(strings));
            let encoded = encode_arrow_array_to_field_with_options::<Fr>(
                &array,
                EncodeOptions {
                    side: true,
                    fingerprint: FingerprintLimbs::None,
                    column: Some("c"),
                    rank: true,
                },
            )
            .unwrap();
            let suffixes: Vec<&str> = encoded.iter().map(|s| s.suffix.as_str()).collect();
            assert_eq!(
                suffixes,
                [
                    "",
                    STRING_LENGTH_SUFFIX,
                    STRING_RANK_SUFFIX,
                    STRING_CHARS_SUFFIX,
                    STRING_ORIG_IND_SUFFIX,
                    STRING_INT_IND_SUFFIX,
                    STRING_BND_SUFFIX
                ]
            );
            let rank = &encoded[2];
            assert!(!rank.is_side());
            let values: Vec<Fr> = rank.iter_values().collect();
            assert_eq!(values, ranks.map(Fr::from));
        }

        let array: ArrayRef = Arc::new(StringArray::from(vec![Some("a"), Some("b")]));
        for options in [EncodeOptions::ALL, EncodeOptions::NONE] {
            let encoded = encode_arrow_array_to_field_with_options::<Fr>(&array, options).unwrap();
            assert!(encoded.iter().all(|s| s.suffix != STRING_RANK_SUFFIX));
        }
        assert!(
            !segment_suffixes_for_type::<Fr>(&DataType::Utf8)
                .iter()
                .any(|s| s == STRING_RANK_SUFFIX)
        );
        assert_eq!(segment_base_name("c__rank"), Some("c"));
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
                rank: false,
            },
        )
        .unwrap();
        assert_eq!(unnamed.len(), 2);
        assert_eq!(segment_base_name(&format!("c__fp{NUM_LIMBS}")), None);
        assert_eq!(segment_base_name("c__fp01"), None);
    }
}
