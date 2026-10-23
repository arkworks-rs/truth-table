use ark_ff::PrimeField;
use ark_piop::arithmetic::mat_poly::mle::MLE;
use datafusion::arrow::array::{Array, LargeStringArray, StringArray, StringViewArray};

use crate::errors::EncodeError;
use crate::fingerprint::{NUM_LIMBS, limb, scheme_for_column};

use super::encodable::{Encodable, EncodeOptions, FingerprintLimbs};
use super::segment::{EncodedSegment, auto_segments, auto_suffixes};
use super::util::{encode_hashed_bytes, hash_slot_count, map_indices};

/// Row-domain segment holding each string's byte length.
pub const STRING_LENGTH_SUFFIX: &str = "__length";

/// Limb `j` of a string column `c` is the row-domain segment `c__fp{j}`,
/// holding bin `j` of `fp(c[i])` under the column's
/// [`FingerprintScheme`](crate::fingerprint::FingerprintScheme) as 0 or 1
/// (a limb is [`LIMB_BITS`](crate::fingerprint::LIMB_BITS) = 1 bin). The
/// data owner commits it, like `__length`, so the Pre-Filtering Check can
/// trust it and read only the bins a query tests.
pub const STRING_FINGERPRINT_LIMB_PREFIX: &str = "__fp";

pub fn fingerprint_limb_suffix(j: usize) -> String {
    format!("{STRING_FINGERPRINT_LIMB_PREFIX}{j}")
}

/// The fingerprint limb suffixes a string column emits, in encoder order:
/// the `limbs` selected among the column's own
/// ([`FingerprintScheme::num_limbs`](crate::fingerprint::FingerprintScheme::num_limbs)),
/// none for a column no rule fingerprints. Prover, verifier and encoder
/// resolve it from the same installed rules and the same selection, so
/// they agree.
pub fn fingerprint_segment_suffixes(column: Option<&str>, limbs: FingerprintLimbs) -> Vec<String> {
    let num_limbs = scheme_for_column(column).map_or(0, |s| s.num_limbs());
    limbs
        .select(num_limbs)
        .into_iter()
        .map(fingerprint_limb_suffix)
        .collect()
}

/// Side segment of the column's characters (paper §3.2), one byte per
/// entry: the strings' bytes concatenated in row order, then zeros up to a
/// power of two. Its activator covers the total byte count; the other side
/// segments share this domain.
pub const STRING_CHARS_SUFFIX: &str = "__chars";

/// Origin index (paper §3.2): `orig-ind[c]` is the row of the string that
/// character slot `c` belongs to.
pub const STRING_ORIG_IND_SUFFIX: &str = "__orig_ind";

/// Internal index (paper §3.2): `int-ind[c]` is the position of character
/// slot `c` within its string.
pub const STRING_INT_IND_SUFFIX: &str = "__int_ind";

/// Boundary marker (paper §3.2): `bnd[c]` is 1 iff character slot `c` is
/// the first character of a string.
pub const STRING_BND_SUFFIX: &str = "__bnd";

/// Row-domain value segment suffixes of a string column, in the order
/// `encode_utf8_like` produces them: `hash_slots` auto-numbered entries,
/// then `STRING_LENGTH_SUFFIX`. The fingerprint limbs
/// ([`fingerprint_segment_suffixes`]) follow them when requested.
pub(super) fn string_row_segment_suffixes<F: PrimeField>() -> Vec<String> {
    let hash_slots = hash_slot_count::<F>();
    let mut s = auto_suffixes(hash_slots);
    s.push(STRING_LENGTH_SUFFIX.to_string());
    s
}

/// Side-domain segment suffixes of a string column, in the order
/// `encode_utf8_like` produces them. The prover's and the verifier's
/// tracking passes walk this sequence, so the order is fixed.
pub(super) fn string_side_segment_suffixes() -> Vec<String> {
    vec![
        STRING_CHARS_SUFFIX.to_string(),
        STRING_ORIG_IND_SUFFIX.to_string(),
        STRING_INT_IND_SUFFIX.to_string(),
        STRING_BND_SUFFIX.to_string(),
    ]
}

/// The base column and limb of a fingerprint limb segment name
/// (`c__fp7` → `(c, 7)`).
pub fn fingerprint_limb_of(field_name: &str) -> Option<(&str, usize)> {
    let at = field_name.rfind(STRING_FINGERPRINT_LIMB_PREFIX)?;
    let digits = &field_name[at + STRING_FINGERPRINT_LIMB_PREFIX.len()..];
    let j: usize = digits.parse().ok()?;
    (j < NUM_LIMBS && digits == j.to_string()).then(|| (&field_name[..at], j))
}

/// The source column of a name that ends in a string segment suffix.
pub(super) fn string_segment_base(field_name: &str) -> Option<&str> {
    for suffix in [
        STRING_LENGTH_SUFFIX,
        STRING_CHARS_SUFFIX,
        STRING_ORIG_IND_SUFFIX,
        STRING_INT_IND_SUFFIX,
        STRING_BND_SUFFIX,
    ] {
        if let Some(base) = field_name.strip_suffix(suffix) {
            return Some(base);
        }
    }
    fingerprint_limb_of(field_name).map(|(base, _)| base)
}

fn encode_utf8_like<F, A, GetValue>(
    array: &A,
    short_string_threshold: usize,
    options: EncodeOptions<'_>,
    value_fn: GetValue,
) -> Result<Vec<EncodedSegment<F>>, EncodeError>
where
    F: PrimeField,
    A: Array + Sync,
    GetValue: Copy + Fn(&A, usize) -> &str + Sync + Send,
{
    let rows = array.len();
    // Null rows read as the empty string: hash slots, length and
    // fingerprint of a null are all zero, and it owns no characters.
    let values: Vec<&[u8]> = (0..rows)
        .map(|idx| {
            if array.is_null(idx) {
                &[][..]
            } else {
                value_fn(array, idx).as_bytes()
            }
        })
        .collect();
    let max_len = values.iter().map(|v| v.len()).max().unwrap_or(0);

    let inline_short = max_len <= short_string_threshold && max_len <= 1;
    // An all-null array still produces every segment. The hash takes
    // `hash_slot_count` slots, or one slot holding the byte itself when no
    // string is longer than one byte.
    let hash_slots = if inline_short {
        1
    } else {
        hash_slot_count::<F>()
    };

    let hash_cols: Vec<Vec<F>> = if inline_short {
        vec![
            values
                .iter()
                .map(|v| v.first().map_or_else(F::zero, |&b| F::from(b as u64)))
                .collect(),
        ]
    } else {
        let chunks: Vec<Vec<F>> = map_indices(rows, |idx| {
            if array.is_null(idx) {
                Vec::new()
            } else {
                encode_hashed_bytes::<F>(values[idx])
            }
        });
        (0..hash_slots)
            .map(|slot| {
                chunks
                    .iter()
                    .map(|c| c.get(slot).copied().unwrap_or_else(F::zero))
                    .collect()
            })
            .collect()
    };
    let length_col: Vec<F> = values.iter().map(|v| F::from(v.len() as u64)).collect();

    let mut segments = auto_segments(hash_cols);
    segments.push(EncodedSegment::named(STRING_LENGTH_SUFFIX, length_col));

    // Fingerprint limbs (paper §6.2) under this column's own rule; a column
    // the table's rules do not fingerprint emits none.
    let selected = scheme_for_column(options.column)
        .map(|scheme| (options.fingerprint.select(scheme.num_limbs()), scheme))
        .filter(|(selected, _)| !selected.is_empty());
    if let Some((selected, scheme)) = selected {
        let masks = scheme.fingerprint_all(&values);
        let num_vars = rows.max(1).trailing_zeros() as usize;
        let limbs: Vec<Vec<u8>> = map_indices(selected.len(), |k| {
            let mut col: Vec<u8> = masks.iter().map(|m| limb(m, selected[k])).collect();
            col.resize(1 << num_vars, 0);
            col
        });
        for (&j, col) in selected.iter().zip(limbs) {
            segments.push(EncodedSegment::named_mle(
                fingerprint_limb_suffix(j),
                MLE::from_u8s(col, num_vars),
            ));
        }
    }

    // Character-level side segments (paper §3.2). All four share one domain
    // and one `active_len`, the total byte count.
    if options.side {
        let total_chars: usize = values.iter().map(|v| v.len()).sum();
        let mut chars_bytes: Vec<u8> = Vec::with_capacity(total_chars);
        let mut orig_ind: Vec<u32> = Vec::with_capacity(total_chars);
        let mut int_ind: Vec<u32> = Vec::with_capacity(total_chars);
        let mut bnd: Vec<u8> = Vec::with_capacity(total_chars);
        for (idx, bytes) in values.iter().enumerate() {
            chars_bytes.extend_from_slice(bytes);
            orig_ind.extend(std::iter::repeat_n(idx as u32, bytes.len()));
            int_ind.extend(0..bytes.len() as u32);
            bnd.extend((0..bytes.len()).map(|j| u8::from(j == 0)));
        }

        // Pad all four to the same power of two. A column with no
        // characters still gets a one-entry zero segment, so tracking sees
        // the same shape.
        let chars_active_len = chars_bytes.len();
        let target_len = chars_active_len.max(1).next_power_of_two();
        chars_bytes.resize(target_len, 0u8);
        orig_ind.resize(target_len, 0u32);
        int_ind.resize(target_len, 0u32);
        bnd.resize(target_len, 0u8);

        // Same order as `string_side_segment_suffixes`.
        segments.push(EncodedSegment::side_bytes(
            STRING_CHARS_SUFFIX,
            chars_bytes,
            chars_active_len,
        ));
        segments.push(EncodedSegment::side_u32(
            STRING_ORIG_IND_SUFFIX,
            orig_ind,
            chars_active_len,
        ));
        segments.push(EncodedSegment::side_u32(
            STRING_INT_IND_SUFFIX,
            int_ind,
            chars_active_len,
        ));
        segments.push(EncodedSegment::side_bytes(
            STRING_BND_SUFFIX,
            bnd,
            chars_active_len,
        ));
    }
    Ok(segments)
}

impl<F: PrimeField> Encodable<F> for StringArray {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        self.encode_with_options(EncodeOptions::ALL)
    }

    fn encode_with_options(
        &self,
        options: EncodeOptions<'_>,
    ) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        encode_utf8_like::<F, _, _>(self, 32, options, |array, idx| array.value(idx))
    }

    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!(
            "Decoding {} is not implemented yet",
            stringify!(StringArray)
        );
    }
}

impl<F: PrimeField> Encodable<F> for LargeStringArray {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        self.encode_with_options(EncodeOptions::ALL)
    }

    fn encode_with_options(
        &self,
        options: EncodeOptions<'_>,
    ) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        encode_utf8_like::<F, _, _>(self, 32, options, |array, idx| array.value(idx))
    }

    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!(
            "Decoding {} is not implemented yet",
            stringify!(LargeStringArray)
        );
    }
}

impl<F: PrimeField> Encodable<F> for StringViewArray {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        self.encode_with_options(EncodeOptions::ALL)
    }

    fn encode_with_options(
        &self,
        options: EncodeOptions<'_>,
    ) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        encode_utf8_like::<F, _, _>(self, 32, options, |array, idx| array.value(idx))
    }

    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!(
            "Decoding {} is not implemented yet",
            stringify!(StringViewArray)
        );
    }
}
