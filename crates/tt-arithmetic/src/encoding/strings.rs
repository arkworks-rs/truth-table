use ark_ff::PrimeField;
use ark_piop::arithmetic::mat_poly::mle::MLE;
use datafusion::arrow::array::{Array, LargeStringArray, StringArray, StringViewArray};

use crate::errors::EncodeError;
use crate::fingerprint::{NUM_LIMBS, limb, scheme_for_column};

use super::encodable::{Encodable, EncodeOptions, FingerprintLimbs};
use super::segment::{EncodedSegment, auto_segments, auto_suffixes};
use super::util::{encode_hashed_bytes, field_element_byte_capacity, map_indices};

// --- String-specific segment suffix conventions ---------------------------
//
// These constants and helpers describe what a string column expands into at
// arithmetization time. They live next to the string encoder so all
// "what does a string turn into on the field side" state is in one file;
// the generic dispatcher in `suffixes.rs` calls into them for the Utf8 /
// LargeUtf8 / Utf8View data-type arms.

/// Conventional segment suffix for the byte length of a string column.
pub const STRING_LENGTH_SUFFIX: &str = "__length";

/// Prefix of the fingerprint limb segment suffixes: limb `j` of a string
/// column `c` is the row-domain segment `c__fp{j}`, holding bin `j` of
/// `fp(c[i])` under the column's
/// [`FingerprintScheme`](crate::fingerprint::FingerprintScheme) as 0 or 1
/// (a limb is [`LIMB_BITS`](crate::fingerprint::LIMB_BITS) = 1 bin).
/// Computed once at ingestion, like `__length`, so the Pre-Filtering Check
/// can trust it at query time and read only the bins a query tests.
pub const STRING_FINGERPRINT_LIMB_PREFIX: &str = "__fp";

/// The suffix of fingerprint limb `j`.
pub fn fingerprint_limb_suffix(j: usize) -> String {
    format!("{STRING_FINGERPRINT_LIMB_PREFIX}{j}")
}

/// The fingerprint limb suffixes a string column emits, in encoder order:
/// the `limbs` selected among the column's own
/// ([`FingerprintScheme::num_limbs`] under the rule that fingerprints it).
/// A column no rule fingerprints emits none. Prover, verifier and encoder
/// all resolve it from the same installed rules and the same selection, so
/// they agree by construction.
pub fn fingerprint_segment_suffixes(column: Option<&str>, limbs: FingerprintLimbs) -> Vec<String> {
    let num_limbs = scheme_for_column(column).map_or(0, |s| s.num_limbs());
    limbs
        .select(num_limbs)
        .into_iter()
        .map(fingerprint_limb_suffix)
        .collect()
}

/// Conventional segment suffix for the concatenated-characters side polynomial
/// of a string column. Each entry is the byte value (`F::from(byte as u64)`)
/// of one character. Bytes of active strings are laid out contiguously in
/// row order at the start of the polynomial, then zero-padded to the next
/// power of two. The accompanying side activator is a contiguous-one poly
/// with `active_len = sum of active string byte lengths`.
pub const STRING_CHARS_SUFFIX: &str = "__chars";

/// Suffix for the per-string-column **origin index** side polynomial (paper
/// §3.2): `orig-ind[c]` is the row index of the source string that character
/// slot `c` belongs to. Lives on the same character-level domain as
/// `__chars`.
pub const STRING_ORIG_IND_SUFFIX: &str = "__orig_ind";

/// Suffix for the per-string-column **internal index** side polynomial
/// (paper §3.2): `int-ind[c]` is the within-string position of character
/// slot `c`, resetting to 0 at each string boundary. Same domain as
/// `__chars`.
pub const STRING_INT_IND_SUFFIX: &str = "__int_ind";

/// Suffix for the per-string-column **boundary marker** side polynomial
/// (paper §3.2): `bnd[c]` is 1 iff character slot `c` is the first
/// character of a string, else 0. Same domain as `__chars`.
pub const STRING_BND_SUFFIX: &str = "__bnd";

/// Row-domain value segment suffixes emitted by the string encoder, in the
/// exact order `encode_utf8_like` produces them: `hash_slots` many
/// auto-numbered entries followed by `STRING_LENGTH_SUFFIX`. The optional
/// fingerprint limbs ([`fingerprint_segment_suffixes`]) follow them when
/// requested.
pub(super) fn string_row_segment_suffixes<F: PrimeField>() -> Vec<String> {
    let hash_slots = 32usize.div_ceil(field_element_byte_capacity::<F>());
    let mut s = auto_suffixes(hash_slots);
    s.push(STRING_LENGTH_SUFFIX.to_string());
    s
}

/// Side-domain segment suffixes emitted by the string encoder, in the exact
/// order `encode_utf8_like` produces them. Do not reorder — prover and
/// verifier tracking passes walk this sequence.
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

/// Recognizes the string-family segment suffixes and returns the source
/// column base name if matched, else `None`. Called from
/// `segment_base_name` in `suffixes.rs`.
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
    // Fixed shape per column so all-null arrays still produce both segments
    // (hash slots + length). Hash slot count is constant for a given field:
    // hash_to_32_bytes always emits 32 bytes, chunked by field byte capacity.
    let hash_slots = if inline_short {
        1
    } else {
        32usize.div_ceil(field_element_byte_capacity::<F>())
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

    // Fingerprint limb columns (paper §6.2), computed at ingestion under this
    // column's own rule — a column the table's rules do not fingerprint emits
    // no limbs at all, so it costs nothing to commit.
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

    // Character-level side polynomials (paper §3.2) — skipped unless the
    // caller asked for them.
    if options.side {
        // All four share the same character-level domain and the same
        // `active_len` = total active byte count. Native storage is kept
        // small: chars/bnd → Vec<u8>, orig_ind/int_ind → Vec<u32>. Commit
        // and track passes lift these to `MLE<F>` transiently.
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

        // Pad every char-level segment to the SAME power-of-two length so
        // they share a common multilinear domain. An empty column still
        // produces a 1-slot, all-zero side poly so downstream tracking
        // sees a consistent shape.
        let chars_active_len = chars_bytes.len();
        let target_len = chars_active_len.max(1).next_power_of_two();
        chars_bytes.resize(target_len, 0u8);
        orig_ind.resize(target_len, 0u32);
        int_ind.resize(target_len, 0u32);
        bnd.resize(target_len, 0u8);

        // ORDER matches `side_segment_suffixes_for_type` and the prover /
        // verifier tracking passes — do not reorder.
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
