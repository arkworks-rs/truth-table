use ark_ff::PrimeField;
use datafusion::arrow::array::{Array, LargeStringArray, StringArray, StringViewArray};

use crate::errors::EncodeError;

use super::encodable::Encodable;
use super::segment::{auto_segments, auto_suffixes, EncodedSegment};
use super::util::{encode_hashed_bytes, field_element_byte_capacity};

// --- String-specific segment suffix conventions ---------------------------
//
// These constants and helpers describe what a string column expands into at
// arithmetization time. They live next to the string encoder so all
// "what does a string turn into on the field side" state is in one file;
// the generic dispatcher in `suffixes.rs` calls into them for the Utf8 /
// LargeUtf8 / Utf8View data-type arms.

/// Conventional segment suffix for the byte length of a string column.
pub const STRING_LENGTH_SUFFIX: &str = "__length";

/// Conventional segment suffix for the concatenated-characters side polynomial
/// of a string column. Each entry is the byte value (`F::from(byte as u64)`)
/// of one character. Bytes of active strings are laid out contiguously in
/// row order at the start of the polynomial, then zero-padded to the next
/// power of two. The accompanying side activator is a contiguous-one poly
/// with `active_len = sum of active string byte lengths`.
pub const STRING_CHARS_SUFFIX: &str = "__chars";

/// Master toggle for the character-level side polynomials of paper §3.2.
///
/// When `true`, string base tables emit the full `{__chars, __orig_ind,
/// __int_ind, __bnd}` side-column bundle at arithmetization time, and both
/// the prover commit/track passes and the verifier tracking pass consume
/// those commitments. When `false`, string columns arithmetize to only
/// their `{hash, __length}` row-domain segments (same behavior as `main`),
/// keeping the prover memory footprint identical to a no-char-level build.
///
/// This is a workspace-level compile-time gate because it must be flipped
/// in lockstep on both prover and verifier: the two must agree on how many
/// commitments enter the transcript per string column. When we start
/// implementing white-box string PIOPs (Broadcast Check, Length Filter,
/// Prefix/Suffix Check, Multi-Char Pattern Match), flip this to `true` and
/// re-generate the bench SRS at the higher `log_size` that the char-level
/// polys need.
pub const CHAR_LEVEL_SIDE_POLYS_ENABLED: bool = true;

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

/// Row-domain segment suffixes emitted by the string encoder, in the exact
/// order `encode_utf8_like` produces them: `hash_slots` many auto-numbered
/// entries followed by `STRING_LENGTH_SUFFIX`.
pub(super) fn string_row_segment_suffixes<F: PrimeField>() -> Vec<String> {
    let hash_slots = 32usize.div_ceil(field_element_byte_capacity::<F>());
    let mut s = auto_suffixes(hash_slots);
    s.push(STRING_LENGTH_SUFFIX.to_string());
    s
}

/// Side-domain segment suffixes emitted by the string encoder, in the exact
/// order `encode_utf8_like` produces them. Empty when
/// `CHAR_LEVEL_SIDE_POLYS_ENABLED` is off. Do not reorder — prover and
/// verifier tracking passes walk this sequence.
pub(super) fn string_side_segment_suffixes() -> Vec<String> {
    if !CHAR_LEVEL_SIDE_POLYS_ENABLED {
        return Vec::new();
    }
    vec![
        STRING_CHARS_SUFFIX.to_string(),
        STRING_ORIG_IND_SUFFIX.to_string(),
        STRING_INT_IND_SUFFIX.to_string(),
        STRING_BND_SUFFIX.to_string(),
    ]
}

/// Recognizes the string-family segment suffixes and returns the source
/// column base name if matched, else `None`. Called from
/// `segment_base_name` in `suffixes.rs`.
pub(super) fn string_segment_base(field_name: &str) -> Option<&str> {
    if let Some(base) = field_name.strip_suffix(STRING_LENGTH_SUFFIX) {
        return Some(base);
    }
    if let Some(base) = field_name.strip_suffix(STRING_CHARS_SUFFIX) {
        return Some(base);
    }
    if let Some(base) = field_name.strip_suffix(STRING_ORIG_IND_SUFFIX) {
        return Some(base);
    }
    if let Some(base) = field_name.strip_suffix(STRING_INT_IND_SUFFIX) {
        return Some(base);
    }
    if let Some(base) = field_name.strip_suffix(STRING_BND_SUFFIX) {
        return Some(base);
    }
    None
}

fn encode_utf8_like<F, A, GetValue>(
    array: &A,
    short_string_threshold: usize,
    value_fn: GetValue,
) -> Result<Vec<EncodedSegment<F>>, EncodeError>
where
    F: PrimeField,
    A: Array,
    GetValue: Copy + Fn(&A, usize) -> &str,
{
    let rows = array.len();
    let mut max_len = 0usize;
    for idx in 0..rows {
        if !array.is_null(idx) {
            let len = value_fn(array, idx).len();
            if len > max_len {
                max_len = len;
            }
        }
    }

    let inline_short = max_len <= short_string_threshold && max_len <= 1;
    // Fixed shape per column so all-null arrays still produce both segments
    // (hash slots + length). Hash slot count is constant for a given field:
    // hash_to_32_bytes always emits 32 bytes, chunked by field byte capacity.
    let hash_slots = if inline_short {
        1
    } else {
        32usize.div_ceil(field_element_byte_capacity::<F>())
    };

    let mut hash_cols: Vec<Vec<F>> = (0..hash_slots)
        .map(|_| Vec::with_capacity(rows))
        .collect();
    let mut length_col: Vec<F> = Vec::with_capacity(rows);

    // Character-level side polynomials (paper §3.2) — only built when the
    // workspace-level toggle is on. When off, this encoder produces only
    // the row-domain `{hash, __length}` segments (same as pre-string-support
    // main) so the prover memory footprint is unchanged.
    if CHAR_LEVEL_SIDE_POLYS_ENABLED {
        // All four share the same character-level domain and the same
        // `active_len` = total active byte count. Native storage is kept
        // small: chars/bnd → Vec<u8>, orig_ind/int_ind → Vec<u32>. Commit
        // and track passes lift these to `MLE<F>` transiently.
        let total_chars: usize = (0..rows)
            .map(|idx| {
                if array.is_null(idx) {
                    0
                } else {
                    value_fn(array, idx).len()
                }
            })
            .sum();
        let mut chars_bytes: Vec<u8> = Vec::with_capacity(total_chars);
        let mut orig_ind: Vec<u32> = Vec::with_capacity(total_chars);
        let mut int_ind: Vec<u32> = Vec::with_capacity(total_chars);
        let mut bnd: Vec<u8> = Vec::with_capacity(total_chars);

        for idx in 0..rows {
            if array.is_null(idx) {
                for col in &mut hash_cols {
                    col.push(F::zero());
                }
                length_col.push(F::zero());
                continue;
            }
            let bytes = value_fn(array, idx).as_bytes();
            if inline_short {
                let head = if bytes.is_empty() {
                    F::zero()
                } else {
                    F::from(bytes[0] as u64)
                };
                hash_cols[0].push(head);
            } else {
                let chunks = encode_hashed_bytes::<F>(bytes);
                for (slot, col) in hash_cols.iter_mut().enumerate() {
                    col.push(chunks.get(slot).copied().unwrap_or_else(F::zero));
                }
            }
            length_col.push(F::from(bytes.len() as u64));
            let row_ix = idx as u32;
            for (j, &byte) in bytes.iter().enumerate() {
                chars_bytes.push(byte);
                orig_ind.push(row_ix);
                int_ind.push(j as u32);
                bnd.push(if j == 0 { 1 } else { 0 });
            }
        }

        // Pad every char-level segment to the SAME power-of-two length so
        // they share a common multilinear domain. An empty column still
        // produces a 1-slot, all-zero side poly so downstream tracking
        // sees a consistent shape.
        let chars_active_len = chars_bytes.len();
        debug_assert_eq!(orig_ind.len(), chars_active_len);
        debug_assert_eq!(int_ind.len(), chars_active_len);
        debug_assert_eq!(bnd.len(), chars_active_len);
        let target_len = chars_active_len.max(1).next_power_of_two();
        chars_bytes.resize(target_len, 0u8);
        orig_ind.resize(target_len, 0u32);
        int_ind.resize(target_len, 0u32);
        bnd.resize(target_len, 0u8);

        let mut segments = auto_segments(hash_cols);
        segments.push(EncodedSegment::named(STRING_LENGTH_SUFFIX, length_col));
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
        return Ok(segments);
    }

    // Char-level toggle off: only build row-domain segments.
    for idx in 0..rows {
        if array.is_null(idx) {
            for col in &mut hash_cols {
                col.push(F::zero());
            }
            length_col.push(F::zero());
            continue;
        }
        let bytes = value_fn(array, idx).as_bytes();
        if inline_short {
            let head = if bytes.is_empty() {
                F::zero()
            } else {
                F::from(bytes[0] as u64)
            };
            hash_cols[0].push(head);
        } else {
            let chunks = encode_hashed_bytes::<F>(bytes);
            for (slot, col) in hash_cols.iter_mut().enumerate() {
                col.push(chunks.get(slot).copied().unwrap_or_else(F::zero));
            }
        }
        length_col.push(F::from(bytes.len() as u64));
    }

    let mut segments = auto_segments(hash_cols);
    segments.push(EncodedSegment::named(STRING_LENGTH_SUFFIX, length_col));
    Ok(segments)
}

impl<F: PrimeField> Encodable<F> for StringArray {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        encode_utf8_like::<F, _, _>(self, 32, |array, idx| array.value(idx))
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
        encode_utf8_like::<F, _, _>(self, 32, |array, idx| array.value(idx))
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
        encode_utf8_like::<F, _, _>(self, 32, |array, idx| array.value(idx))
    }

    fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
        todo!(
            "Decoding {} is not implemented yet",
            stringify!(StringViewArray)
        );
    }
}
