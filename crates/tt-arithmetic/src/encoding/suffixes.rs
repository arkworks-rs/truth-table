use ark_ff::PrimeField;
use datafusion::arrow::datatypes::{DataType, IntervalUnit};

use super::util::field_element_byte_capacity;

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

/// Returns the source-column base name if `field_name` carries a recognized
/// segment suffix (e.g. `"col__length"` → `Some("col")`). Returns `None`
/// when the name does not match any known segment suffix — that case can
/// either mean a primary segment (the column itself) or an unrelated name.
pub fn segment_base_name(field_name: &str) -> Option<&str> {
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
    // Match `__enc<N>` auto-named segments.
    if let Some(enc_at) = field_name.rfind("__enc") {
        let rest = &field_name[enc_at + "__enc".len()..];
        if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
            return Some(&field_name[..enc_at]);
        }
    }
    None
}

/// True if `field_name` either equals `base_name` (the primary segment) or
/// is a recognized segment of `base_name` (e.g. `base_name__length`).
pub fn is_segment_of(field_name: &str, base_name: &str) -> bool {
    if field_name == base_name {
        return true;
    }
    matches!(segment_base_name(field_name), Some(base) if base == base_name)
}

/// Returns the ordered **row-domain** segment suffixes that
/// `encode_arrow_array_to_field` will produce for a column of the given Arrow
/// data type. Used by callers that have only the schema (no data) to
/// enumerate the same set of row-space segments the prover will produce —
/// e.g. the verifier-side tracking pass.
///
/// Side-domain segments (e.g. `__chars` for strings) are NOT included here;
/// see [`side_segment_suffixes_for_type`] to enumerate those separately.
///
/// Must stay in lockstep with the encoder implementations below.
pub fn segment_suffixes_for_type<F: PrimeField>(dtype: &DataType) -> Vec<String> {
    let auto = |n: usize| -> Vec<String> {
        (0..n)
            .map(|i| {
                if i == 0 {
                    String::new()
                } else {
                    format!("__enc{i}")
                }
            })
            .collect()
    };
    let hash_slots = 32usize.div_ceil(field_element_byte_capacity::<F>());

    match dtype {
        DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View => {
            let mut s = auto(hash_slots);
            s.push(STRING_LENGTH_SUFFIX.to_string());
            s
        }
        DataType::Binary
        | DataType::LargeBinary
        | DataType::BinaryView
        | DataType::FixedSizeBinary(_) => auto(hash_slots),
        DataType::Interval(IntervalUnit::DayTime) => {
            auto(8usize.div_ceil(field_element_byte_capacity::<F>()))
        }
        DataType::Interval(IntervalUnit::MonthDayNano) => {
            auto(16usize.div_ceil(field_element_byte_capacity::<F>()))
        }
        _ => vec![String::new()],
    }
}

/// Returns the **side-domain** segment suffixes the encoder will emit for the
/// given Arrow data type, in the same order the encoder produces them. The
/// verifier-side tracking pass uses this to enumerate the side commitments it
/// must consume from the proof transcript.
///
/// Each side segment carries its own (data, activator) commitment pair; the
/// per-segment `log_size` is shared via the transcript's miscellaneous fields
/// since it depends on prover-side data.
pub fn side_segment_suffixes_for_type<F: PrimeField>(dtype: &DataType) -> Vec<String> {
    if !CHAR_LEVEL_SIDE_POLYS_ENABLED {
        return Vec::new();
    }
    match dtype {
        DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View => {
            // ORDER MATCHES ENCODER. Both prover and verifier walk side
            // segments in this exact sequence — do not reorder.
            vec![
                STRING_CHARS_SUFFIX.to_string(),
                STRING_ORIG_IND_SUFFIX.to_string(),
                STRING_INT_IND_SUFFIX.to_string(),
                STRING_BND_SUFFIX.to_string(),
            ]
        }
        _ => Vec::new(),
    }
}
