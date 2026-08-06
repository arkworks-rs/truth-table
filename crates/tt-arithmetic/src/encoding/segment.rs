use ark_ff::PrimeField;
use ark_piop::arithmetic::mat_poly::mle::MLE;
use datafusion::arrow::datatypes::{DataType, IntervalUnit};

use super::strings::{string_row_segment_suffixes, string_segment_base, string_side_segment_suffixes};
use super::util::field_element_byte_capacity;

// --- Segment value types --------------------------------------------------

/// Native-typed backing for a row-domain encoded segment. Carries the
/// smallest representation that faithfully encodes the source column: a
/// boolean column becomes `Bits`, a `u8` column becomes `U8s`, `Int32` with
/// only non-negative values becomes `U32s`, and anything else (signed
/// with negatives, floats, decimals, string hashes, computed field-elements)
/// falls back to `Fs`.
///
/// This is the lazy-MLE layer: the encoder chooses the variant at ingest
/// time and stashes the raw arrow buffer in it; only when the value must
/// actually flow through field arithmetic (sumcheck, evaluation at a
/// challenge point) does anything lift to `F`. Commitment goes through the
/// storage-aware small-scalar MSMs in `pst13`, so a `Bits`-backed column
/// is never materialized to `Vec<F>` on that path either.
///
/// Contract: every variant has exactly `len()` elements when read
/// via `get_as_field(i)`, matching how the same values would appear in a
/// `Vec<F>` after eager encoding. `into_mle(num_vars)` is a straight
/// forward to the matching `MLE::from_*` constructor, so the resulting
/// MLE's evaluations are bit-for-bit identical to the eager path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodedBacking<F: PrimeField> {
    /// Packed booleans, one bit per value, little-endian per byte.
    /// `len` is the count of logical values; `bits.len()` is `len.div_ceil(8)`.
    /// Used for `BooleanArray`.
    Bits { bits: Vec<u8>, len: usize },
    /// One `u8` per value. Used for `UInt8Array` and small char domains.
    U8s(Vec<u8>),
    /// One `u16` per value. Used for `UInt16Array`. `into_mle` promotes to
    /// `MLE::U32s` storage — `MLEStorage` has no `U16` variant, and the 2×
    /// promotion is still 8× smaller than `Field` at rest.
    U16s(Vec<u16>),
    /// One `u32` per value. Used for `UInt32Array`, `Date32Array`, and
    /// non-negative `Int{8,16,32}Array` (encoder peeks at signs).
    U32s(Vec<u32>),
    /// One `u64` per value. Used for `UInt64Array`, `Date64Array`,
    /// non-negative `Int64Array`, timestamps, times, durations that fit.
    U64s(Vec<u64>),
    /// Fallback: full-fat field elements. Used for signed columns with
    /// negative values (the field-side representation `MODULUS - abs(v)` is
    /// a 254-bit scalar that no small variant can hold), decimals, and any
    /// derived value that is intrinsically field-native (string hashes,
    /// `IntervalDayTime`/`MonthDayNano` limb packings). Also the safety
    /// escape hatch when we haven't taught a specific arrow type its
    /// native backing yet.
    Fs(Vec<F>),
}

impl<F: PrimeField> EncodedBacking<F> {
    /// Number of logical values (rows for row-domain segments, character
    /// slots for side-domain segments).
    pub fn len(&self) -> usize {
        match self {
            Self::Bits { len, .. } => *len,
            Self::U8s(v) => v.len(),
            Self::U16s(v) => v.len(),
            Self::U32s(v) => v.len(),
            Self::U64s(v) => v.len(),
            Self::Fs(v) => v.len(),
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Lift the `i`-th element to `F`. This is the "encoder" semantics —
    /// the same computation the eager path applied at ingest, just done on
    /// demand.
    #[inline]
    pub fn get_as_field(&self, i: usize) -> F {
        match self {
            Self::Bits { bits, .. } => {
                if (bits[i >> 3] >> (i & 7)) & 1 == 1 {
                    F::one()
                } else {
                    F::zero()
                }
            }
            Self::U8s(v) => F::from(v[i] as u64),
            Self::U16s(v) => F::from(v[i] as u64),
            Self::U32s(v) => F::from(v[i] as u64),
            Self::U64s(v) => F::from(v[i]),
            Self::Fs(v) => v[i],
        }
    }

    /// Materialize every element as `F`. Escape hatch for callers that
    /// legitimately need a `Vec<F>` (e.g. the LIKE gadget's length column
    /// consumer, `scalar_to_field` for one-shot literals, tests).
    /// The refactored arithmetization pass does NOT call this — it uses
    /// [`into_mle`] to build the compressed MLE directly.
    pub fn to_evaluations_vec(&self) -> Vec<F> {
        (0..self.len()).map(|i| self.get_as_field(i)).collect()
    }

    /// Consume the backing and build the corresponding [`MLE`], preserving
    /// the native storage variant. `num_vars` is the outer (virtually
    /// padded) size the poly should present as; the inner storage stays
    /// the compressed shape and virtual repetition kicks in for indices
    /// beyond the physical length.
    ///
    /// # Panics
    ///
    /// Passing `num_vars < ilog2(len).ceil()` will panic through the
    /// underlying `MLE::from_*` constructor. Callers should ensure
    /// `num_vars >= len.ilog2().ceil()`, matching the eager
    /// `MLE::from_evaluations_vec` contract.
    pub fn into_mle(self, num_vars: usize) -> MLE<F> {
        match self {
            Self::Bits { bits, .. } => MLE::from_bit_backing(bits, num_vars),
            Self::U8s(v) => MLE::from_u8s(v, num_vars),
            // Promote u16 → u32 at MLE-construction time. `MLEStorage` has no
            // `U16` variant; the 2× hit is still 8× smaller than Field storage
            // and lets us reuse the existing U32 commit / lift paths.
            Self::U16s(v) => MLE::from_u32s(v.into_iter().map(|x| x as u32).collect(), num_vars),
            Self::U32s(v) => MLE::from_u32s(v, num_vars),
            Self::U64s(v) => MLE::from_u64s(v, num_vars),
            Self::Fs(v) => MLE::from_evaluations_vec(num_vars, v),
        }
    }

    // --- Constructors used by encoders ------------------------------------

    /// Convenience: convert a `Vec<F>` into an `Fs`-variant backing.
    /// Used by encoders that intrinsically produce field elements (string
    /// hashes, binary hashes, decimal `from_le_bytes_mod_order`).
    #[inline]
    pub fn from_fs(values: Vec<F>) -> Self {
        Self::Fs(values)
    }
}

/// A named slice of a column's encoded representation. A single Arrow column
/// may expand into multiple `EncodedSegment`s — e.g. strings become
/// `[primary hash, "__length", "__chars"]`. The first segment of each Arrow
/// column conventionally carries an empty `suffix` (so it inherits the source
/// column's name); additional segments use a role-specific suffix (e.g.
/// `__length`, `__chars`) or an auto-numbered `__enc<N>` when the role is
/// generic.
///
/// Segments default to the **row domain** — they share the source table's
/// row count and the table-level `__activator__`. A segment may opt into a
/// **side domain** by setting `side: Some(SideSegmentInfo)`; side segments
/// live on their own multilinear domain with their own contiguous-one
/// activator, derived from `active_len` (see [`SideSegmentInfo`]).
///
/// Row-domain values are carried in [`EncodedBacking`] rather than a raw
/// `Vec<F>` so small-int columns stay compressed all the way from ingest
/// to commit. See [`EncodedBacking::into_mle`] for the materialization
/// path used by arithmetization.
#[derive(Debug, Clone)]
pub struct EncodedSegment<F: PrimeField> {
    pub suffix: String,
    pub backing: EncodedBacking<F>,
    pub side: Option<SideSegmentInfo>,
}

/// Payload + sizing metadata for a side-domain segment.
///
/// The raw data is carried in `data`, tagged by its element type. Byte-sized
/// values (chars, boundary flags) live in `SideColData::Bytes`; index-sized
/// values (origin index, internal index) live in `SideColData::U32`. All are
/// pow2-padded by the encoder. `active_len` is the count of leading
/// non-padding entries; the side activator is a contiguous-one polynomial
/// of that weight that downstream callers materialize on demand.
#[derive(Debug, Clone)]
pub struct SideSegmentInfo {
    pub data: SideColData,
    pub active_len: usize,
}

/// Element-type-tagged storage for a side-domain segment. Byte and u32
/// variants are enough for TruthTable++'s string arithmetization (paper §3.2)
/// — `char` and `bnd` fit in `Bytes`; `orig-ind` and `int-ind` fit in `U32`.
/// Kept as native small ints so the in-memory representation stays 32× (or 8×)
/// smaller than the field-element form; commit / track passes lift to `F`
/// transiently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SideColData {
    Bytes(Vec<u8>),
    U32(Vec<u32>),
}

impl SideColData {
    pub fn len(&self) -> usize {
        match self {
            SideColData::Bytes(v) => v.len(),
            SideColData::U32(v) => v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<F: PrimeField> EncodedSegment<F> {
    /// Row-domain primary segment (empty suffix) from an already-`F` payload.
    /// Reserved for encoders whose output is intrinsically field-valued
    /// (`NullArray` all-zeros, existing test helpers). Prefer
    /// [`primary_backed`] when the encoder knows a smaller native shape.
    pub fn primary(values: Vec<F>) -> Self {
        Self::primary_backed(EncodedBacking::Fs(values))
    }

    /// Row-domain primary segment with an explicit native backing.
    pub fn primary_backed(backing: EncodedBacking<F>) -> Self {
        Self {
            suffix: String::new(),
            backing,
            side: None,
        }
    }

    /// Row-domain named segment from an already-`F` payload. Same
    /// `Fs`-fallback bias as [`primary`]; use [`named_backed`] when a
    /// smaller variant fits.
    pub fn named(suffix: impl Into<String>, values: Vec<F>) -> Self {
        Self::named_backed(suffix, EncodedBacking::Fs(values))
    }

    /// Row-domain named segment with an explicit native backing.
    pub fn named_backed(suffix: impl Into<String>, backing: EncodedBacking<F>) -> Self {
        Self {
            suffix: suffix.into(),
            backing,
            side: None,
        }
    }

    /// Read-only iterator over this segment's values as `F`. Preserves the
    /// eager-encoding contract without materializing a `Vec<F>` for backing
    /// types that stay compressed. Row-domain segments only.
    pub fn iter_values(&self) -> impl Iterator<Item = F> + '_ {
        (0..self.backing.len()).map(|i| self.backing.get_as_field(i))
    }

    /// Number of logical row-domain values in this segment. For side
    /// segments this is 0 (the payload lives in `side.data`).
    pub fn len(&self) -> usize {
        self.backing.len()
    }

    pub fn is_empty(&self) -> bool {
        self.backing.is_empty()
    }

    /// Construct a byte-valued side-domain segment. `bytes` is pow2-padded
    /// by the caller; `active_len` is the count of active leading entries.
    /// The row-domain backing is left empty for side segments.
    pub fn side_bytes(suffix: impl Into<String>, bytes: Vec<u8>, active_len: usize) -> Self {
        debug_assert!(
            active_len <= bytes.len(),
            "side segment active_len {} exceeds bytes length {}",
            active_len,
            bytes.len()
        );
        Self {
            suffix: suffix.into(),
            backing: EncodedBacking::Fs(Vec::new()),
            side: Some(SideSegmentInfo {
                data: SideColData::Bytes(bytes),
                active_len,
            }),
        }
    }

    /// Construct a u32-valued side-domain segment. Same padding /
    /// `active_len` convention as `side_bytes`.
    pub fn side_u32(suffix: impl Into<String>, values: Vec<u32>, active_len: usize) -> Self {
        debug_assert!(
            active_len <= values.len(),
            "side segment active_len {} exceeds u32 length {}",
            active_len,
            values.len()
        );
        Self {
            suffix: suffix.into(),
            backing: EncodedBacking::Fs(Vec::new()),
            side: Some(SideSegmentInfo {
                data: SideColData::U32(values),
                active_len,
            }),
        }
    }

    pub fn is_side(&self) -> bool {
        self.side.is_some()
    }
}

// --- Auto-numbered segment convention ------------------------------------
// `auto_segments` and `auto_suffixes` are the value-side and name-side of
// the same convention: the first entry uses `""` (primary — inherits the
// source column name), subsequent entries use `"__enc1"`, `"__enc2"`, …
// Kept adjacent so the invariant that the two agree is visually obvious.

/// Wrap a `Vec<Vec<F>>` (one inner Vec per column) into auto-named segments.
/// The default naming when an encoder does not assign role-specific names.
///
/// Field payloads flow through the `Fs` backing — this helper is for encoders
/// that intrinsically produce field elements (hashes, decimal / interval limb
/// packings). Encoders that know a smaller native shape use
/// [`auto_segments_backed`] instead.
pub(crate) fn auto_segments<F: PrimeField>(cols: Vec<Vec<F>>) -> Vec<EncodedSegment<F>> {
    auto_segments_backed(cols.into_iter().map(EncodedBacking::Fs).collect())
}

/// Like [`auto_segments`], but each per-column payload is an already-tagged
/// [`EncodedBacking`]. Encoders for native-typed columns (bool/u{8,16,32,64}/
/// non-negative signed) call this so `arithmetization::into_mle` never has to
/// materialize a `Vec<F>` for compressible columns.
pub(crate) fn auto_segments_backed<F: PrimeField>(
    cols: Vec<EncodedBacking<F>>,
) -> Vec<EncodedSegment<F>> {
    cols.into_iter()
        .enumerate()
        .map(|(i, backing)| EncodedSegment {
            suffix: auto_suffix_at(i),
            backing,
            side: None,
        })
        .collect()
}

/// Generate the auto-numbered suffix sequence for `n` segments: `""`,
/// `"__enc1"`, `"__enc2"`, …. Kept `pub(super)` so per-type-family modules
/// (see `strings::string_row_segment_suffixes`) can share the same
/// convention.
pub(super) fn auto_suffixes(n: usize) -> Vec<String> {
    (0..n).map(auto_suffix_at).collect()
}

fn auto_suffix_at(i: usize) -> String {
    if i == 0 {
        String::new()
    } else {
        format!("__enc{i}")
    }
}

// --- Segment-name dispatchers --------------------------------------------

/// Returns the source-column base name if `field_name` carries a recognized
/// segment suffix (e.g. `"col__length"` → `Some("col")`). Returns `None`
/// when the name does not match any known segment suffix — that case can
/// either mean a primary segment (the column itself) or an unrelated name.
///
/// Delegation: type-family-specific suffix constants (e.g. the string
/// `__length` / `__chars` / …) live with their encoders; only the generic
/// `__enc<N>` auto-numbered convention is decoded here.
pub fn segment_base_name(field_name: &str) -> Option<&str> {
    if let Some(base) = string_segment_base(field_name) {
        return Some(base);
    }
    // Auto-numbered `__enc<N>` segments produced by `auto_segments`.
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
/// Must stay in lockstep with the encoder implementations. Per-type-family
/// suffix sets live with their encoders (see e.g.
/// [`string_row_segment_suffixes`](super::strings::string_row_segment_suffixes));
/// this function only dispatches.
pub fn segment_suffixes_for_type<F: PrimeField>(dtype: &DataType) -> Vec<String> {
    let hash_slots = 32usize.div_ceil(field_element_byte_capacity::<F>());

    match dtype {
        DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View => {
            string_row_segment_suffixes::<F>()
        }
        DataType::Binary
        | DataType::LargeBinary
        | DataType::BinaryView
        | DataType::FixedSizeBinary(_) => auto_suffixes(hash_slots),
        DataType::Interval(IntervalUnit::DayTime) => {
            auto_suffixes(8usize.div_ceil(field_element_byte_capacity::<F>()))
        }
        DataType::Interval(IntervalUnit::MonthDayNano) => {
            auto_suffixes(16usize.div_ceil(field_element_byte_capacity::<F>()))
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
    match dtype {
        DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View => {
            string_side_segment_suffixes()
        }
        _ => Vec::new(),
    }
}
