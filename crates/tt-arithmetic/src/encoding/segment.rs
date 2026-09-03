use ark_ff::PrimeField;
use ark_piop::arithmetic::mat_poly::mle::MLE;
use datafusion::arrow::datatypes::{DataType, IntervalUnit};

use super::strings::{
    string_row_segment_suffixes, string_segment_base, string_side_segment_suffixes,
};
use super::util::field_element_byte_capacity;

// --- Segment value types --------------------------------------------------

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
/// Row-domain values are carried in `mle` as a fully-formed [`MLE<F>`] whose
/// storage variant matches whatever native shape the encoder picked (bool →
/// `Bit`, u8 → `U8`, u32 → `U32`, …). The encoder builds the MLE directly
/// from the Arrow buffer in one pass — no intermediate `Vec<F>` for small-int
/// columns, no separate "backing" type to bridge. Only encoders that
/// intrinsically produce field elements (string hashes, decimal
/// `from_le_bytes_mod_order`, interval limb packings) allocate a `Vec<F>`.
///
/// Side segments set `mle` to `None`; their payload lives in `side.data`
/// and gets a fresh `MLE` materialized on demand at commit/track time (with
/// its own smaller multilinear domain).
#[derive(Debug, Clone)]
pub struct EncodedSegment<F: PrimeField> {
    pub suffix: String,
    /// Row-domain MLE. `Some` for row-domain segments, `None` for side
    /// segments (whose payload lives in [`Self::side`]).
    pub mle: Option<MLE<F>>,
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
    // --- Row-domain constructors -----------------------------------------

    /// Row-domain primary segment (empty suffix) from an already-built MLE.
    /// The MLE's storage variant determines the native shape; encoders call
    /// this directly with the tightest [`MLE::from_*`] constructor for their
    /// element type.
    pub fn primary_mle(mle: MLE<F>) -> Self {
        Self {
            suffix: String::new(),
            mle: Some(mle),
            side: None,
        }
    }

    /// Row-domain named segment from an already-built MLE.
    pub fn named_mle(suffix: impl Into<String>, mle: MLE<F>) -> Self {
        Self {
            suffix: suffix.into(),
            mle: Some(mle),
            side: None,
        }
    }

    /// Row-domain primary segment from a `Vec<F>`. Convenience wrapper: the
    /// segment stores an `MLE` whose `Field` storage is exactly this vec.
    /// Used by encoders whose output is intrinsically field-valued (string
    /// hashes, decimals, interval limb packings). `values.len()` must be a
    /// power of two.
    pub fn primary(values: Vec<F>) -> Self {
        Self::primary_mle(mle_from_fs(values))
    }

    /// Row-domain named segment from a `Vec<F>`. Same power-of-two rule as
    /// [`primary`].
    pub fn named(suffix: impl Into<String>, values: Vec<F>) -> Self {
        Self::named_mle(suffix, mle_from_fs(values))
    }

    // --- Side-domain constructors ----------------------------------------

    /// Construct a byte-valued side-domain segment. `bytes` is pow2-padded
    /// by the caller; `active_len` is the count of active leading entries.
    /// Row-domain MLE is `None` for side segments — the payload lives in
    /// `side.data`.
    pub fn side_bytes(suffix: impl Into<String>, bytes: Vec<u8>, active_len: usize) -> Self {
        debug_assert!(
            active_len <= bytes.len(),
            "side segment active_len {} exceeds bytes length {}",
            active_len,
            bytes.len()
        );
        Self {
            suffix: suffix.into(),
            mle: None,
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
            mle: None,
            side: Some(SideSegmentInfo {
                data: SideColData::U32(values),
                active_len,
            }),
        }
    }

    // --- Accessors --------------------------------------------------------

    /// Iterator over this segment's row-domain values as `F`. Yields nothing
    /// for side segments. Preserves the eager-encoding contract without
    /// materializing a `Vec<F>` for backing types that stay compressed.
    pub fn iter_values(&self) -> impl Iterator<Item = F> + '_ {
        self.mle.as_ref().into_iter().flat_map(|m| m.iter())
    }

    /// Number of logical row-domain values in this segment. For side
    /// segments this is 0 (the payload lives in `side.data`).
    pub fn len(&self) -> usize {
        self.mle.as_ref().map_or(0, |m| 1usize << m.num_vars())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read a single row-domain value as `F`. Panics on side segments and
    /// on out-of-range indices.
    pub fn value_as_field(&self, i: usize) -> F {
        let mle = self
            .mle
            .as_ref()
            .expect("value_as_field on a side segment (no row-domain MLE)");
        mle.storage().lift(i)
    }

    pub fn is_side(&self) -> bool {
        self.side.is_some()
    }
}

// --- Fs-vec → MLE helper --------------------------------------------------

/// Build an MLE from a `Vec<F>` whose length is a power of two. The stored
/// `num_vars` is `values.len().ilog2()`; `MLE::from_evaluations_vec` also
/// asserts `values.len() <= 2^num_vars`, but callers that pass a non-pow2
/// vec will end up with cyclic virtual padding — almost certainly a bug in
/// our pipeline, so we assert pow2 up front here.
#[inline]
pub(super) fn mle_from_fs<F: PrimeField>(values: Vec<F>) -> MLE<F> {
    let len = values.len().max(1);
    assert!(
        len.is_power_of_two(),
        "mle_from_fs: len {} must be a power of two",
        values.len()
    );
    let num_vars = len.trailing_zeros() as usize;
    // For empty input we synthesize an all-zero singleton so downstream
    // code sees a 1-slot MLE; this only fires on encoder edge cases
    // (e.g. all-null primary segments that produced no F values).
    if values.is_empty() {
        return MLE::from_evaluations_vec(0, vec![F::zero()]);
    }
    MLE::from_evaluations_vec(num_vars, values)
}

// --- Auto-numbered segment convention ------------------------------------
// `auto_segments` and `auto_suffixes` are the value-side and name-side of
// the same convention: the first entry uses `""` (primary — inherits the
// source column name), subsequent entries use `"__enc1"`, `"__enc2"`, …
// Kept adjacent so the invariant that the two agree is visually obvious.

/// Wrap a `Vec<Vec<F>>` (one inner Vec per column) into auto-named segments.
/// The default naming when an encoder does not assign role-specific names.
///
/// Field payloads flow through `MLE::from_evaluations_vec` — this helper is
/// for encoders that intrinsically produce field elements (hashes, decimal /
/// interval limb packings). Encoders that know a smaller native shape use
/// [`auto_segments_from_mles`] instead.
pub(crate) fn auto_segments<F: PrimeField>(cols: Vec<Vec<F>>) -> Vec<EncodedSegment<F>> {
    auto_segments_from_mles(cols.into_iter().map(mle_from_fs).collect())
}

/// Like [`auto_segments`], but each per-column payload is an already-built
/// [`MLE<F>`]. Encoders for native-typed columns (bool/u{8,16,32,64}/
/// non-negative signed) call this so no `Vec<F>` is ever materialized.
pub(crate) fn auto_segments_from_mles<F: PrimeField>(cols: Vec<MLE<F>>) -> Vec<EncodedSegment<F>> {
    cols.into_iter()
        .enumerate()
        .map(|(i, mle)| EncodedSegment {
            suffix: auto_suffix_at(i),
            mle: Some(mle),
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
        DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View => string_side_segment_suffixes(),
        _ => Vec::new(),
    }
}
