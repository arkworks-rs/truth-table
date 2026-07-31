use ark_ff::PrimeField;

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
#[derive(Debug, Clone)]
pub struct EncodedSegment<F: PrimeField> {
    pub suffix: String,
    pub values: Vec<F>,
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
    pub fn primary(values: Vec<F>) -> Self {
        Self {
            suffix: String::new(),
            values,
            side: None,
        }
    }

    pub fn named(suffix: impl Into<String>, values: Vec<F>) -> Self {
        Self {
            suffix: suffix.into(),
            values,
            side: None,
        }
    }

    /// Construct a byte-valued side-domain segment. `bytes` is pow2-padded
    /// by the caller; `active_len` is the count of active leading entries.
    /// The row-domain `values` field is left empty for side segments.
    pub fn side_bytes(suffix: impl Into<String>, bytes: Vec<u8>, active_len: usize) -> Self {
        debug_assert!(
            active_len <= bytes.len(),
            "side segment active_len {} exceeds bytes length {}",
            active_len,
            bytes.len()
        );
        Self {
            suffix: suffix.into(),
            values: Vec::new(),
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
            values: Vec::new(),
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

/// Wrap a `Vec<Vec<F>>` (one inner Vec per column) into auto-named segments:
/// the first segment uses no suffix, subsequent segments get `__enc1`,
/// `__enc2`, … This is the default naming when an encoder does not assign
/// role-specific names.
pub(crate) fn auto_segments<F: PrimeField>(cols: Vec<Vec<F>>) -> Vec<EncodedSegment<F>> {
    cols.into_iter()
        .enumerate()
        .map(|(i, values)| {
            let suffix = if i == 0 {
                String::new()
            } else {
                format!("__enc{i}")
            };
            EncodedSegment {
                suffix,
                values,
                side: None,
            }
        })
        .collect()
}
