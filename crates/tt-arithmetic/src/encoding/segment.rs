use ark_ff::PrimeField;
use ark_piop::arithmetic::mat_poly::mle::MLE;
use datafusion::arrow::datatypes::{DataType, IntervalUnit};

use super::strings::{
    string_row_segment_suffixes, string_segment_base, string_side_segment_suffixes,
};
use super::util::{field_element_byte_capacity, hash_slot_count};

/// One column of an Arrow column's encoding. An Arrow column may expand into
/// several segments (a string becomes `["", "__length", "__chars", …]`). The
/// first has an empty `suffix`, so it keeps the source column's name; the
/// others have a role-specific suffix or an auto-numbered `__enc<N>`.
///
/// A row-domain segment shares the table's row count and `__activator__`;
/// its values are in `mle`, in the smallest native storage the encoder
/// could pick. A side-domain segment (`side` is `Some`) lives on its own
/// multilinear domain with its own activator and has no `mle`.
#[derive(Debug, Clone)]
pub struct EncodedSegment<F: PrimeField> {
    pub suffix: String,
    pub mle: Option<MLE<F>>,
    pub side: Option<SideSegmentInfo>,
}

/// A side-domain segment's data, padded to a power of two by the encoder.
/// The first `active_len` entries are active: the side activator is the
/// contiguous-one polynomial of that weight.
#[derive(Debug, Clone)]
pub struct SideSegmentInfo {
    pub data: SideColData,
    pub active_len: usize,
}

/// Native storage of a side-domain segment (paper §3.2): `char` and `bnd`
/// are `Bytes`, `orig-ind` and `int-ind` are `U32`. The commit and tracking
/// passes lift them to `F`.
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
    /// Row-domain primary segment (empty suffix).
    pub fn primary_mle(mle: MLE<F>) -> Self {
        Self {
            suffix: String::new(),
            mle: Some(mle),
            side: None,
        }
    }

    /// Row-domain named segment.
    pub fn named_mle(suffix: impl Into<String>, mle: MLE<F>) -> Self {
        Self {
            suffix: suffix.into(),
            mle: Some(mle),
            side: None,
        }
    }

    /// Row-domain primary segment of field elements. `values.len()` must be
    /// a power of two.
    pub fn primary(values: Vec<F>) -> Self {
        Self::primary_mle(mle_from_fs(values))
    }

    /// Row-domain named segment of field elements. `values.len()` must be a
    /// power of two.
    pub fn named(suffix: impl Into<String>, values: Vec<F>) -> Self {
        Self::named_mle(suffix, mle_from_fs(values))
    }

    /// Byte-valued side-domain segment. The caller pads `bytes` to a power
    /// of two; the first `active_len` entries are active.
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

    /// `u32`-valued side-domain segment, padded like [`Self::side_bytes`].
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

    /// The row-domain values as `F`; nothing for a side segment.
    pub fn iter_values(&self) -> impl Iterator<Item = F> + '_ {
        self.mle.as_ref().into_iter().flat_map(|m| m.iter())
    }

    /// Number of row-domain values; 0 for a side segment.
    pub fn len(&self) -> usize {
        self.mle.as_ref().map_or(0, |m| 1usize << m.num_vars())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Row-domain value `i` as `F`. Panics on a side segment and on an
    /// out-of-range index.
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

/// An MLE over `values`, whose length must be a power of two: a shorter vec
/// would be padded cyclically by `MLE::from_evaluations_vec`. An empty vec
/// becomes the one-entry zero MLE.
#[inline]
pub(super) fn mle_from_fs<F: PrimeField>(values: Vec<F>) -> MLE<F> {
    let len = values.len().max(1);
    assert!(
        len.is_power_of_two(),
        "mle_from_fs: len {} must be a power of two",
        values.len()
    );
    let num_vars = len.trailing_zeros() as usize;
    if values.is_empty() {
        return MLE::from_evaluations_vec(0, vec![F::zero()]);
    }
    MLE::from_evaluations_vec(num_vars, values)
}

/// One row-domain segment per column of field elements, named by the
/// auto-numbered convention: `""` for the first, then `"__enc1"`,
/// `"__enc2"`, … ([`auto_suffixes`] is the name side of the same rule).
pub(crate) fn auto_segments<F: PrimeField>(cols: Vec<Vec<F>>) -> Vec<EncodedSegment<F>> {
    cols.into_iter()
        .enumerate()
        .map(|(i, col)| EncodedSegment {
            suffix: auto_suffix_at(i),
            mle: Some(mle_from_fs(col)),
            side: None,
        })
        .collect()
}

/// The auto-numbered suffixes of `n` segments.
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

/// The source column of a non-primary segment name (`"col__length"` →
/// `Some("col")`). `None` for a primary segment and for any other name.
pub fn segment_base_name(field_name: &str) -> Option<&str> {
    if let Some(base) = string_segment_base(field_name) {
        return Some(base);
    }
    if let Some(enc_at) = field_name.rfind("__enc") {
        let rest = &field_name[enc_at + "__enc".len()..];
        if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
            return Some(&field_name[..enc_at]);
        }
    }
    None
}

/// Whether `field_name` is `base_name` itself (the primary segment) or one
/// of its other segments.
pub fn is_segment_of(field_name: &str, base_name: &str) -> bool {
    if field_name == base_name {
        return true;
    }
    matches!(segment_base_name(field_name), Some(base) if base == base_name)
}

/// The row-domain segment suffixes the encoder produces for a column of
/// type `dtype`, in encoder order, without the fingerprint limbs and the
/// side segments ([`side_segment_suffixes_for_type`]). The verifier's
/// tracking pass, which has the schema but no data, enumerates segments
/// with it, so it must agree with the encoders.
pub fn segment_suffixes_for_type<F: PrimeField>(dtype: &DataType) -> Vec<String> {
    let hash_slots = hash_slot_count::<F>();

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

/// The side-domain segment suffixes the encoder produces for a column of
/// type `dtype`, in encoder order. The verifier's tracking pass consumes
/// one (data, activator) commitment pair per suffix; each segment's
/// `log_size` depends on the data, so it travels in the transcript's
/// miscellaneous fields.
pub fn side_segment_suffixes_for_type<F: PrimeField>(dtype: &DataType) -> Vec<String> {
    match dtype {
        DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View => string_side_segment_suffixes(),
        _ => Vec::new(),
    }
}
