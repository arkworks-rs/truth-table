use std::collections::{BTreeMap, BTreeSet};

use ark_ff::PrimeField;

use crate::errors::EncodeError;

use super::segment::EncodedSegment;

/// Which fingerprint limbs (`__fp{j}`) a string encoder emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintLimbs<'a> {
    None,
    /// Every limb of the column's rule — what the data owner commits.
    All,
    /// Only these limbs — what a query's pre-filters test. Limbs past the
    /// rule's width are ignored.
    Only(&'a BTreeSet<usize>),
}

impl FingerprintLimbs<'_> {
    /// The selected limbs among `0..num_limbs`, ascending.
    pub fn select(self, num_limbs: usize) -> Vec<usize> {
        match self {
            Self::None => Vec::new(),
            Self::All => (0..num_limbs).collect(),
            Self::Only(limbs) => limbs.range(..num_limbs).copied().collect(),
        }
    }
}

/// The fingerprint limbs a query's pre-filters test, per string column.
pub type FingerprintSelection = BTreeMap<String, BTreeSet<usize>>;

/// `column`'s limbs in `selection`, or none.
pub fn selected_limbs<'a>(
    selection: &'a FingerprintSelection,
    column: &str,
) -> FingerprintLimbs<'a> {
    selection
        .get(column)
        .map_or(FingerprintLimbs::None, FingerprintLimbs::Only)
}

/// Which optional segments an encoder emits besides a column's row-domain
/// value segments. Only string encoders have optional segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeOptions<'a> {
    /// Char-level side segments (`__chars`, `__orig_ind`, …).
    pub side: bool,
    /// Fingerprint limb segments (`__fp{j}`, one per bin of the column's
    /// rule), all or some of them.
    pub fingerprint: FingerprintLimbs<'a>,
    /// The source column's name, so the string encoder can fingerprint it
    /// under *that column's* rule. With `None`, or a column with no rule,
    /// no limbs are emitted.
    pub column: Option<&'a str>,
}

impl EncodeOptions<'_> {
    /// Every optional segment of an unnamed column: side segments, and no
    /// limbs, since only a named column has a rule.
    pub const ALL: Self = Self {
        side: true,
        fingerprint: FingerprintLimbs::All,
        column: None,
    };
    /// Row-domain value segments only.
    pub const NONE: Self = Self {
        side: false,
        fingerprint: FingerprintLimbs::None,
        column: None,
    };
}

/// A trait for encoding types into PrimeField elements.
pub trait Encodable<F: PrimeField>: Sized {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError>;

    /// Like [`Encodable::encode`], but lets the caller suppress optional
    /// segments so encoders never even *build* their buffers. Only string
    /// encoders have optional segments, so the default ignores the options.
    fn encode_with_options(
        &self,
        options: EncodeOptions<'_>,
    ) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
        let _ = options;
        self.encode()
    }

    fn decode(field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError>;
}

/// This macro implements the `Encodable` trait for Arrow array types that can
/// be mapped directly to field elements. No decoding functionality is provided
/// (or needed) for now.
macro_rules! impl_col_adapter_map {
    ($array_ty:ty, $map:expr_2021) => {
        impl<F: PrimeField> Encodable<F> for $array_ty {
            fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
                let cols = collect_by_columns(self.len(), |idx| {
                    if self.is_null(idx) {
                        vec![F::zero()]
                    } else {
                        vec![$map(self.value(idx))]
                    }
                });
                Ok(auto_segments(cols))
            }

            fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
                todo!("Decoding {} is not implemented yet", stringify!($array_ty));
            }
        }
    };
}

/// This macro implements the `Encodable` trait for Arrow array types that are
/// not supported yet
macro_rules! impl_col_adapter_unsupported {
    ($array_ty:ty, $name:expr_2021) => {
        impl<F: PrimeField> Encodable<F> for $array_ty {
            fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError> {
                Err(EncodeError::TypeNotSupported($name.to_string()))
            }

            fn decode(_field_elem: impl IntoIterator<Item = F>) -> Result<Self, EncodeError> {
                todo!("Decoding {} is not implemented yet", stringify!($array_ty));
            }
        }
    };
}

pub(crate) use impl_col_adapter_map;
pub(crate) use impl_col_adapter_unsupported;
