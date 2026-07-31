use ark_ff::PrimeField;

use crate::errors::EncodeError;

use super::segment::EncodedSegment;

/// A trait for encoding types into PrimeField elements.
pub trait Encodable<F: PrimeField>: Sized {
    fn encode(&self) -> Result<Vec<EncodedSegment<F>>, EncodeError>;
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
