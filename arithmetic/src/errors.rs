//! Error module.

use kit::{displaydoc::Display, ark_serialize::SerializationError};

/// A `enum` specifying the possible failure modes of the arithmetics.
#[derive(Display, Debug)]
pub enum ArithErrors {
    /// Invalid parameters: {0}
    InvalidParameters(String),
    /// Should not arrive to this point
    ShouldNotArrive,
    /// An error during (de)serialization: {0}
    SerializationErrors(SerializationError),
}

impl From<SerializationError> for ArithErrors {
    fn from(e: SerializationError) -> Self {
        Self::SerializationErrors(e)
    }
}
