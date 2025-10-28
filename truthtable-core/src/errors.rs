//! Error utilities for the TruthTable core crate.

use ark_piop::errors::SnarkError;
use thiserror::Error;

/// Error type used across the TruthTable codebase.
#[derive(Debug, Error)]
pub enum TTError {
    #[error("{0}")]
    Snark(#[from] SnarkError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] ark_serialize::SerializationError),
}

/// Convenient result alias for functions that return a `TTError`.
pub type TTResult<T> = Result<T, TTError>;
