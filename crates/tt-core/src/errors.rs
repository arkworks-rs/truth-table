//! The crate-wide error type.

use ark_piop::errors::SnarkError;
use datafusion_common::DataFusionError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TTError {
    #[error("{0}")]
    Snark(#[from] SnarkError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] ark_serialize::SerializationError),

    #[error("datafusion error: {0}")]
    DataFusion(#[from] DataFusionError),
}

pub type TTResult<T> = Result<T, TTError>;
