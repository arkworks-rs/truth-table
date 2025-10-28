use clap::Args;
use std::path::PathBuf;

#[derive(Args, Debug, Clone)]
pub struct ParquetArg {
    /// Path to input parquet file
    #[arg(long = "parquet-path", value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    pub parquet: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub struct OracleArg {
    /// Path to oracle file
    #[arg(long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    pub oracle: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub struct QueryArg {
    /// Query string
    #[arg(long, value_name = "SQL")]
    pub query: String,
}
