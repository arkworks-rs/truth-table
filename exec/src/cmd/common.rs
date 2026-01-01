use clap::Args;
use std::path::PathBuf;

#[derive(Args, Debug, Clone)]
pub struct ParquetArg {
    /// Path(s) to input parquet file(s)
    #[arg(
        long = "parquet-path",
        value_name = "FILE",
        value_hint = clap::ValueHint::FilePath,
        required = true,
        num_args = 1..,
        action = clap::ArgAction::Append
    )]
    pub parquet: Vec<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct OracleArg {
    /// Path(s) to oracle file(s)
    #[arg(
        long,
        value_name = "FILE",
        value_hint = clap::ValueHint::FilePath,
        required = true,
        num_args = 1..,
        action = clap::ArgAction::Append
    )]
    pub oracle: Vec<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct QueryArg {
    /// Query string
    #[arg(long, value_name = "SQL")]
    pub query: String,
}
