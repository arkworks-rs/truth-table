use anyhow::{Result, bail};
use clap::Args;
use std::path::PathBuf;
use tpch_data::query_spec;

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
    #[arg(long, value_name = "SQL", conflicts_with = "tpch_query")]
    pub query: Option<String>,

    /// TPCH query number
    #[arg(long = "tpch-query", value_name = "NUM", conflicts_with = "query")]
    pub tpch_query: Option<u8>,
}

impl QueryArg {
    pub fn resolve_sql(&self) -> Result<String> {
        match (&self.query, self.tpch_query) {
            (Some(query), None) => Ok(query.clone()),
            (None, Some(number)) => {
                // Load the TPCH SQL on demand to match the CLI option.
                Ok(query_spec(number, false).sql.to_string())
            }
            _ => bail!("provide either --query or --tpch-query"),
        }
    }
}
