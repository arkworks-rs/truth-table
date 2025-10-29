use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use super::{
    Runnable,
    common::{OracleArg, ParquetArg, QueryArg},
};
use crate::prove::ProveBuilder;

#[derive(Args, Debug)]
pub struct Prove {
    #[command(flatten)]
    pub query: QueryArg,

    #[command(flatten)]
    pub parquet: ParquetArg,

    #[command(flatten)]
    pub oracle: OracleArg,

    /// Output proof path (file or directory)
    #[arg(long, value_name = "PATH", value_hint = clap::ValueHint::AnyPath)]
    pub output_path: Option<PathBuf>,

    /// Print how long the command takes to execute
    #[arg(long)]
    pub timed: bool,
}

#[async_trait::async_trait]
impl Runnable for Prove {
    async fn run(self) -> Result<()> {
        let runner = ProveBuilder::new()
            .with_query(self.query.query.clone())
            .with_parquet_paths(self.parquet.parquet.clone())
            .with_oracle_paths(self.oracle.oracle.clone())
            .with_output_path(self.output_path.clone())
            .build()?;

        let output = runner.run().await?;
        println!("proof written to {}", output.display());
        Ok(())
    }
}

impl super::TimedCommand for Prove {
    fn is_timed(&self) -> bool {
        self.timed
    }
}
