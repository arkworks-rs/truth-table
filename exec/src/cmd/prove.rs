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

    /// Path to serialized proving key (TTProvingKey)
    #[arg(long = "pk-path", value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    pub pk_path: Option<PathBuf>,

    /// Output proof path (file or directory)
    #[arg(long, value_name = "PATH", value_hint = clap::ValueHint::AnyPath)]
    pub output_path: Option<PathBuf>,

    /// Print how long the command takes to execute
    #[arg(long)]
    pub timed: bool,
}

#[async_trait::async_trait(?Send)]
impl Runnable for Prove {
    async fn run(self) -> Result<()> {
        let mut builder = ProveBuilder::new()
            .with_query(self.query.query)
            .with_parquet_paths(self.parquet.parquet)
            .with_oracle_paths(self.oracle.oracle)
            .with_output_path(self.output_path);

        if let Some(pk_path) = self.pk_path {
            builder = builder.with_pk_path(pk_path);
        }

        let runner = builder.build()?;
        let output = runner.run().await?;
        println!("proof written to {}", output.display());
        Ok(())
    }

    async fn run_timed(self) -> Result<()> {
        let mut builder = ProveBuilder::new()
            .with_query(self.query.query)
            .with_parquet_paths(self.parquet.parquet)
            .with_oracle_paths(self.oracle.oracle)
            .with_output_path(self.output_path);

        if let Some(pk_path) = self.pk_path {
            builder = builder.with_pk_path(pk_path);
        }

        let runner = builder.build()?;

        match runner.run_with_build_timing().await {
            Ok((output, elapsed)) => {
                println!("proof written to {}", output.display());
                println!("build proof completed in {:.2?}", elapsed);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

impl super::TimedCommand for Prove {
    fn is_timed(&self) -> bool {
        self.timed
    }
}
