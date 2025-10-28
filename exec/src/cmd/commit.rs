use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use super::{Runnable, common::ParquetArg};
use crate::commit::CommitBuilder;

#[derive(Args, Debug)]
pub struct Commit {
    #[command(flatten)]
    pub parquet: ParquetArg,

    /// Path to serialized proving key (TTProvingKey)
    #[arg(long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    pub pk_path: PathBuf,

    /// Output directory or file path for the generated oracle
    #[arg(long, value_name = "PATH", value_hint = clap::ValueHint::AnyPath)]
    pub output_path: Option<PathBuf>,

    /// Print how long the command takes to execute
    #[arg(long)]
    pub timed: bool,
}

#[async_trait::async_trait]
impl Runnable for Commit {
    async fn run(self) -> Result<()> {
        let runner = CommitBuilder::new()
            .with_parquet_path(self.parquet.parquet.clone())
            .with_pk_path(self.pk_path.clone())
            .with_output_path(self.output_path.clone())
            .build()?;

        let output = runner.run().await?;
        println!("oracle written to {}", output.display());
        Ok(())
    }
}

impl super::TimedCommand for Commit {
    fn is_timed(&self) -> bool {
        self.timed
    }
}
