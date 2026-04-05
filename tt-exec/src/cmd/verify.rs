use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use super::{
    Runnable,
    common::{OracleArg, QueryArg},
};
use crate::verify::VerifyBuilder;

#[derive(Args, Debug)]
pub struct Verify {
    #[command(flatten)]
    pub query: QueryArg,

    #[command(flatten)]
    pub oracle: OracleArg,

    /// Path to the proof artifact
    #[arg(long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    pub proof: PathBuf,

    /// Path to the prover-produced result parquet
    #[arg(long = "result-path", value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    pub result_path: PathBuf,

    /// Path to serialized verifying key (TTVerifyingKey)
    #[arg(long = "vk-path", value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    pub vk_path: PathBuf,

    /// Print how long the command takes to execute
    #[arg(long)]
    pub timed: bool,
}

#[async_trait::async_trait(?Send)]
impl Runnable for Verify {
    async fn run(self) -> Result<()> {
        let sql = self.query.resolve_sql()?;
        let runner = VerifyBuilder::new()
            .with_query(sql)
            .with_oracle_paths(self.oracle.oracle)
            .with_proof_path(self.proof)
            .with_result_path(self.result_path)
            .with_vk_path(self.vk_path)
            .build()?;

        runner.run().await?;
        Ok(())
    }
}

impl super::TimedCommand for Verify {
    fn is_timed(&self) -> bool {
        self.timed
    }
}
