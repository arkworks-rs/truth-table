use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

use super::Runnable;
use crate::setup::SetupBuilder;

#[derive(Args, Debug)]
pub struct Setup {
    /// Dataset size descriptor (e.g., small, medium, large)
    #[arg(long)]
    pub size: Option<String>,

    /// Path to an existing proving key
    #[arg(long)]
    pub pk_path: Option<PathBuf>,

    /// Path to an existing verifying key
    #[arg(long)]
    pub vk_path: Option<PathBuf>,

    /// Print how long the command takes to execute
    #[arg(long)]
    pub timed: bool,
}

#[async_trait::async_trait]
impl Runnable for Setup {
    async fn run(self) -> Result<()> {
        let runner = SetupBuilder::new()
            .with_size_label(self.size)
            .with_pk_path(self.pk_path)
            .with_vk_path(self.vk_path)
            .build()?;

        runner.run()?;
        Ok(())
    }
}

impl super::TimedCommand for Setup {
    fn is_timed(&self) -> bool {
        self.timed
    }
}
