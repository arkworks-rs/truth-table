pub mod commit;
pub mod common;
pub mod prove;
pub mod setup;
pub mod verify;

use anyhow::Result;
use std::time::Instant;

#[async_trait::async_trait]
pub trait Runnable: Sized {
    async fn run(self) -> Result<()>;

    async fn run_timed(self) -> Result<()> {
        let start = Instant::now();
        match self.run().await {
            Ok(()) => {
                println!("completed in {:.2?}", start.elapsed());
                Ok(())
            },
            Err(err) => {
                println!("failed in {:.2?}", start.elapsed());
                Err(err)
            },
        }
    }
}

pub trait TimedCommand {
    fn is_timed(&self) -> bool;
}
