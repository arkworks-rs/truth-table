use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use super::{Runnable, TimedCommand};

#[derive(Args, Debug)]
pub struct DataGen {
    /// Explicit scale factor (default 0.01). Conflicts with --test and --bench.
    #[arg(long, conflicts_with_all = ["test", "bench"])]
    pub scale: Option<f64>,

    /// Output directory for the generated Parquet files.
    #[arg(long)]
    pub output_dir: Option<PathBuf>,

    /// Generate the test dataset (scale = 0.001, default output dir =
    /// tpch-data/test-data).
    #[arg(long, conflicts_with_all = ["scale", "bench"])]
    pub test: bool,

    /// Generate the benchmark dataset (scale = 1, default output dir =
    /// tpch-data/bench-data).
    #[arg(long, conflicts_with_all = ["scale", "test"])]
    pub bench: bool,

    /// Print how long the command takes to execute.
    #[arg(long)]
    pub timed: bool,
}

fn default_output_dir(is_bench: bool) -> PathBuf {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // exec/Cargo.toml lives in .../dbsnark-system/exec, so hop to workspace root.
    let tpch_dir = base.join("..").join("tpch-data");
    if is_bench {
        tpch_dir.join("bench-data")
    } else {
        tpch_dir.join("test-data")
    }
}

#[async_trait::async_trait(?Send)]
impl Runnable for DataGen {
    async fn run(self) -> Result<()> {
        let scale = if self.test {
            0.0005
        } else if self.bench {
            0.06
        } else {
            self.scale.unwrap_or(0.01)
        };

        let out_dir = self
            .output_dir
            .unwrap_or_else(|| default_output_dir(self.bench));

        println!(
            "Generating TPC-H data at scale {:.3} into {}",
            scale,
            out_dir.display()
        );

        tpch_data::generate_parquet_scale(scale, &out_dir);

        println!("TPC-H data generation completed.");
        Ok(())
    }
}

impl TimedCommand for DataGen {
    fn is_timed(&self) -> bool {
        self.timed
    }
}
