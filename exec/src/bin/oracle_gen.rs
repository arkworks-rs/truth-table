use std::path::PathBuf;

use clap::Parser;

use exec::data_owner::commit_parquet_serializes_oracle;

#[derive(Parser, Debug)]
#[command(author, version, about = "Generate an oracle commitment for a parquet file", long_about = None)]
struct Args {
    /// Path to the parquet file to commit
    parquet: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    commit_parquet_serializes_oracle(&args.parquet)?;
    println!(
        "Committed and verified oracle for {}",
        args.parquet.display()
    );
    Ok(())
}
