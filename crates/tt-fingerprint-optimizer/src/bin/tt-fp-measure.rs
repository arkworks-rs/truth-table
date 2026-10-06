//! Measurements for the width figures: `commit` times committing a table
//! at one fingerprint width (building the rules, encoding and committing;
//! not loading the key); `query` proves and verifies one LIKE query against
//! a given oracle and reports the prover time, verifier time and proof
//! size.
//!
//! ```text
//! tt commit --parquet-path lineitem.parquet --pk-path pk \
//!     --fp-bins 64 --output-path lineitem-64.oracle
//! cargo run --release -p tt-fingerprint-optimizer --features calibration \
//!     --bin tt-fp-measure -- query --parquet lineitem.parquet \
//!     --oracle lineitem-64.oracle --pk pk --vk vk --pattern '%erve%' \
//!     --out-dir scratch/
//! ```
//!
//! Prints `pattern,prove_s,verify_s,proof_bytes,result_rows`, `verify_s`
//! the median of `--verify-runs`. Only `prove` and `verify` themselves are
//! timed, not loading keys or oracles.
//! The query is `SELECT l_returnflag FROM <table> WHERE l_comment LIKE
//! 'pattern'`, the table named after the parquet file.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tt_exec::prove::ProveBuilder;
use tt_exec::verify::VerifyBuilder;

#[derive(Parser)]
#[command(about = "Measure a commit, or one LIKE query's proof")]
enum Cli {
    /// Prove and verify one LIKE query; report times and proof size.
    Query(QueryArgs),
    /// Commit a table at a fingerprint width; print
    /// `bins,commit_s,oracle_bytes,bins_bytes` (`bins_bytes`: the prover's
    /// `<oracle>.bins`, 0 when there is none).
    Commit(CommitArgs),
}

#[derive(clap::Args)]
struct CommitArgs {
    #[arg(long)]
    parquet: PathBuf,
    #[arg(long)]
    pk: PathBuf,
    #[arg(long)]
    bins: usize,
    #[arg(long)]
    out: PathBuf,
}

#[derive(clap::Args)]
struct QueryArgs {
    #[arg(long)]
    parquet: PathBuf,
    #[arg(long)]
    oracle: PathBuf,
    #[arg(long)]
    pk: PathBuf,
    #[arg(long)]
    vk: PathBuf,
    /// LIKE pattern with `%` wildcards.
    #[arg(long)]
    pattern: String,
    /// Directory for the proof and result files.
    #[arg(long)]
    out_dir: PathBuf,
    /// Verifications to run; the median time is reported. Verifying takes
    /// milliseconds, so one run is at the level of timer noise.
    #[arg(long, default_value_t = 5)]
    verify_runs: usize,
}

fn main() -> Result<()> {
    match Cli::parse() {
        Cli::Query(args) => query(args),
        Cli::Commit(args) => commit(args),
    }
}

fn commit(args: CommitArgs) -> Result<()> {
    let runner = tt_exec::commit::CommitBuilder::new()
        .with_parquet_path(args.parquet)
        .with_pk_path(args.pk)
        .with_output_path(Some(args.out))
        .with_fp_width(Some(args.bins))
        .build()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (path, elapsed) = runtime.block_on(runner.run_with_timing())?;
    let bins_bytes =
        std::fs::metadata(tt_exec::paths::fingerprint_bins_path(&path)).map_or(0, |m| m.len());
    println!(
        "{},{:.4},{},{bins_bytes}",
        args.bins,
        elapsed.as_secs_f64(),
        std::fs::metadata(&path)?.len()
    );
    Ok(())
}

fn query(cli: QueryArgs) -> Result<()> {
    let table = cli
        .parquet
        .file_stem()
        .context("parquet path has no file name")?
        .to_string_lossy()
        .to_string();
    let query = format!(
        "SELECT l_returnflag FROM {table} WHERE l_comment LIKE '{}'",
        cli.pattern.replace('\'', "''")
    );
    std::fs::create_dir_all(&cli.out_dir)?;
    let prover = ProveBuilder::new()
        .with_query(query.clone())
        .with_parquet_paths(vec![cli.parquet])
        .with_oracle_paths(vec![cli.oracle.clone()])
        .with_pk_path(cli.pk)
        .with_output_path(Some(cli.out_dir.join("proof.pi")))
        .build()
        .context("build prover")?;
    // Current-thread runtime, as in `calibration`: the heavy work is rayon's,
    // and a multi-thread tokio runtime oversubscribes against it.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (outputs, prove) = runtime
        .block_on(prover.run_with_build_timing())
        .context("prove")?;
    let proof_bytes = std::fs::metadata(&outputs.proof_path)?.len();
    let result_rows = count_rows(&outputs.result_path)?;
    let verifier = VerifyBuilder::new()
        .with_query(query)
        .with_oracle_path(cli.oracle)
        .with_proof_path(outputs.proof_path)
        .with_result_path(outputs.result_path)
        .with_vk_path(cli.vk)
        .build()
        .context("build verifier")?;
    let mut verify = (0..cli.verify_runs.max(1))
        .map(|_| {
            runtime
                .block_on(verifier.run_with_timing())
                .context("verify")
        })
        .collect::<Result<Vec<_>>>()?;
    verify.sort();
    let verify = verify[verify.len() / 2];
    println!(
        "{},{:.4},{:.4},{proof_bytes},{result_rows}",
        cli.pattern,
        prove.as_secs_f64(),
        verify.as_secs_f64()
    );
    Ok(())
}

fn count_rows(path: &std::path::Path) -> Result<i64> {
    use parquet::file::reader::{FileReader, SerializedFileReader};
    let reader = SerializedFileReader::new(std::fs::File::open(path)?)?;
    Ok(reader.metadata().file_metadata().num_rows())
}
