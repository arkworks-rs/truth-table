//! One-shot Poneglyph bench driver.
//!
//! Runs a single (query, k) PoneglyphDB kzg circuit through setup + prove +
//! verify and prints a single JSON object on the LAST line of stdout. The
//! Poneglyph prover's existing human-readable `println!`s (vk/pk/prove times,
//! data-file paths, etc.) still flow to stdout above the JSON, which is what
//! `run_pgn.sh` tees to its raw log file.
//!
//! Mapping between `--k` and lineitem dataset size (per the PoneglyphDB README):
//!
//! ```text
//! k  rows
//! 16 60K     ↔ TPC-H SF=0.01
//! 17 120K    ↔ TPC-H SF=0.02
//! 18 240K    ↔ TPC-H SF=0.04
//! ```
//!
//! (The PoneglyphDB README claims Q3 fits at one-smaller k=15, but in practice
//! the Q3 circuit panics with NotEnoughRowsAvailable at k=15, so `run_pgn.sh`
//! sweeps all six queries at the same k=16/17/18. This binary just passes
//! whatever `--k` it's given straight through.)

use anyhow::Result;
use clap::Parser;
use poneglyph::poneglyph_bench::{
    run_q1, run_q18, run_q3, run_q5, run_q8, run_q9, BenchResult,
};
use serde::Serialize;

#[derive(Parser)]
#[command(version, about = "Run one PoneglyphDB kzg query and emit JSON.")]
struct Cli {
    /// TPC-H query number (one of: 1, 3, 5, 8, 9, 18).
    #[arg(long, value_parser = ["1", "3", "5", "8", "9", "18"])]
    query: String,

    /// Halo2 degree (typically 15..=18; meaning depends on the query — see README).
    #[arg(long)]
    k: u32,
}

#[derive(Serialize)]
struct Output<'a> {
    /// Marker so the parser can extract this object from amongst Poneglyph's
    /// other human-readable stdout lines.
    marker: &'a str,
    query: &'a str,
    bench: &'a BenchResult,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let bench = match cli.query.as_str() {
        "1" => run_q1(cli.k),
        "3" => run_q3(cli.k),
        "5" => run_q5(cli.k),
        "8" => run_q8(cli.k),
        "9" => run_q9(cli.k),
        "18" => run_q18(cli.k),
        other => anyhow::bail!("unsupported query: {other}"),
    };

    let out = Output {
        marker: "POENGLYPH_BENCH_JSON",
        query: &cli.query,
        bench: &bench,
    };
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}
