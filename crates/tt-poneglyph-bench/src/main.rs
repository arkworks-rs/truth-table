//! Runs one (query, k) PoneglyphDB kzg circuit through setup, prove and
//! verify, and prints one JSON object on the last line of stdout. Poneglyph's
//! own `println!`s come before it; `run_pgn.sh` tees all of it to its raw log.
//!
//! `--k` and the lineitem size (PoneglyphDB README):
//!
//! ```text
//! k  rows
//! 16 60K     ↔ TPC-H SF=0.01
//! 17 120K    ↔ TPC-H SF=0.02
//! 18 240K    ↔ TPC-H SF=0.04
//! ```
//!
//! The README says Q3 fits at k=15, but its circuit panics there with
//! NotEnoughRowsAvailable, so `run_pgn.sh` sweeps all six queries at
//! k=16/17/18. This binary passes `--k` through unchanged.

use anyhow::Result;
use clap::Parser;
use poneglyph::poneglyph_bench::{BenchResult, run_q1, run_q3, run_q5, run_q8, run_q9, run_q18};
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
    /// Lets the parser find this object among Poneglyph's other stdout lines.
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
