//! Measure one point of the cost model by proving
//! `SELECT l_returnflag FROM lineitem WHERE l_comment LIKE 'pattern'` on the
//! release bench table under the active fingerprint scheme.
//!
//! ```text
//! cargo run --release -p tt-fingerprint-optimizer --features calibration \
//!     --bin tt-fp-calibrate -- --pattern '%erve%'
//! ```
//!
//! Prints `pattern,bins,rows,chars,survivors,survivor_chars,matches,
//! touched_limbs,literal_len,seconds` — a [`Shape`] and its whole-prove
//! time, the row `tt-fp-opt fit` consumes. The scheme is the rule
//! `commit` gives the column. `bins` counts the bins
//! the planner tests: its greedy choice under the compiled-in cost model,
//! reproduced here with the same function.

use anyhow::Result;
use anyhow::anyhow;
use arithmetic::fingerprint::cost::select_bins;
use arithmetic::fingerprint::{FingerprintScheme, NUM_BINS, column_rule};
use clap::Parser;
use tt_fingerprint_optimizer::calibration::{load_corpus, prove_pattern_seconds};
use tt_fingerprint_optimizer::corpus::like_matches;
use tt_fingerprint_optimizer::model::{CostModel, measure_shape};
use tt_fingerprint_optimizer::workload::parse_pattern;

#[derive(Parser)]
#[command(about = "Prove one LIKE pattern on bench lineitem and report its cost-model point")]
struct Cli {
    /// LIKE pattern with `%` wildcards, e.g. `%erve%` or `%a%bc%`.
    #[arg(long)]
    pattern: String,
    /// Only compute the shape; skip the (slow) prove.
    #[arg(long)]
    shape_only: bool,
    /// Cost model to print a prediction with.
    #[arg(long)]
    model: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let factors = parse_pattern(&cli.pattern)?;
    let corpus = load_corpus()?;
    let scheme =
        FingerprintScheme::from_config(column_rule("l_comment", &corpus.strings, NUM_BINS))
            .map_err(|e| anyhow!("the column rule is invalid: {e}"))?;
    let fingerprints = scheme.fingerprint_all(&corpus.strings);
    let matches = corpus
        .strings
        .iter()
        .filter(|s| like_matches(s, &factors))
        .count();
    let factor_slices: Vec<&[u8]> = factors.iter().map(Vec::as_slice).collect();
    let chosen = select_bins(
        &scheme,
        &CostModel::default(),
        &factor_slices,
        &corpus.strings,
        &fingerprints,
        matches,
    );
    let bins = chosen.bins.len();
    let shape = measure_shape(&corpus, &scheme, &fingerprints, &factors, &chosen.mask());
    debug_assert_eq!(shape.survivors, chosen.shape.survivors);
    let model = match &cli.model {
        Some(path) => Some(
            CostModel::from_toml_str(&std::fs::read_to_string(path)?)
                .map_err(anyhow::Error::msg)?,
        ),
        None => None,
    };
    eprintln!(
        "[calib] scheme={} pattern={} bins={bins} {shape:?}{}",
        scheme.config().name,
        cli.pattern,
        model
            .map(|m| format!(" model={:.2}s", m.cost(&shape)))
            .unwrap_or_default()
    );
    let seconds = if cli.shape_only {
        f64::NAN
    } else {
        prove_pattern_seconds(&cli.pattern)?.as_secs_f64()
    };
    println!(
        "{},{bins},{},{},{},{},{},{},{},{seconds:.4}",
        cli.pattern,
        shape.rows,
        shape.chars,
        shape.survivors,
        shape.survivor_chars,
        shape.matches,
        shape.touched_limbs,
        shape.literal_len
    );
    Ok(())
}
