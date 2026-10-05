//! Offline tooling for the fingerprint rules: synthetic workloads, the
//! width sweep that prices the committed rule, and the cost-model fit.
//!
//! ```text
//! tt-fp-opt workload --out workload.csv
//! tt-fp-opt sweep    --workload workload.csv --model model.toml --out sweep.csv
//! tt-fp-opt fit      --points points.csv --out model.toml
//! ```

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use arithmetic::fingerprint::{Bin, Feature, single};
use clap::{Args, Parser, Subcommand};
use tt_fingerprint_optimizer::corpus::{Corpus, FeatureIndex, LengthPlanes, pattern_features};
use tt_fingerprint_optimizer::model::{self, CostModel, Shape, TERMS};
use tt_fingerprint_optimizer::pricing::{self, Assignment, Problem};
use tt_fingerprint_optimizer::workload::{self, Query, REGIMES, regime_label};

#[derive(Parser)]
#[command(about = "Fingerprint rule tooling")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Clone)]
struct CorpusArgs {
    /// `parquet_path:column` of the column.
    #[arg(
        long,
        default_value = "artifacts/bench-data/lineitem.parquet:l_comment"
    )]
    corpus: String,
    /// Activator column; rows where it is false are padding.
    #[arg(long, default_value = "__activator__")]
    activator: String,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a synthetic workload filling every selectivity regime.
    Workload {
        #[command(flatten)]
        corpus: CorpusArgs,
        #[arg(long, default_value_t = 300)]
        per_regime: usize,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// Where to write one workload. Required unless `--out-dir` is
        /// given.
        #[arg(long, conflicts_with = "out_dir")]
        out: Option<PathBuf>,
        /// Generate a workload for EVERY string column of the corpus
        /// parquet, writing `<column>.csv` here. The `--corpus` column
        /// suffix is then optional and ignored.
        #[arg(long)]
        out_dir: Option<PathBuf>,
    },
    /// Price the committed rule at every width in `--widths`,
    /// every query choosing its own bins as the prover does. Bins are
    /// renumbered densely, in their original order, so a narrow rule
    /// touches few limbs.
    Sweep {
        #[command(flatten)]
        corpus: CorpusArgs,
        #[arg(long)]
        workload: PathBuf,
        #[arg(long)]
        model: PathBuf,
        #[arg(
            long,
            value_delimiter = ',',
            default_value = "1,2,4,8,12,16,24,32,48,64,96,128,192,256,384,512,768,1024,1536,2048"
        )]
        widths: Vec<usize>,
        /// `bins,regime,label,queries,no_filter_s,cost_s,greedy_bins,greedy_limbs,survivors,perfect_s`
        #[arg(long)]
        out: PathBuf,
        /// Also write every query's limb chain at the widths in
        /// `--chains-at`: `bins,regime,query,limbs,cost_s,chosen`, the cost
        /// after the prover's first `limbs` limbs, `chosen` marking its pick.
        #[arg(long, requires = "chains_at")]
        chains: Option<PathBuf>,
        #[arg(long, value_delimiter = ',')]
        chains_at: Vec<usize>,
        /// Also write every query's shape under the prover's choice at every
        /// width: `bins,regime,pattern,matches,factors,literal_len,limbs,
        /// survivors,survivor_chars,none_s,cost_s` (rows and characters of
        /// the column are the same for all).
        #[arg(long)]
        shapes: Option<PathBuf>,
    },
    /// Fit the cost model to measured points (`tt-fp-calibrate` rows).
    Fit {
        /// CSV files of measured points.
        #[arg(long, required = true, num_args = 1..)]
        points: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
        /// Also write `measured_s,model_s,held_out_s,pattern` per point.
        #[arg(long)]
        predictions: Option<PathBuf>,
        /// Hold a coefficient at a measured value, e.g. `touched_limb=0.678`.
        #[arg(long = "fix", value_parser = parse_fixed_term)]
        fixed: Vec<(usize, f64)>,
    },
}

/// `term=seconds` for `fit --fix`.
fn parse_fixed_term(arg: &str) -> Result<(usize, f64), String> {
    let (name, value) = arg
        .split_once('=')
        .ok_or_else(|| format!("expected term=seconds, got {arg:?}"))?;
    let term = TERMS
        .iter()
        .position(|t| *t == name)
        .ok_or_else(|| format!("unknown term {name:?}; terms: {}", TERMS.join(", ")))?;
    let value = value
        .parse::<f64>()
        .map_err(|e| format!("{value:?}: {e}"))?;
    Ok((term, value))
}

/// The parquet path of a `--corpus` value, with or without a `:column`
/// suffix (a Windows-style drive letter is not a concern here).
fn corpus_path(args: &CorpusArgs) -> &str {
    match args.corpus.rsplit_once(':') {
        Some((path, _)) if !path.is_empty() => path,
        _ => &args.corpus,
    }
}

fn load_corpus(args: &CorpusArgs) -> Result<Corpus> {
    let (path, column) = args
        .corpus
        .rsplit_once(':')
        .context("--corpus must be parquet_path:column")?;
    let corpus = Corpus::from_parquet(Path::new(path), column, Some(&args.activator))?;
    eprintln!(
        "corpus: {} rows, mean length {:.1}",
        corpus.len(),
        corpus.avg_len()
    );
    Ok(corpus)
}

fn load_model(path: &Path) -> Result<CostModel> {
    CostModel::from_toml_str(
        &std::fs::read_to_string(path).with_context(|| format!("read model {}", path.display()))?,
    )
    .map_err(anyhow::Error::msg)
}

fn write(path: &Path, text: &str) -> Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, text).with_context(|| format!("write {}", path.display()))?;
    eprintln!("wrote {}", path.display());
    Ok(())
}

/// Workload CSV: `regime,matches,pattern` (patterns never contain a comma
/// they could be confused by: the pattern is the last field).
fn write_workload(path: &Path, queries: &[Query]) -> Result<()> {
    let mut csv = String::from("regime,matches,pattern\n");
    for q in queries {
        let _ = writeln!(csv, "{},{},{}", q.regime, q.matches, q.pattern());
    }
    write(path, &csv)
}

fn read_workload(path: &Path, corpus: &Corpus, index: &FeatureIndex) -> Result<Vec<Query>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read workload {}", path.display()))?;
    let mut queries = Vec::new();
    for line in text.lines().skip(1) {
        let mut fields = line.splitn(3, ',');
        let (Some(regime), Some(matches), Some(pattern)) =
            (fields.next(), fields.next(), fields.next())
        else {
            bail!("malformed workload line {line:?}");
        };
        let factors = workload::parse_pattern(pattern)?;
        let matches: usize = matches.parse()?;
        let regime: usize = regime.parse()?;
        if Some(regime) != workload::regime_of(matches as f64 / corpus.len() as f64) {
            bail!("workload {pattern:?} was generated for another corpus");
        }
        let features = pattern_features(&factors)
            .into_iter()
            .filter_map(|f| index.id(f))
            .collect();
        queries.push(Query {
            factors,
            matches,
            regime,
            features,
        });
    }
    Ok(queries)
}

/// `pairs` on the corpus' features, its bins renumbered `0..` in their
/// original order (features the corpus lacks are dropped).
fn dense_assignment(pairs: &[(Feature, usize)], index: &FeatureIndex) -> Assignment {
    let mut used: Vec<usize> = pairs.iter().map(|&(_, b)| b).collect();
    used.sort_unstable();
    used.dedup();
    let bin_of: std::collections::HashMap<Feature, usize> = pairs.iter().copied().collect();
    Assignment {
        bin_of: index
            .features
            .iter()
            .map(|f| {
                bin_of
                    .get(f)
                    .map(|b| used.binary_search(b).expect("collected above") as Bin)
            })
            .collect(),
    }
}

/// Per-regime means of a [`pricing::select`] run.
struct SelectRow {
    queries: usize,
    none: f64,
    greedy: f64,
    greedy_bins: f64,
    greedy_limbs: f64,
    greedy_survivors: f64,
    perfect: f64,
}

fn select_rows(selected: &[pricing::Selected]) -> Vec<SelectRow> {
    (0..REGIMES.len())
        .map(|r| {
            let rows: Vec<_> = selected.iter().filter(|s| s.regime == r).collect();
            let n = rows.len().max(1) as f64;
            let mean =
                |f: &dyn Fn(&pricing::Selected) -> f64| rows.iter().map(|s| f(s)).sum::<f64>() / n;
            SelectRow {
                queries: rows.len(),
                none: mean(&|s| s.none),
                greedy: mean(&|s| s.greedy),
                greedy_bins: mean(&|s| s.greedy_bins as f64),
                greedy_limbs: mean(&|s| s.greedy_limbs as f64),
                greedy_survivors: mean(&|s| s.greedy_survivors as f64),
                perfect: mean(&|s| s.perfect),
            }
        })
        .collect()
}

/// Measured point CSV (as printed by `tt-fp-calibrate`).
fn read_points(path: &Path) -> Result<Vec<(String, Shape, f64)>> {
    let text = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in text.lines() {
        if line.starts_with("pattern") || line.trim().is_empty() {
            continue;
        }
        // The pattern is first and may contain commas: parse from the right.
        let fields: Vec<&str> = line.rsplitn(10, ',').collect();
        if fields.len() != 10 {
            bail!("malformed point {line:?}");
        }
        let factors = workload::parse_pattern(fields[9])?.len();
        let num = |i: usize| -> Result<f64> { Ok(fields[i].parse::<f64>()?) };
        let shape = Shape {
            rows: num(7)? as usize,
            chars: num(6)?,
            survivors: num(5)? as usize,
            survivor_chars: num(4)?,
            matches: num(3)? as usize,
            touched_limbs: num(2)? as usize,
            literal_len: num(1)? as usize,
            factors,
        };
        out.push((fields[9].to_string(), shape, num(0)?));
    }
    Ok(out)
}

/// A rule's feature → bin pairs.
type Pairs = Vec<(Feature, usize)>;

/// Each width's feature → bin pairs, in the order asked: the committed
/// rule's bins are numbered most common first, so a width keeps a prefix.
fn width_rules(strings: &[Vec<u8>], widths: &[usize]) -> Result<Vec<(usize, Pairs)>> {
    let all = single::single_feature_rule("sweep", strings)
        .assignment()
        .map_err(anyhow::Error::msg)?;
    Ok(widths
        .iter()
        .map(|&w| (w, all.iter().copied().filter(|&(_, b)| b < w).collect()))
        .collect())
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Workload {
            corpus,
            per_regime,
            seed,
            out,
            out_dir,
        } => {
            let one = |column: &str, path: &PathBuf| -> Result<()> {
                let c = Corpus::from_parquet(
                    Path::new(corpus_path(&corpus)),
                    column,
                    Some(&corpus.activator),
                )?;
                let index = FeatureIndex::build(&c);
                let queries = workload::generate(&c, &index, per_regime, seed);
                eprintln!(
                    "{column}: {} rows, mean length {:.1}, {} features",
                    c.len(),
                    c.avg_len(),
                    index.len()
                );
                for r in 0..REGIMES.len() {
                    let n = queries.iter().filter(|q| q.regime == r).count();
                    eprintln!("  {:>8}: {n} queries", regime_label(r));
                }
                write_workload(path, &queries)
            };
            match (out, out_dir) {
                (_, Some(dir)) => {
                    // Whole table: every string column, discovered from the
                    // file's own schema.
                    let path = Path::new(corpus_path(&corpus));
                    let columns = Corpus::string_columns(path)?;
                    if columns.is_empty() {
                        bail!("no string columns in {}", path.display());
                    }
                    std::fs::create_dir_all(&dir)?;
                    for column in columns {
                        one(&column, &dir.join(format!("{column}.csv")))?;
                    }
                    Ok(())
                }
                (Some(out), None) => {
                    let (_, column) = corpus
                        .corpus
                        .rsplit_once(':')
                        .context("--corpus must be parquet_path:column")?;
                    let column = column.to_string();
                    one(&column, &out)
                }
                (None, None) => bail!("pass --out <file> or --out-dir <dir>"),
            }
        }
        Command::Sweep {
            corpus: corpus_args,
            workload,
            model,
            widths,
            out,
            chains,
            chains_at,
            shapes,
        } => {
            let corpus = load_corpus(&corpus_args)?;
            let index = FeatureIndex::build(&corpus);
            let queries = read_workload(&workload, &corpus, &index)?;
            let lengths = LengthPlanes::new(&corpus);
            let problem = Problem::new(&index, &queries, load_model(&model)?, &lengths);
            let mut csv = String::from(
                "bins,regime,label,queries,no_filter_s,cost_s,greedy_bins,greedy_limbs,survivors,perfect_s\n",
            );
            let mut chain_csv = String::from("bins,regime,query,limbs,cost_s,chosen\n");
            let mut shape_csv = String::from(
                "bins,regime,pattern,matches,factors,literal_len,limbs,survivors,survivor_chars,none_s,cost_s\n",
            );
            for (width, pairs) in width_rules(&corpus.strings, &widths)? {
                let assignment = dense_assignment(&pairs, &index);
                let bins = assignment.used_bins();
                let selected = pricing::select(&problem, &assignment);
                let rows = select_rows(&selected);
                let used: Vec<&SelectRow> = rows.iter().filter(|r| r.queries > 0).collect();
                eprintln!(
                    "{width} bins ({bins} used): J = {:.3} s",
                    used.iter().map(|r| r.greedy).sum::<f64>() / used.len().max(1) as f64,
                );
                for (query, sel) in queries.iter().zip(&selected) {
                    writeln!(
                        shape_csv,
                        "{bins},{},{},{},{},{},{},{},{},{:.4},{:.4}",
                        sel.regime,
                        query.pattern(),
                        sel.matches,
                        query.factors.len(),
                        query.literal_len(),
                        sel.greedy_limbs,
                        sel.greedy_survivors,
                        sel.greedy_survivor_chars,
                        sel.none,
                        sel.greedy
                    )?;
                }
                if chains_at.contains(&width) {
                    for (q, sel) in selected.iter().enumerate() {
                        for (k, cost) in sel.chain.iter().enumerate() {
                            writeln!(
                                chain_csv,
                                "{bins},{},{q},{k},{cost:.4},{}",
                                sel.regime,
                                u8::from(k == sel.greedy_limbs)
                            )?;
                        }
                    }
                }
                for (r, row) in rows.iter().enumerate() {
                    if row.queries == 0 {
                        continue;
                    }
                    writeln!(
                        csv,
                        "{bins},{r},{},{},{:.4},{:.4},{:.3},{:.3},{:.1},{:.4}",
                        regime_label(r),
                        row.queries,
                        row.none,
                        row.greedy,
                        row.greedy_bins,
                        row.greedy_limbs,
                        row.greedy_survivors,
                        row.perfect,
                    )?;
                }
            }
            if let Some(path) = chains {
                write(&path, &chain_csv)?;
            }
            if let Some(path) = shapes {
                write(&path, &shape_csv)?;
            }
            write(&out, &csv)
        }
        Command::Fit {
            points,
            out,
            predictions,
            fixed,
        } => {
            let mut all = Vec::new();
            for path in &points {
                all.extend(read_points(path)?);
            }
            let points: Vec<_> = all.iter().map(|(_, shape, secs)| (*shape, *secs)).collect();
            let fitted = model::fit_with_fixed(&points, &fixed);
            let held_out = model::leave_one_out(&points, &fixed);
            for (name, c) in TERMS.iter().zip(fitted.coefficients) {
                eprintln!("  {name:>34} = {c:.6e}");
            }
            eprintln!(
                "{:>40} {:>9} {:>9} {:>7} {:>9}",
                "pattern", "measured", "model", "error", "held-out"
            );
            let (mut fit_sq, mut held_sq) = (0.0, 0.0);
            for ((pattern, shape, secs), held) in all.iter().zip(&held_out) {
                let modeled = fitted.cost(shape);
                fit_sq += (modeled - secs).powi(2);
                held_sq += (held - secs).powi(2);
                eprintln!(
                    "{pattern:>40} {secs:>9.2} {modeled:>9.2} {:>+7.2} {:>+9.2}",
                    modeled - secs,
                    held - secs
                );
            }
            if let Some(path) = predictions {
                let mut csv = String::from("measured_s,model_s,held_out_s,pattern\n");
                for ((pattern, shape, secs), held) in all.iter().zip(&held_out) {
                    let _ = writeln!(csv, "{secs},{},{held},{pattern}", fitted.cost(shape));
                }
                write(&path, &csv)?;
            }
            let n = all.len().max(1) as f64;
            eprintln!(
                "rms error: fit {:.2}s, leave-one-out {:.2}s over {} points",
                (fit_sq / n).sqrt(),
                (held_sq / n).sqrt(),
                all.len()
            );
            write(&out, &fitted.to_toml_string())
        }
    }
}
