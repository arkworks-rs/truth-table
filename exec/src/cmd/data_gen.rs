use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use serde::Serialize;
use std::fs;

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
            0.01
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
        write_tpch_constraints(&out_dir)?;

        println!("TPC-H data generation completed.");
        Ok(())
    }
}

impl TimedCommand for DataGen {
    fn is_timed(&self) -> bool {
        self.timed
    }
}

#[derive(Serialize)]
struct ForeignKey<'a> {
    columns: &'a [&'a str],
    ref_table: &'a str,
    ref_columns: &'a [&'a str],
}

#[derive(Serialize)]
struct TableConstraints<'a> {
    primary_key: &'a [&'a str],
    unique: &'a [&'a [&'a str]],
    foreign_keys: &'a [ForeignKey<'a>],
}

#[derive(Serialize)]
struct ConstraintsDump<'a> {
    tables: std::collections::BTreeMap<&'a str, TableConstraints<'a>>,
}

fn write_tpch_constraints(out_dir: &PathBuf) -> Result<()> {
    let mut tables = std::collections::BTreeMap::new();

    tables.insert(
        "region",
        TableConstraints {
            primary_key: &["r_regionkey"],
            unique: &[],
            foreign_keys: &[],
        },
    );
    tables.insert(
        "nation",
        TableConstraints {
            primary_key: &["n_nationkey"],
            unique: &[],
            foreign_keys: &[ForeignKey {
                columns: &["n_regionkey"],
                ref_table: "region",
                ref_columns: &["r_regionkey"],
            }],
        },
    );
    tables.insert(
        "supplier",
        TableConstraints {
            primary_key: &["s_suppkey"],
            unique: &[],
            foreign_keys: &[ForeignKey {
                columns: &["s_nationkey"],
                ref_table: "nation",
                ref_columns: &["n_nationkey"],
            }],
        },
    );
    tables.insert(
        "customer",
        TableConstraints {
            primary_key: &["c_custkey"],
            unique: &[],
            foreign_keys: &[ForeignKey {
                columns: &["c_nationkey"],
                ref_table: "nation",
                ref_columns: &["n_nationkey"],
            }],
        },
    );
    tables.insert(
        "part",
        TableConstraints {
            primary_key: &["p_partkey"],
            unique: &[],
            foreign_keys: &[],
        },
    );
    tables.insert(
        "partsupp",
        TableConstraints {
            primary_key: &["ps_partkey", "ps_suppkey"],
            unique: &[],
            foreign_keys: &[
                ForeignKey {
                    columns: &["ps_partkey"],
                    ref_table: "part",
                    ref_columns: &["p_partkey"],
                },
                ForeignKey {
                    columns: &["ps_suppkey"],
                    ref_table: "supplier",
                    ref_columns: &["s_suppkey"],
                },
            ],
        },
    );
    tables.insert(
        "orders",
        TableConstraints {
            primary_key: &["o_orderkey"],
            unique: &[],
            foreign_keys: &[ForeignKey {
                columns: &["o_custkey"],
                ref_table: "customer",
                ref_columns: &["c_custkey"],
            }],
        },
    );
    tables.insert(
        "lineitem",
        TableConstraints {
            primary_key: &["l_orderkey", "l_linenumber"],
            unique: &[],
            foreign_keys: &[
                ForeignKey {
                    columns: &["l_orderkey"],
                    ref_table: "orders",
                    ref_columns: &["o_orderkey"],
                },
                ForeignKey {
                    columns: &["l_partkey"],
                    ref_table: "part",
                    ref_columns: &["p_partkey"],
                },
                ForeignKey {
                    columns: &["l_suppkey"],
                    ref_table: "supplier",
                    ref_columns: &["s_suppkey"],
                },
                ForeignKey {
                    columns: &["l_partkey", "l_suppkey"],
                    ref_table: "partsupp",
                    ref_columns: &["ps_partkey", "ps_suppkey"],
                },
            ],
        },
    );

    let dump = ConstraintsDump { tables };
    let path = out_dir.join("tpch_constraints.json");
    let payload =
        serde_json::to_string_pretty(&dump).expect("tpch constraints serialization");
    fs::write(&path, payload)?;
    println!("Wrote TPC-H constraints to {}", path.display());
    Ok(())
}
