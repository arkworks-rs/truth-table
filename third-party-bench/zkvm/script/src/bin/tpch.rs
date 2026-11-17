//! The SP1 zkVM baseline on the TPC-H queries of `tt_zkvm_lib::tpch`, over
//! the tables the baseline bench generates under
//! `third-party-bench/artifact/tpch/sf_<sf>/` (without padding or system
//! columns). Before proving, each query's result is checked against
//! DataFusion's in `reference/` (written by the third-party-bench
//! `tpch_reference` binary).
//!
//! `ZKVM_SFS` (default 0.01,0.02,0.04,0.05,0.1) and `ZKVM_QUERIES` (e.g.
//! `tt_q1,pgn_q3`) narrow the sweep. Each committed table prints
//!   table sf=<sf> name=<t> rows=<n> commit_ms=<ms> commitment_bytes=<b>
//! and each query `tt_zkvm_script::Bench`'s lines, labelled
//! `sf=<sf> variant=<tt|pgn> q=<n>`; their commit fields sum the query's tables.

use std::{collections::BTreeMap, path::Path};

use tt_zkvm_lib::{tpch, Query};
use tt_zkvm_script::{check_against, env_list, load_table, Bench, Table};

const TT_QUERIES: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 15, 17, 18, 19, 20];
const PGN_QUERIES: &[u8] = &[1, 3, 5, 8, 9, 18];

fn main() {
    let artifact = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifact/tpch");
    let sfs = env_list("ZKVM_SFS").unwrap_or_else(|| {
        ["0.01", "0.02", "0.04", "0.05", "0.1"]
            .map(String::from)
            .to_vec()
    });
    let only = env_list("ZKVM_QUERIES");
    let bench = Bench::new();

    for sf in sfs {
        let sf_dir = artifact.join(format!("sf_{sf}"));
        let out_dir = sf_dir.join("zkvm");
        std::fs::create_dir_all(&out_dir).expect("create zkvm dir");
        let specs: Vec<(&str, u8)> = TT_QUERIES
            .iter()
            .map(|&q| ("tt", q))
            .chain(PGN_QUERIES.iter().map(|&q| ("pgn", q)))
            .filter(|(v, q)| {
                only.as_ref()
                    .is_none_or(|o| o.iter().any(|x| *x == format!("{v}_q{q}")))
            })
            .collect();

        // Every table once: (table, commitment path, commit ms, commitment bytes).
        let mut tables: BTreeMap<String, (Table, std::path::PathBuf, f64, u64)> = BTreeMap::new();
        for &(variant, q) in &specs {
            for base in tpch::tables(q) {
                let name = if variant == "pgn" {
                    format!("{base}_poneglyph")
                } else {
                    base.to_string()
                };
                if tables.contains_key(&name) {
                    continue;
                }
                let table = if variant == "pgn" {
                    load_table(
                        &name,
                        &sf_dir.join("data").join(format!("{name}.parquet")),
                        true,
                    )
                } else {
                    load_table(
                        &name,
                        &sf_dir.join("orig-data").join(format!("{name}.parquet")),
                        false,
                    )
                };
                let (paths, ms, bytes) = bench.commit(&out_dir, &[&table]);
                println!(
                    "table sf={sf} name={name} rows={} commit_ms={ms:.4} commitment_bytes={bytes}",
                    table.columns.first().map_or(0, |(_, c)| c.len())
                );
                tables.insert(name, (table, paths[0].clone(), ms, bytes));
            }
        }

        for (variant, q) in specs {
            let query = Query::Tpch {
                q,
                pgn: variant == "pgn",
            };
            let entries: Vec<_> = tpch::tables(q)
                .iter()
                .map(|base| {
                    let name = if variant == "pgn" {
                        format!("{base}_poneglyph")
                    } else {
                        base.to_string()
                    };
                    &tables[&name]
                })
                .collect();
            let query_tables: Vec<&Table> = entries.iter().map(|e| &e.0).collect();
            let paths: Vec<_> = entries.iter().map(|e| e.1.clone()).collect();
            let commit = (
                entries.iter().map(|e| e.2).sum::<f64>(),
                entries.iter().map(|e| e.3).sum::<u64>(),
            );
            let reference = sf_dir.join("reference").join(format!("{variant}_q{q}.csv"));
            if let Err(err) = check_against(&Bench::result(query, &query_tables), &reference) {
                panic!("sf={sf} {variant} q{q} differs from DataFusion: {err}");
            }
            bench.run(
                &format!("sf={sf} variant={variant} q={q}"),
                query,
                &query_tables,
                &paths,
                commit,
                &out_dir,
            );
        }
    }
}
