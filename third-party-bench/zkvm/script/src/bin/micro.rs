//! The SP1 zkVM baseline on the micro queries, over the raw bench parquets of
//! `third-party-bench/artifact/size_<pow>/`. `ZKVM_POWS` (comma-separated,
//! default 16,17,18,19) and `ZKVM_QUERIES` (comma-separated names, default
//! all) narrow the sweep; the output is `tt_zkvm_script::Bench`'s.

use std::path::Path;

use tt_zkvm_lib::Query;
use tt_zkvm_script::{env_list, load_table, Bench};

const QUERIES: &[(&str, &str, Query, &[&str])] = &[
    ("filter", "filter", Query::Filter, &["bench_table"]),
    (
        "aggregate_count",
        "aggregate_count",
        Query::AggregateCount,
        &["bench_table"],
    ),
    (
        "join",
        "Join",
        Query::Join,
        &["bench_table", "bench_table_2"],
    ),
    (
        "join_pk_fk",
        "Join_PK_FK",
        Query::JoinPkFk,
        &["bench_table", "bench_table_2"],
    ),
    (
        "limit_offset",
        "Limit_Offset",
        Query::Limit,
        &["bench_table"],
    ),
];

fn main() {
    let artifact = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifact");
    let pows: Vec<u32> = env_list("ZKVM_POWS")
        .map(|v| v.iter().map(|p| p.parse().expect("ZKVM_POWS")).collect())
        .unwrap_or_else(|| vec![16, 17, 18, 19]);
    let only = env_list("ZKVM_QUERIES");
    let bench = Bench::new();

    for pow in pows {
        for &(name, dir, query, prefixes) in QUERIES {
            if only.as_ref().is_some_and(|o| !o.iter().any(|q| q == name)) {
                continue;
            }
            let dir = artifact.join(format!("size_{pow}")).join(dir);
            let tables: Vec<_> = prefixes
                .iter()
                .map(|prefix| {
                    let table = format!("{prefix}_{pow}");
                    load_table(&table, &dir.join(format!("{table}.parquet")), false)
                })
                .collect();
            let tables: Vec<_> = tables.iter().collect();
            let (paths, commit_ms, commit_bytes) = bench.commit(&dir, &tables);
            bench.run(
                &format!("pow={pow} q={name}"),
                query,
                &tables,
                &paths,
                (commit_ms, commit_bytes),
                &dir,
            );
        }
    }
}
