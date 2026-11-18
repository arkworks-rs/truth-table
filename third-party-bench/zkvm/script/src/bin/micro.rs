//! The SP1 zkVM on the micro queries, over the parquet files TruthTable's
//! `micro_data` writes under `third-party-bench/artifact/micro/`, so it proves
//! over the same rows as the other systems. `MICRO_POWS` (default 15 to 20) and
//! `MICRO_QUERIES` narrow the sweep; the output is `tt_zkvm_script::Bench`'s.

use std::path::Path;

use tt_zkvm_lib::{micro::Micro, Query};
use tt_zkvm_script::{env_list, load_table, Bench};

/// `micro.rs`'s queries and their tables.
const QUERIES: &[(&str, &[&str])] = &[
    ("filter_0p1", &["filter_0p1"]),
    ("filter_1", &["filter_1"]),
    ("filter_10", &["filter_10"]),
    ("aggregate", &["aggregate"]),
    ("range", &["range"]),
    ("in_list", &["in_list"]),
    ("arithmetic", &["arithmetic"]),
    ("group_by", &["group_by"]),
    ("join_pk_fk", &["join_pk_fk_l", "join_pk_fk_r"]),
    ("join_m2m", &["join_m2m_l", "join_m2m_r"]),
    ("order_by", &["order_by"]),
];

fn main() {
    let artifact = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifact/micro");
    let pows: Vec<u32> = env_list("MICRO_POWS")
        .map(|v| v.iter().map(|p| p.parse().expect("MICRO_POWS")).collect())
        .unwrap_or_else(|| (15..=20).collect());
    let only = env_list("MICRO_QUERIES");
    let bench = Bench::new();

    for pow in pows {
        for &(name, tables) in QUERIES {
            if only.as_ref().is_some_and(|o| !o.iter().any(|q| q == name)) {
                continue;
            }
            let dir = artifact.join(format!("size_{pow}")).join(name);
            let tables: Vec<_> = tables
                .iter()
                .map(|t| {
                    let table = format!("{t}_{pow}");
                    load_table(&table, &dir.join(format!("{table}.parquet")), false)
                })
                .collect();
            let tables: Vec<_> = tables.iter().collect();
            let (paths, commit_ms, commit_bytes) = bench.commit(&dir, &tables);
            let query = Query::Micro(Micro::from_name(name).expect("micro query"));
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
