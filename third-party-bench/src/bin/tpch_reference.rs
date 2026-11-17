//! Writes DataFusion's result of every TPC-H query the baselines run, as CSV,
//! for checking the zkVM's hand-written queries:
//! `artifact/tpch/sf_<sf>/reference/<tt|pgn>_q<n>.csv`. The tables are those
//! of the baseline bench, without padding or system columns.
//!
//! Usage: `cargo run --release --bin tpch_reference -- <sf>...`

use std::{fs::File, path::Path, sync::Arc};

use datafusion::{
    arrow::csv::WriterBuilder,
    datasource::MemTable,
    prelude::{SessionConfig, SessionContext},
};
use tpch_data::{Variant, query_spec};
use tt_third_party_bench::baseline::{ensure_tpch_data, load_tpch_table};

const TT_QUERIES: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 15, 17, 18, 19, 20];
const PGN_QUERIES: &[u8] = &[1, 3, 5, 8, 9, 18];

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let bench_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for sf in std::env::args().skip(1) {
        let sf_value: f64 = sf.parse().expect("scale factor");
        let sf_dir = bench_root
            .join("artifact")
            .join("tpch")
            .join(format!("sf_{sf_value}"));
        ensure_tpch_data(&sf_dir, sf_value);
        let out_dir = sf_dir.join("reference");
        std::fs::create_dir_all(&out_dir).expect("create reference dir");
        let specs = TT_QUERIES
            .iter()
            .map(|&q| (Variant::Tt, "tt", q))
            .chain(PGN_QUERIES.iter().map(|&q| (Variant::Pgn, "pgn", q)));
        for (variant, label, q) in specs {
            let spec = query_spec(q, variant);
            let ctx =
                SessionContext::new_with_config(SessionConfig::new().with_target_partitions(1));
            for name in spec.tables {
                let batch = load_tpch_table(&sf_dir, name);
                let table =
                    MemTable::try_new(batch.schema(), vec![vec![batch]]).expect("mem table");
                ctx.register_table(*name, Arc::new(table))
                    .expect("register table");
            }
            let batches = ctx
                .sql(spec.sql)
                .await
                .expect("plan")
                .collect()
                .await
                .expect("run");
            let path = out_dir.join(format!("{label}_q{q}.csv"));
            let mut writer = WriterBuilder::new()
                .with_header(true)
                .build(File::create(&path).expect("create csv"));
            for batch in &batches {
                writer.write(batch).expect("write csv");
            }
            let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
            println!("sf={sf_value} {label} q{q}: {rows} rows");
        }
    }
}
