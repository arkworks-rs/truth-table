//! Writes every micro table's parquet file (`micro::ensure_parquets`) for the
//! sizes of `MICRO_POWS`, so a bench outside this crate (the zkVM) reads the
//! same rows as the others.

use std::path::Path;

use tt_third_party_bench::micro;

fn main() {
    let bench_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for pow in micro::table_pows() {
        for query in micro::QUERIES.iter().filter(|q| micro::selected(q)) {
            for path in micro::ensure_parquets(bench_root, pow, query, "_preprocessed") {
                println!("{}", path.display());
            }
        }
    }
}
