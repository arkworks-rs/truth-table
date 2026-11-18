//! Poneglyph (halo2 with KZG on BN254) on the micro queries. Poneglyph has no
//! SQL front end; the fork's `sql::micro_kzg` writes each query as a circuit
//! from Poneglyph's gadgets and its TPC-H circuits' gate patterns, in two
//! variants: `faithful` enables selectors from the data as those circuits do,
//! so the verifying key depends on the data, and leaves the tables unbound;
//! `fixed` keeps every selector on a range fixed by the table size, and binds
//! the proof to the data owner's commitments to the tables (timed as
//! `commit_ms`). Only `fixed` runs unless PONEGLYPH_FAITHFUL=1. A table of 2^p rows needs a circuit of
//! 2^(p+1) rows: the output and the halo2 blinding rows sit beside the input.

use std::path::Path;

use poneglyph::poneglyph_bench::{micro_supported, run_micro, setup_params};
use tt_third_party_bench::micro;

/// The data-independent circuits; PONEGLYPH_FAITHFUL=1 adds the faithful ones.
fn variants() -> Vec<(&'static str, bool)> {
    let mut variants = vec![("fixed", true)];
    if std::env::var("PONEGLYPH_FAITHFUL").is_ok_and(|v| v == "1") {
        variants.insert(0, ("faithful", false));
    }
    variants
}

fn main() {
    let bench_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let pows = micro::table_pows();
    println!("table_sizes: {pows:?}");
    for pow in pows {
        let rows = 1usize << pow;
        // The KZG parameters for the degree every query of this size uses.
        let setup_ms = setup_params(pow + 1).as_secs_f64() * 1e3;
        for query in micro::QUERIES.iter().filter(|q| micro::selected(q)) {
            let tables: Vec<Vec<Vec<u64>>> = query
                .tables
                .iter()
                .map(|name| {
                    let columns = micro::table(name, rows);
                    (0..rows)
                        .map(|r| columns.iter().map(|(_, c)| c[r] as u64).collect())
                        .collect()
                })
                .collect();
            let dir = micro::query_dir(bench_root, pow, query);
            std::fs::create_dir_all(&dir).expect("create micro dir");
            for (variant, fixed) in variants() {
                if !micro_supported(query.name, fixed) {
                    continue;
                }
                let proof = dir.join(format!("poneglyph_{variant}.proof"));
                println!("pow: {pow} query: {} variant: {variant}", query.name);
                let result = run_micro(
                    query.name,
                    fixed,
                    pow + 1,
                    &tables,
                    proof.to_str().expect("utf-8 path"),
                );
                assert!(
                    result.bench.verified,
                    "{} ({variant}) at 2^{pow} did not verify",
                    query.name
                );
                let keygen_s = result.bench.vk_time_s + result.bench.pk_time_s;
                println!("setup_ms: {setup_ms:.3}");
                println!("params_bytes: {}", result.bench.params_bytes);
                println!("keygen_ms: {:.3}", keygen_s * 1e3);
                println!("pk_bytes: {}", result.bench.pk_bytes);
                println!("vk_bytes: {}", result.bench.vk_bytes);
                if let Some((elapsed, bytes)) = result.commit {
                    println!("commit_ms: {:.3}", elapsed.as_secs_f64() * 1e3);
                    println!("commitment_bytes: {bytes}");
                }
                println!("prove_ms: {:.3}", result.bench.prove_time_s * 1e3);
                println!("proof_bytes: {}", result.bench.proof_size_bytes);
                println!("verify_ms: {:.3}", result.bench.verify_time_s * 1e3);
                println!("public_inputs: {}", result.public_inputs);
                println!("----------------------------------------");
            }
        }
    }
}
