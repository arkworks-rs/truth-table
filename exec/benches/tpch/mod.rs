use std::sync::OnceLock;

use divan::Bencher;
use tpch_data::query_spec;

use crate::support::{
    BenchCase, build_verifier_state, ensure_proof, log_proof_size_once, prepare_assets,
    prepare_prover_iteration, run_prover_iteration, run_verifier_once, warmup_proof,
};

fn tpch_cases() -> &'static [BenchCase] {
    // Static list of TPCH queries to benchmark.
    static CASES: OnceLock<&'static [BenchCase]> = OnceLock::new();
    CASES.get_or_init(|| {
        let q1 = query_spec(1);
        let q3 = query_spec(3);
        let q5 = query_spec(5);
        let q8 = query_spec(8);
        let q9 = query_spec(9);
        let q18 = query_spec(18);
        let q19 = query_spec(19);
        ////////////////////////////////////////////////
        let q8_simplified_sql = "    SELECT
    o_orderdate_year
FROM (
    SELECT
        o_orderdate_year,
        l_extendedprice * (1 - l_discount) AS volume
    FROM
        part,
        supplier,
        lineitem,
        orders,
        customer,
        nation n1,
        region
    WHERE
        p_partkey = l_partkey
        AND s_suppkey = l_suppkey
        AND l_orderkey = o_orderkey
        AND o_custkey = c_custkey
        AND c_nationkey = n1.n_nationkey
        AND n1.n_regionkey = r_regionkey
        AND r_name = 'AMERICA'
        AND o_orderdate BETWEEN CAST('1995-01-01' AS date)
        AND CAST('1996-12-31' AS date)
        AND p_type = 'ECONOMY ANODIZED STEEL') AS all_nations";

        let cases = vec![
            BenchCase {
                name: "tpch_q1",
                query: q1.sql,
                tables: q1.tables,
            },
            BenchCase {
                name: "tpch_q3",
                query: q3.sql,
                tables: q3.tables,
            },
            BenchCase {
                name: "tpch_q5",
                query: q5.sql,
                tables: q5.tables,
            },
            BenchCase {
                name: "tpch_q8",
                query: q8_simplified_sql,
                tables: q8.tables,
            },
            BenchCase {
                name: "tpch_q9",
                query: q9.sql,
                tables: q9.tables,
            },
            BenchCase {
                name: "tpch_q18",
                query: q18.sql,
                tables: q18.tables,
            },
            BenchCase {
                name: "tpch_q19_repeat",
                query: q19.sql,
                tables: q19.tables,
            },
        ];
        Box::leak(cases.into_boxed_slice())
    })
}

#[divan::bench(args = tpch_cases(), max_time = 1)]
fn bench_tpch_prover(bencher: Bencher, case: BenchCase) {
    // Prover benchmark: build a new prover per iteration, time only prove().
    bencher
        .with_inputs(|| {
            let assets = prepare_assets(case);
            prepare_prover_iteration(&assets)
        })
        .bench_local_values(|iteration| {
            let _proof = run_prover_iteration(iteration);
        });
}

#[divan::bench(args = tpch_cases(), max_time = 1)]
fn bench_tpch_verifier(bencher: Bencher, case: BenchCase) {
    // Verifier benchmark: require a warm cache, then reuse cached proof bytes.
    bencher
        .with_inputs(|| {
            let assets = prepare_assets(case);
            let _ = warmup_proof(&assets);
            let bench_proof = ensure_proof(&assets);
            log_proof_size_once(case.name, bench_proof.proof_bytes.len());
            build_verifier_state(&assets, bench_proof.proof_bytes.clone())
        })
        .bench_local_values(|state| {
            run_verifier_once(&state);
        });
}
