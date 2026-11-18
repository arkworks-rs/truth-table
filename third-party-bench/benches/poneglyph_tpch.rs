//! Poneglyph's data-independent TPC-H circuits (the fork's `sql::fixed_tpch`
//! and `sql::q1_fixed_kzg`) on the `_pgn` queries over the `_poneglyph`
//! tables: every selector covers a range fixed by the table sizes, and the
//! proof is bound to the data owner's commitments to the tables it reads
//! (timed as `commit_ms`). Before proving, each circuit's claimed result is
//! checked against DataFusion's (`tpch_reference`) as a multiset; the circuit
//! proves the order.
//!
//! PGN_SFS (comma-separated, default 0.01,0.02,0.04) and PGN_QUERIES
//! (default 1,3,5,8,9,18) narrow the sweep.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::Duration,
};

use chrono::NaiveDate;
use datafusion::arrow::{
    array::{AsArray, RecordBatch},
    compute::cast,
    datatypes::{DataType, Date32Type, Int64Type},
};
use poneglyph::poneglyph_bench::{
    Fp, MicroResult, Q1Circuit,
    fixed::{self, Col},
    run_fixed_q1, setup_params,
};
use tt_third_party_bench::baseline::{ensure_tpch_data, load_tpch_table};

fn list<T: std::str::FromStr>(var: &str, default: &str) -> Vec<T> {
    std::env::var(var)
        .unwrap_or_else(|_| default.into())
        .split(',')
        .map(|s| {
            s.trim()
                .parse()
                .unwrap_or_else(|_| panic!("bad {var} entry {s}"))
        })
        .collect()
}

/// The `_poneglyph` tables of one scale factor, loaded on first use.
struct Tables {
    dir: PathBuf,
    loaded: HashMap<&'static str, RecordBatch>,
}

impl Tables {
    fn col(&mut self, table: &'static str, name: &str) -> Col {
        let dir = &self.dir;
        let batch = self
            .loaded
            .entry(table)
            .or_insert_with(|| load_tpch_table(dir, &format!("{table}_poneglyph")));
        let array = batch
            .column_by_name(name)
            .unwrap_or_else(|| panic!("{table} has no column {name}"));
        match array.data_type() {
            DataType::Utf8 | DataType::Utf8View | DataType::LargeUtf8 => {
                let strings = cast(array, &DataType::Utf8).expect("cast to utf-8");
                Col::Str(
                    strings
                        .as_string::<i32>()
                        .iter()
                        .map(|s| s.expect("no NULLs").to_string())
                        .collect(),
                )
            }
            DataType::Date32 => Col::Int(
                array
                    .as_primitive::<Date32Type>()
                    .values()
                    .iter()
                    .map(|&d| d as i64)
                    .collect(),
            ),
            _ => {
                let ints = cast(array, &DataType::Int64).expect("cast to int64");
                Col::Int(ints.as_primitive::<Int64Type>().values().to_vec())
            }
        }
    }

    fn cols<const N: usize>(&mut self, table: &'static str, names: [&str; N]) -> [Col; N] {
        names.map(|name| self.col(table, name))
    }
}

/// A reference CSV as the circuits encode values: integers as they are,
/// dates as days since 1970-01-01, strings by `fixed::string`.
fn reference(sf_dir: &Path, q: u8) -> Vec<Vec<i128>> {
    let path = sf_dir.join("reference").join(format!("pgn_q{q}.csv"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}; run the tpch_reference bin", path.display()));
    let epoch = NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();
    text.lines()
        .skip(1)
        .map(|line| {
            line.split(',')
                .map(|v| {
                    v.parse::<i128>().unwrap_or_else(|_| {
                        match NaiveDate::parse_from_str(v, "%Y-%m-%d") {
                            Ok(d) => (d - epoch).num_days() as i128,
                            Err(_) => fixed::string(v),
                        }
                    })
                })
                .collect()
        })
        .collect()
}

/// Proves query `q`, after `setup(k)` for the degree `k` it needs; returns
/// `k` and the result.
fn prove(q: u8, t: &mut Tables, proof: &str, setup: &mut impl FnMut(u32)) -> (u32, MicroResult) {
    // Each query's claimed result and, per reference column, the result
    // column it is.
    let expected = reference(&t.dir, q);
    let check = |result: Vec<Vec<i128>>, columns: &[usize]| {
        let mut ours: Vec<Vec<i128>> = result
            .iter()
            .map(|r| columns.iter().map(|&c| r[c]).collect())
            .collect();
        let mut theirs = expected.clone();
        ours.sort();
        theirs.sort();
        assert_eq!(
            ours, theirs,
            "Q{q}: the circuit's result is not DataFusion's"
        );
    };
    match q {
        1 => {
            let [qty, price, disc, tax, flag, date] = t.cols(
                "lineitem",
                [
                    "l_quantity",
                    "l_extendedprice",
                    "l_discount",
                    "l_tax",
                    "l_returnflag",
                    "l_shipdate",
                ],
            );
            let ints = |c: &Col| match c {
                Col::Int(v) => v.iter().map(|&x| x as u64).collect::<Vec<_>>(),
                Col::Str(v) => v.iter().map(|s| s.as_bytes()[0] as u64).collect(),
            };
            let cols = [&qty, &price, &disc, &tax, &flag, &date].map(ints);
            let rows: Vec<[u64; 6]> = (0..qty.len())
                .map(|r| cols.each_ref().map(|c| c[r]))
                .collect();
            let circuit = Q1Circuit::<Fp>::new(rows.clone());
            check(
                circuit.result().iter().map(|r| r.to_vec()).collect(),
                &[0, 1, 2, 3, 4, 5],
            );
            let k = fixed::degree(rows.len());
            setup(k);
            (k, run_fixed_q1(k, rows, proof))
        }
        3 => {
            let tables = fixed::Q3Tables {
                customer: t.cols("customer", ["c_custkey", "c_mktsegment"]),
                orders: t.cols(
                    "orders",
                    ["o_orderkey", "o_custkey", "o_orderdate", "o_shippriority"],
                ),
                lineitem: t.cols(
                    "lineitem",
                    ["l_orderkey", "l_extendedprice", "l_discount", "l_shipdate"],
                ),
            };
            let circuit = fixed::Q3Circuit::<Fp>::new(&tables);
            check(circuit.result(), &[0, 3, 1, 2]);
            let k = fixed::degree(circuit.rows());
            setup(k);
            (k, fixed::run_q3(k, &tables, proof))
        }
        5 => {
            let tables = fixed::Q5Tables {
                customer: t.cols("customer", ["c_custkey", "c_nationkey"]),
                orders: t.cols("orders", ["o_orderkey", "o_custkey", "o_orderdate"]),
                lineitem: t.cols(
                    "lineitem",
                    ["l_orderkey", "l_suppkey", "l_extendedprice", "l_discount"],
                ),
                supplier: t.cols("supplier", ["s_suppkey", "s_nationkey"]),
                nation: t.cols("nation", ["n_nationkey", "n_name", "n_regionkey"]),
                region: t.cols("region", ["r_regionkey", "r_name"]),
            };
            let circuit = fixed::Q5Circuit::<Fp>::new(&tables);
            check(circuit.result(), &[0, 1]);
            let k = fixed::degree(circuit.rows());
            setup(k);
            (k, fixed::run_q5(k, &tables, proof))
        }
        8 => {
            let tables = fixed::Q8Tables {
                part: t.cols("part", ["p_partkey", "p_type"]),
                supplier: t.cols("supplier", ["s_suppkey", "s_nationkey"]),
                lineitem: t.cols(
                    "lineitem",
                    [
                        "l_orderkey",
                        "l_partkey",
                        "l_suppkey",
                        "l_extendedprice",
                        "l_discount",
                    ],
                ),
                orders: t.cols(
                    "orders",
                    ["o_orderkey", "o_custkey", "o_orderdate", "o_orderdate_year"],
                ),
                customer: t.cols("customer", ["c_custkey", "c_nationkey"]),
                nation: t.cols("nation", ["n_nationkey", "n_name", "n_regionkey"]),
                region: t.cols("region", ["r_regionkey", "r_name"]),
            };
            let circuit = fixed::Q8Circuit::<Fp>::new(&tables);
            check(circuit.result(), &[0, 1, 2]);
            let k = fixed::degree(circuit.rows());
            setup(k);
            (k, fixed::run_q8(k, &tables, proof))
        }
        9 => {
            let tables = fixed::Q9Tables {
                part: t.cols("part", ["p_partkey"]),
                supplier: t.cols("supplier", ["s_suppkey", "s_nationkey"]),
                lineitem: t.cols(
                    "lineitem",
                    [
                        "l_orderkey",
                        "l_partkey",
                        "l_suppkey",
                        "l_quantity",
                        "l_extendedprice",
                        "l_discount",
                    ],
                ),
                partsupp: t.cols("partsupp", ["ps_partkey", "ps_suppkey", "ps_supplycost"]),
                orders: t.cols("orders", ["o_orderkey", "o_orderdate_year"]),
                nation: t.cols("nation", ["n_nationkey", "n_name"]),
            };
            let circuit = fixed::Q9Circuit::<Fp>::new(&tables);
            check(circuit.result(), &[1, 2, 3]);
            let k = fixed::degree(circuit.rows());
            setup(k);
            (k, fixed::run_q9(k, &tables, proof))
        }
        18 => {
            let tables = fixed::Q18Tables {
                customer: t.cols("customer", ["c_custkey", "c_name"]),
                orders: t.cols(
                    "orders",
                    ["o_orderkey", "o_custkey", "o_orderdate", "o_totalprice"],
                ),
                lineitem: t.cols("lineitem", ["l_orderkey", "l_quantity"]),
            };
            let circuit = fixed::Q18Circuit::<Fp>::new(&tables);
            check(circuit.result(), &[4, 1, 0, 2, 3, 5]);
            let k = fixed::degree(circuit.rows());
            setup(k);
            (k, fixed::run_q18(k, &tables, proof))
        }
        _ => panic!("no data-independent circuit for Q{q}"),
    }
}

fn main() {
    let bench_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sfs: Vec<f64> = list("PGN_SFS", "0.01,0.02,0.04");
    let queries: Vec<u8> = list("PGN_QUERIES", "1,3,5,8,9,18");
    println!("scale_factors: {sfs:?}");
    let mut setups: HashMap<u32, Duration> = HashMap::new();
    for sf in sfs {
        let sf_dir = bench_root
            .join("artifact")
            .join("tpch")
            .join(format!("sf_{sf}"));
        ensure_tpch_data(&sf_dir, sf);
        let out = sf_dir.join("poneglyph");
        std::fs::create_dir_all(&out).expect("create proof dir");
        let mut tables = Tables {
            dir: sf_dir,
            loaded: HashMap::new(),
        };
        for &q in &queries {
            let proof = out.join(format!("fixed_q{q}.proof"));
            println!("sf: {sf} query: q{q} variant: fixed");
            // The KZG parameters for each degree are generated, and timed, once.
            let (k, result) = prove(
                q,
                &mut tables,
                proof.to_str().expect("utf-8 path"),
                &mut |k| {
                    setups.entry(k).or_insert_with(|| setup_params(k));
                },
            );
            let setup = setups[&k];
            assert!(result.bench.verified, "Q{q} at SF {sf} did not verify");
            let keygen_s = result.bench.vk_time_s + result.bench.pk_time_s;
            println!("k: {k}");
            println!("setup_ms: {:.3}", setup.as_secs_f64() * 1e3);
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
