#![allow(clippy::needless_borrows_for_generic_args)]

use std::{collections::HashMap, fs::File, hash::Hash, io::BufReader};

use arithmetic::{ctx::ProverCtx, table_oracle::ArithTableOracle};
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    prover::Prover,
    test_utils::bench_prelude,
};
use ark_serialize::CanonicalDeserialize;
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::{
    logical_expr::LogicalPlan,
    prelude::{ParquetReadOptions, SessionContext},
};
use dbsnark_core::prover_trees::{
    arithmetized_tree::ProverArithmetizedTree, hint_tree::ProverHintTree,
    piop_tree::ProverPIOPTree, proof_tree::ProverProofTree, tracked_tree::ProverTrackedTree,
};
use tokio::runtime::Runtime;
type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;

#[derive(Clone, Copy)]
struct QuerySpec {
    sql: &'static str,
    tables: &'static [&'static str],
}

impl std::fmt::Display for QuerySpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.tables.is_empty() {
            write!(f, "{}", self.sql)
        } else {
            write!(f, "{} [{}]", self.sql, self.tables.join(", "))
        }
    }
}

const PROVER_BENCH_QUERIES: &[QuerySpec] = &[
    QuerySpec {
        sql: "SELECT l_partkey FROM lineitem",
        tables: &["lineitem"],
    },
    QuerySpec {
        sql: "SELECT l_orderkey FROM lineitem where l_linenumber = 3",
        tables: &["lineitem"],
    },
    QuerySpec {
        sql: "SELECT l_partkey FROM lineitem where l_quantity = 8 AND l_linenumber = 3",
        tables: &["lineitem"],
    },
    QuerySpec {
        sql: "SELECT l_partkey FROM lineitem where l_quantity = 8 AND l_linenumber = 3 OR
    l_extendedprice = 100.1",
        tables: &["lineitem"],
    },
];

struct BenchInputs {
    runtime: Runtime,
    ctx: SessionContext,
    logical_plan: LogicalPlan,
    prover_ctx: ProverCtx<F, MvPCS, UvPCS>,
    prover: Prover<F, MvPCS, UvPCS>,
}

#[divan::bench(args = PROVER_BENCH_QUERIES, max_time = 60)]
fn prover_pipeline(bencher: divan::Bencher, spec: QuerySpec) {
    bencher
        .with_inputs(move || {
            let runtime = Runtime::new().expect("tokio runtime");
            let ctx = SessionContext::new();

            runtime.block_on(async {
                for &table in spec.tables {
                    register_tpch_table(&ctx, table).await;
                }
            });

            let logical_plan = runtime.block_on(async {
                ctx.sql(spec.sql)
                    .await
                    .expect("sql execution")
                    .into_unoptimized_plan()
            });

            let table_oracle_path = tpch_data::bench_data_path(spec.tables.join("_") + ".oracle");
            let table_oracle_file =
                File::open(&table_oracle_path).expect("open table oracle commitment");
            let mut reader = BufReader::new(table_oracle_file);
            let table_serializable =
                ArithTableOracle::<F, MvPCS, UvPCS>::deserialize_uncompressed(&mut reader)
                    .expect("deserialize table oracle");
            let mut table_oracles = HashMap::new();
            if let Some(schema) = table_serializable.schema() {
                table_oracles.insert(schema, table_serializable);
            }

            let prover_ctx = ProverCtx::new(table_oracles);
            let (prover, _) = bench_prelude::<F, MvPCS, UvPCS>().expect("bench prelude");

            BenchInputs {
                runtime,
                ctx,
                logical_plan,
                prover_ctx,
                prover,
            }
        })
        .bench_local_values(|inputs| {
            let BenchInputs {
                runtime,
                ctx,
                logical_plan,
                prover_ctx,
                prover,
            } = inputs;

            runtime.block_on(async move {
                let mut prover = prover;
                let proof_tree =
                    ProverProofTree::<F, MvPCS, UvPCS>::from_lp(&ctx, prover_ctx, &logical_plan);
                let hint_tree = ProverHintTree::from_proof_tree(&ctx, proof_tree.clone())
                    .await
                    .expect("hint tree");
                let arith_tree =
                    ProverArithmetizedTree::<F, MvPCS, UvPCS>::from_hint_tree(hint_tree)
                        .expect("arithmetized tree");
                let tracked_tree =
                    ProverTrackedTree::from_arithmetized_tree(arith_tree, &mut prover)
                        .expect("tracked tree");
                let mut piop_tree = ProverPIOPTree::from_tracked_plan(tracked_tree, &mut prover);

                let flattened = piop_tree.proof_tree().clone().flatten();
                for node in flattened.values() {
                    node.prove_piop(&mut prover, &mut piop_tree)
                        .expect("prove piop");
                }
                let proof = prover.build_proof();
                let _ = divan::black_box(proof);
            });
        });
}

async fn register_tpch_table(ctx: &SessionContext, table: &str) {
    let parquet_path = tpch_data::bench_data_path(format!("{table}.parquet"));
    assert!(
        parquet_path.exists(),
        "missing bench parquet {}",
        parquet_path.display()
    );
    ctx.register_parquet(
        table,
        parquet_path
            .to_str()
            .expect("parquet path should be valid UTF-8"),
        ParquetReadOptions::default(),
    )
    .await
    .expect("register parquet");
}

fn main() {
    divan::main();
}
