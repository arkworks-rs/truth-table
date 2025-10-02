#![allow(clippy::needless_borrows_for_generic_args)]

use std::{collections::HashMap, fs::File, io::BufReader};

use arithmetic::{ctx::ProverCtx, table_oracle::SerializableArithTableOracle};
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
use dbsnark_core::trees::{
    arithmetized_tree::ArithmetizedTree, hint_tree::HintTree, piop_tree::PIOPTree,
    proof_tree::ProofTree,
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
    // QuerySpec {
    //     sql: "SELECT c_custkey FROM customer",
    //     tables: &["customer"],
    // },
    QuerySpec {
        sql: "SELECT c_custkey FROM customer where c_nationkey = 15",
        tables: &["customer"],
    },
    // QuerySpec {
    //     sql: "SELECT l_orderkey FROM lineitem WHERE l_quantity >= 20",
    //     tables: &["lineitem"],
    // },
];

struct BenchInputs {
    runtime: Runtime,
    ctx: SessionContext,
    logical_plan: LogicalPlan,
    prover_ctx: ProverCtx<F, MvPCS, UvPCS>,
    prover: Prover<F, MvPCS, UvPCS>,
}

#[divan::bench(args = PROVER_BENCH_QUERIES, max_time = 10)]
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

            let customer_oracle_path = tpch_data::bench_data_path("customer.oracle");
            let customer_oracle_file =
                File::open(&customer_oracle_path).expect("open customer oracle commitment");
            let mut reader = BufReader::new(customer_oracle_file);
            let customer_serializable =
                SerializableArithTableOracle::<F, MvPCS, UvPCS>::deserialize_uncompressed(
                    &mut reader,
                )
                .expect("deserialize customer oracle");

            let mut table_oracles = HashMap::new();
            if let Some(schema) = customer_serializable.schema() {
                table_oracles.insert(schema, customer_serializable);
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
                    ProofTree::<F, MvPCS, UvPCS>::from_lp(&ctx, prover_ctx, &logical_plan);
                let hint_tree = HintTree::from_proof_tree(&ctx, proof_tree.clone())
                    .await
                    .expect("hint tree");
                let arith_tree =
                    ArithmetizedTree::<F, MvPCS, UvPCS>::from_hint_tree(hint_tree, &mut prover)
                        .expect("arithmetized tree");
                let mut piop_tree = PIOPTree::from_arithmetized_plan(arith_tree, &mut prover);

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
