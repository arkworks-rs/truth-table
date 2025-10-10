#![allow(clippy::needless_borrows_for_generic_args)]

use ark_piop::prover::structs::proof::Proof;
use indexmap::IndexMap;
use std::{
    fs::File,
    hash::Hash,
    io::BufReader,
    sync::{Mutex, OnceLock},
};

use arithmetic::{ctx::SharedCtx, table_oracle::ArithTableOracle};
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    prover::Prover,
    test_utils::bench_prelude,
    verifier::Verifier,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::{
    logical_expr::LogicalPlan,
    prelude::{ParquetReadOptions, SessionContext},
};
use dbsnark_core::prover::trees::{
    arithmetized_tree::ProverArithmetizedTree, hint_tree::ProverHintTree,
    piop_tree::ProverPIOPTree, proof_tree::ProverProofTree, tracked_tree::ProverTrackedTree,
};
use tokio::runtime::Runtime;
type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;
type ProofForBench = Proof<F, MvPCS, UvPCS>;
#[derive(Clone, Copy, Hash, Eq, PartialEq)]
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

impl QuerySpec {
    fn short_label(&self) -> String {
        let mut words = self.sql.split_whitespace();
        let first = words.next().unwrap_or("");
        let last = words.last().unwrap_or(first);
        let tables = if self.tables.is_empty() {
            String::new()
        } else {
            format!(" [{}]", self.tables.join(", "))
        };
        format!("{} ... {}{}", first, last, tables)
    }
}

const PROVER_BENCH_QUERIES: &[QuerySpec] = &[
    // QuerySpec {
    //     sql: "SELECT l_partkey FROM lineitem",
    //     tables: &["lineitem"],
    // },
    // QuerySpec {
    //     sql: "SELECT l_orderkey FROM lineitem where l_linenumber = 3",
    //     tables: &["lineitem"],
    // },
    // QuerySpec {
    //     sql: "SELECT l_partkey FROM lineitem where l_quantity = 8 AND l_linenumber = 3",
    //     tables: &["lineitem"],
    // },
    // QuerySpec {
    //     sql: "SELECT l_partkey FROM lineitem where l_quantity = 8 AND l_linenumber = 3 OR
    // l_extendedprice = 100.1",
    //     tables: &["lineitem"],
    // },
    QuerySpec {
        sql: "SELECT l_partkey FROM lineitem where l_linenumber >= 5",
        tables: &["lineitem"],
    },
    // QuerySpec {
    //     sql: "SELECT count(l_partkey) FROM lineitem GROUP BY l_quantity",
    //     tables: &["lineitem"],
    // },
];

struct CommonInputs {
    runtime: Runtime,
    ctx: SessionContext,
    logical_plan: LogicalPlan,
    prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
}

struct ProverInputs {
    spec: QuerySpec,
    common: CommonInputs,
    prover: Prover<F, MvPCS, UvPCS>,
}

struct VerifierInputs {
    spec: QuerySpec,
    common: CommonInputs,
    verifier: Verifier<F, MvPCS, UvPCS>,
    proof: ProofForBench,
}

fn prepare_common_inputs(spec: QuerySpec) -> CommonInputs {
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
    let table_oracle_file = File::open(&table_oracle_path).expect("open table oracle commitment");
    let mut reader = BufReader::new(table_oracle_file);
    let table_serializable =
        ArithTableOracle::<F, MvPCS, UvPCS>::deserialize_uncompressed(&mut reader)
            .expect("deserialize table oracle");
    let mut table_oracles = IndexMap::new();
    if let Some(schema) = table_serializable.schema() {
        table_oracles.insert(schema, table_serializable);
    }

    let prover_ctx = SharedCtx::new(table_oracles);

    CommonInputs {
        runtime,
        ctx,
        logical_plan,
        prover_ctx,
    }
}

fn build_proof(
    runtime: &Runtime,
    ctx: &SessionContext,
    logical_plan: &LogicalPlan,
    prover_ctx: &SharedCtx<F, MvPCS, UvPCS>,
    prover: &mut Prover<F, MvPCS, UvPCS>,
) -> ProofForBench {
    let proof_tree =
        ProverProofTree::<F, MvPCS, UvPCS>::from_lp(ctx, prover_ctx.clone(), logical_plan);
    let hint_tree = runtime
        .block_on(ProverHintTree::from_proof_tree(ctx, proof_tree.clone()))
        .expect("hint tree");
    let arith_tree = ProverArithmetizedTree::<F, MvPCS, UvPCS>::from_hint_tree(hint_tree)
        .expect("arithmetized tree");
    let tracked_tree =
        ProverTrackedTree::from_arithmetized_tree(arith_tree, prover).expect("tracked tree");
    let mut piop_tree = ProverPIOPTree::from_tracked_plan(tracked_tree, prover);
    let flattened = piop_tree.proof_tree().clone().flatten();
    for node in flattened.values() {
        node.prove_piop(prover, &mut piop_tree).expect("prove piop");
    }
    prover.build_proof().expect("build proof")
}

#[divan::bench(args = PROVER_BENCH_QUERIES, max_time = 60)]
fn prover_pipeline(bencher: divan::Bencher, spec: QuerySpec) {
    bencher
        .with_inputs(move || {
            let common = prepare_common_inputs(spec);
            let (prover, _) = bench_prelude::<F, MvPCS, UvPCS>().expect("bench prelude");

            ProverInputs {
                spec,
                common,
                prover,
            }
        })
        .bench_local_values(|inputs| {
            let ProverInputs {
                spec,
                common,
                mut prover,
            } = inputs;

            let proof = build_proof(
                &common.runtime,
                &common.ctx,
                &common.logical_plan,
                &common.prover_ctx,
                &mut prover,
            );
            let _ = divan::black_box(proof);
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
