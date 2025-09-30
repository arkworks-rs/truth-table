#![allow(clippy::needless_borrows_for_generic_args)]

use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    test_utils::bench_prelude,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::prelude::{ParquetReadOptions, SessionContext};
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
    QuerySpec {
        sql: "SELECT c_custkey FROM customer",
        tables: &["customer"],
    },
    // QuerySpec {
    //     sql: "SELECT l_orderkey FROM lineitem WHERE l_quantity >= 20",
    //     tables: &["lineitem"],
    // },
];

#[divan::bench(args = PROVER_BENCH_QUERIES, max_time = 1)]
fn prover_pipeline(spec: QuerySpec) {
    let rt = Runtime::new().expect("tokio runtime");
    rt.block_on(async move {
        let (mut prover, _) = bench_prelude::<F, MvPCS, UvPCS>().expect("bench prelude");
        let ctx = SessionContext::new();

        for &table in spec.tables {
            register_tpch_table(&ctx, table).await;
        }

        let logical_plan = ctx
            .sql(spec.sql)
            .await
            .expect("sql execution")
            .into_unoptimized_plan();

        let proof_tree = ProofTree::<F, MvPCS, UvPCS>::from_logical_plan(&ctx, &logical_plan);
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
