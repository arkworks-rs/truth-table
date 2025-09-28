use super::PIOPTree;
use crate::trees::{
    arithmetized_tree::ArithmetizedTree, hint_tree::HintTree, proof_tree::ProofTree,
};
use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    prover::Prover,
    test_utils::test_prelude,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::{
    error::Result as DFResult,
    logical_expr::LogicalPlan,
    prelude::{ParquetReadOptions, SessionContext},
};
use tpch_data::test_data_path;

type F = Fr;
type MvPCS = PST13<Bls12_381>;
type UvPCS = KZG10<Bls12_381>;

async fn build_plan(ctx: &SessionContext) -> DFResult<LogicalPlan> {
    let parquet_path = test_data_path("lineitem.parquet");
    assert!(
        parquet_path.exists(),
        "Missing Parquet at {:?}",
        parquet_path
    );

    ctx.register_parquet(
        "lineitem",
        parquet_path
            .to_str()
            .expect("parquet path should be valid UTF-8"),
        ParquetReadOptions::default(),
    )
    .await?;

    let sql = "SELECT l_orderkey FROM lineitem WHERE l_quantity >= 10";
    let df = ctx.sql(sql).await?;
    Ok(df.into_unoptimized_plan())
}

#[tokio::test]
async fn display_graphviz_smoke() -> DFResult<()> {
    let ctx = SessionContext::new();
    let plan = build_plan(&ctx).await?;
    let proof_tree = ProofTree::from_logical_plan(&ctx, &plan);
    let hint_tree = HintTree::from_proof_tree(&ctx, proof_tree).await?;

    let (mut prover, _verifier): (Prover<F, MvPCS, UvPCS>, _) = test_prelude().unwrap();
    let arith_tree = ArithmetizedTree::from_hint_tree(hint_tree, &mut prover).unwrap();
    let piop_plan = PIOPTree::from_arithmetized_plan(arith_tree);

    let dot = format!("{}", piop_plan.display_graphviz());
    assert!(dot.contains("digraph PIOPTree"));
    Ok(())
}
