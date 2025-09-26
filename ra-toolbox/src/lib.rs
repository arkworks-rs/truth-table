use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use planner::{
    arithmetized_plan::ArithmetizedTree,
    ra_proof_plan::{self, ProverNode, ProverNodeNodeId},
};
use std::sync::Arc;

use crate::{expr_piop::dispatch_expr_piop, logical_piop::dispatch_logical_piop};

pub mod expr_piop;
pub mod logical_piop;

pub fn dispatch_piop<F, MvPCS, UvPCS>(
    prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    proof_plan: &Arc<dyn ProverNode>,
    plan: &ArithmetizedTree<F, MvPCS, UvPCS>,
) where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    let ordered = ra_proof_plan::sorted_descendants(Arc::clone(proof_plan));
    for node in ordered {
        match node.node_id() {
            ProverNodeNodeId::LP(_) => dispatch_logical_piop(prover, &node, plan),
            ProverNodeNodeId::Expr(_) => {
                dispatch_expr_piop(prover, &node, plan).expect("expression PIOP dispatch failed")
            },
            ProverNodeNodeId::None => todo!("unknown proof plan node"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_piop::{
        pcs::{kzg10::KZG10, pst13::PST13},
        prover::Prover,
        test_utils::test_prelude,
    };
    use ark_test_curves::bls12_381::{Bls12_381, Fr};
    use datafusion::prelude::{ParquetReadOptions, SessionContext};
    use planner::{ra_proof_plan::logical_to_proof_plan, witness_plan::HintTree};
    use std::sync::Arc;
    use tpch_data::test_data_path;

    type F = Fr;
    type MvPCS = PST13<Bls12_381>;
    type UvPCS = KZG10<Bls12_381>;

    #[tokio::test]
    #[ignore]
    async fn end_to_end_dispatch_piop() {
        let (mut prover, _verifier): (Prover<F, MvPCS, UvPCS>, _) = test_prelude().unwrap();
        let ctx = SessionContext::new();
        let parquet_path = test_data_path("lineitem.parquet");
        assert!(
            parquet_path.exists(),
            "Missing Parquet at {:?}",
            parquet_path
        );

        ctx.register_parquet(
            "lineitem",
            parquet_path.to_str().unwrap(),
            ParquetReadOptions::default(),
        )
        .await
        .unwrap();

        let sql = r#"
            SELECT l_discount FROM lineitem WHERE l_quantity = 2
        "#;
        let df = ctx.sql(sql).await.unwrap();
        let logical = df.into_unoptimized_plan();

        let proof_plan = logical_to_proof_plan(&ctx, &logical);
        let witness_plan = HintTree::from_proof_plan(&ctx, Arc::clone(&proof_plan))
            .await
            .unwrap();
        let arithmetic_plan =
            ArithmetizedTree::from_witness_plan(witness_plan, &mut prover).unwrap();

        dispatch_piop(&mut prover, &proof_plan, &arithmetic_plan);
    }
}
