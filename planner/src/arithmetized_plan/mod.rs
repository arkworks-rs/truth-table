use std::{collections::HashMap, sync::Arc};

use arithmetic::{errors::EncodeError, table::ArithTable};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    prover::Prover,
};
use datafusion::{
    error::{DataFusionError, Result as DFResult},
    prelude::SessionContext,
};

use crate::{
    ra_proof_plan::ProofPlan,
    witness_plan::{self, WitnessNode},
};

/// Arithmetized node mirrors the proof-plan tree while storing arithmetized
/// tables for each witness label.
pub struct ArithmetizedNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub node: Arc<dyn ProofPlan>,
    pub tables: HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
    pub children: Vec<ArithmetizedNode<F, MvPCS, UvPCS>>,
}

/// Build an arithmetized tree by first materializing witnesses (record batches)
/// and then arithmetizing each batch collection into an `ArithTable`.
#[tracing::instrument(name = "witness_to_arithmetic_plan", skip(witness_plan, prover))]
pub fn witness_to_arithmetic_plan<F, MvPCS, UvPCS>(
    witness_plan: WitnessNode,
    prover: &mut Prover<F, MvPCS, UvPCS>,
) -> DFResult<ArithmetizedNode<F, MvPCS, UvPCS>>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    arithmetize_node::<F, MvPCS, UvPCS>(witness_plan, prover)
        .map_err(|e| DataFusionError::Execution(e.to_string()))
}

fn arithmetize_node<F, MvPCS, UvPCS>(
    witness: WitnessNode,
    prover: &mut Prover<F, MvPCS, UvPCS>,
) -> Result<ArithmetizedNode<F, MvPCS, UvPCS>, EncodeError>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    let tables = witness
        .results
        .into_iter()
        .map(|(label, batches)| {
            let table = ArithTable::<F, MvPCS, UvPCS>::from_record_batches(batches, prover)?;
            Ok::<_, EncodeError>((label, table))
        })
        .collect::<Result<HashMap<_, _>, _>>()?;

    let children = witness
        .children
        .into_iter()
        .map(|child| arithmetize_node::<F, MvPCS, UvPCS>(child, prover))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ArithmetizedNode {
        node: witness.node,
        tables,
        children,
    })
}

/// Append descendants in post-order (children first, then parent).
pub fn append_sorted_descendants<'a, F, MvPCS, UvPCS>(
    node: &'a ArithmetizedNode<F, MvPCS, UvPCS>,
    out: &mut Vec<&'a ArithmetizedNode<F, MvPCS, UvPCS>>,
) where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    for child in &node.children {
        append_sorted_descendants(child, out);
    }
    out.push(node);
}

/// Return all descendants including root in post-order traversal order.
pub fn sorted_descendants<'a, F, MvPCS, UvPCS>(
    root: &'a ArithmetizedNode<F, MvPCS, UvPCS>,
) -> Vec<&'a ArithmetizedNode<F, MvPCS, UvPCS>>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    let mut v = Vec::new();
    append_sorted_descendants(root, &mut v);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ra_proof_plan::logical_to_proof_plan,
        witness_plan::{self},
    };
    use ark_piop::{
        pcs::{kzg10::KZG10, pst13::PST13},
        prover::Prover,
        test_utils::test_prelude,
    };
    use ark_test_curves::bls12_381::{Bls12_381, Fr};
    use datafusion::prelude::{ParquetReadOptions, SessionContext};
    use std::sync::Arc;
    use tpch_data::test_data_path;

    type F = Fr;
    type MvPCS = PST13<Bls12_381>;
    type UvPCS = KZG10<Bls12_381>;

    #[tokio::test]
    async fn logical_plan_to_arithmetized_plan() {
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

        let witness_plan = witness_plan::proof_to_witness_plan(&ctx, Arc::clone(&proof_plan))
            .await
            .unwrap();
        let arithmetic_plan =
            witness_to_arithmetic_plan::<F, MvPCS, UvPCS>(witness_plan, &mut prover).unwrap();
        let nodes = sorted_descendants(&arithmetic_plan);
        assert!(!nodes.is_empty());
    }
}
