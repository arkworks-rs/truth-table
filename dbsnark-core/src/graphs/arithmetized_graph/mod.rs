pub mod display;

use std::{collections::HashMap, fmt};

use arithmetic::{errors::EncodeError, table::ArithTable};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    prover::Prover,
};

use crate::{
    graphs::witness_graph::WitnessGraph,
    nodes::{ProofPlanNodeId, describe_node_id},
};

/// Arithmetized witness tables indexed by proof-plan node identifier.
pub struct ArithmetizedGraph<F, MvPCS, UvPCS>(
    HashMap<ProofPlanNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>>,
)
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>;

impl<F, MvPCS, UvPCS> fmt::Debug for ArithmetizedGraph<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArithmetizedGraph")
            .field("num_nodes", &self.0.len())
            .field("nodes", &ArithNodesDebug { inner: &self.0 })
            .finish()
    }
}

impl<F, MvPCS, UvPCS> ArithmetizedGraph<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub fn new(
        tables: HashMap<ProofPlanNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>>,
    ) -> Self {
        Self(tables)
    }

    pub fn table_by_node_map(
        self,
    ) -> HashMap<ProofPlanNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn tables_for(
        &self,
        node_id: &ProofPlanNodeId,
    ) -> Option<&HashMap<String, ArithTable<F, MvPCS, UvPCS>>> {
        self.0.get(node_id)
    }

    pub fn table_for(
        &self,
        node_id: &ProofPlanNodeId,
        label: &str,
    ) -> Option<&ArithTable<F, MvPCS, UvPCS>> {
        self.0.get(node_id).and_then(|by_label| by_label.get(label))
    }

    /// Build arithmetized tables for every witness node by consuming a witness
    /// plan.
    #[tracing::instrument(
        name = "arithmetized_plan::from_witness_plan",
        skip(witness_plan, prover)
    )]
    pub fn from_witness_plan(
        witness_plan: WitnessGraph,
        prover: &mut Prover<F, MvPCS, UvPCS>,
    ) -> Result<Self, EncodeError> {
        let mut tables_by_node: HashMap<
            ProofPlanNodeId,
            HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
        > = HashMap::with_capacity(witness_plan.len());

        for (node_id, batches_by_label) in witness_plan.into_iter() {
            let mut arith_tables = HashMap::with_capacity(batches_by_label.len());
            for (label, batches) in batches_by_label {
                let table = ArithTable::<F, MvPCS, UvPCS>::from_record_batches(batches, prover)?;
                arith_tables.insert(label, table);
            }
            tables_by_node.insert(node_id, arith_tables);
        }

        Ok(Self::new(tables_by_node))
    }
}

impl<'a, F, MvPCS, UvPCS> IntoIterator for &'a ArithmetizedGraph<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type Item = (
        &'a ProofPlanNodeId,
        &'a HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
    );
    type IntoIter = std::collections::hash_map::Iter<
        'a,
        ProofPlanNodeId,
        HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<F, MvPCS, UvPCS> IntoIterator for ArithmetizedGraph<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type Item = (
        ProofPlanNodeId,
        HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
    );
    type IntoIter = std::collections::hash_map::IntoIter<
        ProofPlanNodeId,
        HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

struct ArithNodesDebug<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    inner: &'a HashMap<ProofPlanNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>>,
}

impl<'a, F, MvPCS, UvPCS> fmt::Debug for ArithNodesDebug<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (node_id, tables) in self.inner.iter() {
            map.entry(
                &NodeIdDebug { node_id },
                &ArithTablesDebug { inner: tables },
            );
        }
        map.finish()
    }
}

struct NodeIdDebug<'a> {
    node_id: &'a ProofPlanNodeId,
}

impl<'a> fmt::Debug for NodeIdDebug<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&describe_node_id(self.node_id))
    }
}
struct ArithTablesDebug<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    inner: &'a HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
}

impl<'a, F, MvPCS, UvPCS> fmt::Debug for ArithTablesDebug<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        for (label, table) in self.inner.iter() {
            map.entry(label, table);
        }
        map.finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        graphs::arithmetized_graph::display::DisplayableArithmetizedGraph,
        nodes::logical_to_proof_plan,
    };

    use super::*;
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

        let witness_plan = WitnessGraph::from_proof_plan(&ctx, Arc::clone(&proof_plan))
            .await
            .unwrap();
        let arithmetic_plan =
            ArithmetizedGraph::<F, MvPCS, UvPCS>::from_witness_plan(witness_plan, &mut prover)
                .unwrap();
        assert!(!arithmetic_plan.is_empty());

        let graphviz = DisplayableArithmetizedGraph::new(&proof_plan, &arithmetic_plan).graphviz();
        println!("Arithmetized plan graphviz\n{}", graphviz);
    }
}
