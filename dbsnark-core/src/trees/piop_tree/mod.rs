pub mod display;

use std::{collections::HashMap, fmt};

use arithmetic::table::ArithTable;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};

use crate::{
    trees::arithmetized_tree::ArithmetizedTree,
    nodes::{ProverNodeNodeId, describe_node_id},
};

/// Virtualized tables indexed by proof-plan node identifier.
pub struct PIOPPlan<F, MvPCS, UvPCS>(
    HashMap<ProverNodeNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>>,
)
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>;

impl<F, MvPCS, UvPCS> fmt::Debug for PIOPPlan<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PIOPPlan")
            .field("num_nodes", &self.0.len())
            .field("nodes", &VirtualNodesDebug { inner: &self.0 })
            .finish()
    }
}

impl<F, MvPCS, UvPCS> PIOPPlan<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub fn new(
        tables: HashMap<ProverNodeNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>>,
    ) -> Self {
        Self(tables)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn tables_for(
        &self,
        node_id: &ProverNodeNodeId,
    ) -> Option<&HashMap<String, ArithTable<F, MvPCS, UvPCS>>> {
        self.0.get(node_id)
    }

    pub fn table_for(
        &self,
        node_id: &ProverNodeNodeId,
        label: &str,
    ) -> Option<&ArithTable<F, MvPCS, UvPCS>> {
        self.0.get(node_id).and_then(|by_label| by_label.get(label))
    }

    /// Build a virtualized plan from an arithmetized plan.
    pub fn from_arithmetized_plan(arith_plan: ArithmetizedTree<F, MvPCS, UvPCS>) -> Self {
        let mut tables_by_node = arith_plan.table_by_node_map();

        for (node_id, tables_by_label) in tables_by_node.iter_mut() {
           todo!() 
        }

        Self::new(tables_by_node)
    }
}

impl<'a, F, MvPCS, UvPCS> IntoIterator for &'a PIOPPlan<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type Item = (
        &'a ProverNodeNodeId,
        &'a HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
    );
    type IntoIter = std::collections::hash_map::Iter<
        'a,
        ProverNodeNodeId,
        HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<F, MvPCS, UvPCS> IntoIterator for PIOPPlan<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type Item = (
        ProverNodeNodeId,
        HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
    );
    type IntoIter = std::collections::hash_map::IntoIter<
        ProverNodeNodeId,
        HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

struct VirtualNodesDebug<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    inner: &'a HashMap<ProverNodeNodeId, HashMap<String, ArithTable<F, MvPCS, UvPCS>>>,
}

impl<'a, F, MvPCS, UvPCS> fmt::Debug for VirtualNodesDebug<'a, F, MvPCS, UvPCS>
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
                &VirtualTablesDebug { inner: tables },
            );
        }
        map.finish()
    }
}

struct NodeIdDebug<'a> {
    node_id: &'a ProverNodeNodeId,
}

impl<'a> fmt::Debug for NodeIdDebug<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&describe_node_id(self.node_id))
    }
}

struct VirtualTablesDebug<'a, F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    inner: &'a HashMap<String, ArithTable<F, MvPCS, UvPCS>>,
}

impl<'a, F, MvPCS, UvPCS> fmt::Debug for VirtualTablesDebug<'a, F, MvPCS, UvPCS>
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
        trees::hint_tree::HintTree,
        plans::piop_plan::display::DisplayablePIOPPlan,
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
    async fn logical_plan_to_virtualized_plan() {
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
            ArithmetizedTree::<F, MvPCS, UvPCS>::from_witness_plan(witness_plan, &mut prover)
                .unwrap();
        let virtual_plan = PIOPPlan::<F, MvPCS, UvPCS>::from_arithmetized_plan(arithmetic_plan);
        assert!(!virtual_plan.is_empty());

        let treeviz = DisplayablePIOPPlan::new(&proof_plan, &virtual_plan).treeviz();
        println!("Virtualized plan treeviz\n{}", treeviz);
    }
}
