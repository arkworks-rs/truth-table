use crate::{
    proof_nodes::{id::NodeId, lps::verifier::VerifierTableScanNode, verifier::VerifierNode},
    verifier::trees::proof_tree::VerifierProofTree,
};
use arithmetic::{ctx::SharedCtx, table_oracle::TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    verifier::Verifier,
};
use datafusion::{
    arrow::datatypes::{FieldRef, Schema},
    common::DFSchemaRef,
};
use indexmap::IndexMap;
use std::{fmt, sync::Arc};
use tracing::instrument;

mod display;
#[cfg(test)]
mod tests;

pub struct VerifierTrackedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    arena: IndexMap<NodeId, IndexMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>,
    inner_proof_tree: VerifierProofTree<F, MvPCS, UvPCS>,
}

impl<F, MvPCS, UvPCS> fmt::Debug for VerifierTrackedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifierTrackedTree")
            .field("num_nodes", &self.arena.len())
            .finish()
    }
}

impl<F, MvPCS, UvPCS> VerifierTrackedTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub fn new(
        proof_tree: VerifierProofTree<F, MvPCS, UvPCS>,
        arena: IndexMap<NodeId, IndexMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>,
    ) -> Self {
        Self {
            arena,
            inner_proof_tree: proof_tree,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        VerifierProofTree<F, MvPCS, UvPCS>,
        IndexMap<NodeId, IndexMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>,
    ) {
        let VerifierTrackedTree {
            arena,
            inner_proof_tree,
        } = self;
        (inner_proof_tree, arena)
    }

    pub fn table_by_node_map(
        self,
    ) -> IndexMap<NodeId, IndexMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>> {
        let (_, tables) = self.into_parts();
        tables
    }

    pub fn len(&self) -> usize {
        self.arena.len()
    }

    pub fn is_empty(&self) -> bool {
        self.arena.is_empty()
    }

    pub fn tables_for(
        &self,
        node_id: &NodeId,
    ) -> Option<&IndexMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>> {
        self.arena.get(node_id)
    }

    pub fn table_for(
        &self,
        node_id: &NodeId,
        label: &str,
    ) -> Option<&TrackedTableOracle<F, MvPCS, UvPCS>> {
        self.arena
            .get(node_id)
            .and_then(|by_label| by_label.get(label))
    }

    pub fn proof_tree(&self) -> &VerifierProofTree<F, MvPCS, UvPCS> {
        &self.inner_proof_tree
    }

    pub fn display_graphviz(&self) -> display::DisplayableVerifierTrackedTree<'_, F, MvPCS, UvPCS> {
        display::DisplayableVerifierTrackedTree::new(self)
    }

    #[instrument(level = "debug", skip_all)]
    pub fn from_proof_tree(
        proof_tree: VerifierProofTree<F, MvPCS, UvPCS>,
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
    ) -> VerifierTrackedTree<F, MvPCS, UvPCS> {
        let shared_ctx = proof_tree.ctx();

        let ordered_nodes: Vec<_> = proof_tree.arena().values().cloned().collect();

        let mut ordered_infos: Vec<(NodeId, bool, IndexMap<String, DFSchemaRef>)> =
            Vec::with_capacity(ordered_nodes.len());

        for node in &ordered_nodes {
            let node_id = node.node_id();
            let is_table_scan = node
                .as_any()
                .downcast_ref::<VerifierTableScanNode>()
                .is_some();
            let schema_map: IndexMap<String, DFSchemaRef> = node
                .hint_generation_plans(&proof_tree)
                .into_iter()
                .filter_map(|(label, hint_plan)| {
                    hint_plan
                        .project_materialized()
                        .map(|plan| (label, Arc::clone(plan.schema())))
                })
                .collect();
            ordered_infos.push((node_id, is_table_scan, schema_map));
        }

        let mut tables_by_node: IndexMap<
            NodeId,
            IndexMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>,
        > = IndexMap::with_capacity(ordered_infos.len());
        // At this point, we have the nodes in an order synced with the prover
        for (node_id, is_table_scan, schema_map) in ordered_infos {
            let mut tables_for_node = IndexMap::with_capacity(schema_map.len());

            for (label, df_schema) in schema_map {

                let arrow_schema_ref = Arc::clone(df_schema.inner());
                let schema_owned = Some(arrow_schema_ref.as_ref().clone());

                let mut columns: IndexMap<FieldRef, _> =
                    IndexMap::with_capacity(arrow_schema_ref.fields().len());
                let mut log_size: Option<usize> = None;

                if is_table_scan {
                    let schema_ref = arrow_schema_ref.as_ref();
                    let base_oracle = shared_ctx.table_oracle(schema_ref).unwrap_or_else(|| {
                        panic!("missing table oracle for schema {schema_ref:?}")
                    });
                    log_size = Some(base_oracle.log_size());
                    for field_ref in arrow_schema_ref.fields().iter() {

                        let field_ref = field_ref.clone();
                        let commitment = base_oracle
                            .comitments()
                            .get(&field_ref)
                            .unwrap_or_else(|| {
                                panic!(
                                    "missing commitment for field {} in table scan node {}",
                                    field_ref.name(),
                                    node_id
                                )
                            })
                            .clone();
                        let tracked = verifier
                            .track_mat_mv_com(commitment)
                            .expect("failed to track table scan commitment");
                        columns.insert(field_ref, tracked);
                    }
                } else {
                    for field_ref in arrow_schema_ref.fields().iter() {

                        let field_ref = field_ref.clone();
                        let expected_id = verifier.peek_next_id();
                        let tracked = verifier
                            .track_mv_com_by_id(expected_id)
                            .expect("failed to track prover commitment by id");
                        let num_vars = verifier
                            .commitment_num_vars(expected_id)
                            .expect("missing commitment arity");
                        match log_size {
                            Some(existing) => {
                                assert_eq!(
                                    existing, num_vars,
                                    "inconsistent log size within table for node {}",
                                    node_id
                                );
                            },
                            None => {
                                log_size = Some(num_vars);
                            },
                        }
                        columns.insert(field_ref, tracked);
                    }
                }

                let table_log_size = log_size.unwrap_or(0);
                let table_oracle = TrackedTableOracle::new(schema_owned, columns, table_log_size);
                tables_for_node.insert(label, table_oracle);
            }

            tables_by_node.insert(node_id, tables_for_node);
        }
        VerifierTrackedTree::new(proof_tree, tables_by_node)
    }
}
