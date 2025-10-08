use crate::{
    id::NodeId,
    verifier::{
        nodes::{VerifierNode, lps::TableScanNode},
        trees::proof_tree::VerifierProofTree,
    },
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
use std::{collections::HashMap, fmt, sync::Arc};
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
    tables: IndexMap<NodeId, HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>,
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
            .field("num_nodes", &self.tables.len())
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
        tables: IndexMap<NodeId, HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>,
    ) -> Self {
        Self {
            tables,
            inner_proof_tree: proof_tree,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        VerifierProofTree<F, MvPCS, UvPCS>,
        IndexMap<NodeId, HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>,
    ) {
        let VerifierTrackedTree {
            tables,
            inner_proof_tree,
        } = self;
        (inner_proof_tree, tables)
    }

    pub fn table_by_node_map(
        self,
    ) -> IndexMap<NodeId, HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>> {
        let (_, tables) = self.into_parts();
        tables
    }

    pub fn len(&self) -> usize {
        self.tables.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tables.is_empty()
    }

    pub fn tables_for(
        &self,
        node_id: &NodeId,
    ) -> Option<&HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>> {
        self.tables.get(node_id)
    }

    pub fn table_for(
        &self,
        node_id: &NodeId,
        label: &str,
    ) -> Option<&TrackedTableOracle<F, MvPCS, UvPCS>> {
        self.tables
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
        shared_ctx: SharedCtx<F, MvPCS, UvPCS>,
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
    ) -> VerifierTrackedTree<F, MvPCS, UvPCS> {
        fn collect<F, MvPCS, UvPCS>(
            node: &Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
            depth: usize,
            depths: &mut HashMap<usize, usize>,
            out: &mut Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
        ) where
            F: PrimeField,
            MvPCS: PCS<F, Poly = MLE<F>> + 'static,
            UvPCS: PCS<F, Poly = LDE<F>> + 'static,
        {
            for child in node.children() {
                collect(child, depth + 1, depths, out);
            }
            depths.insert(node_ptr_id(node), depth);
            out.push(Arc::clone(node));
        }

        let root = proof_tree.root();
        let mut nodes = Vec::new();
        let mut depths = HashMap::new();
        collect(&root, 0, &mut depths, &mut nodes);

        let mut table_scan_nodes: Vec<_> = nodes
            .iter()
            .filter(|node| node.as_any().downcast_ref::<TableScanNode>().is_some())
            .cloned()
            .collect();
        let mut other_nodes: Vec<_> = nodes
            .iter()
            .filter(|node| node.as_any().downcast_ref::<TableScanNode>().is_none())
            .cloned()
            .collect();

        let cmp_nodes = |a: &Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
                         b: &Arc<dyn VerifierNode<F, MvPCS, UvPCS>>| {
            let depth_a = depths.get(&node_ptr_id(a)).copied().unwrap_or(0);
            let depth_b = depths.get(&node_ptr_id(b)).copied().unwrap_or(0);
            depth_b
                .cmp(&depth_a)
                .then_with(|| a.node_id().to_string().cmp(&b.node_id().to_string()))
        };

        table_scan_nodes.sort_by(cmp_nodes);
        other_nodes.sort_by(cmp_nodes);

        let ordered_nodes = table_scan_nodes
            .into_iter()
            .chain(other_nodes)
            .collect::<Vec<_>>();

        let mut ordered_infos: Vec<(NodeId, bool, HashMap<String, DFSchemaRef>)> =
            Vec::with_capacity(ordered_nodes.len());

        for node in ordered_nodes {
            let node_id = node.node_id();
            let is_table_scan = node.as_any().downcast_ref::<TableScanNode>().is_some();
            let schema_map: HashMap<String, DFSchemaRef> = node
                .hint_generation_plans()
                .into_iter()
                .map(|(label, plan)| (label, Arc::clone(plan.schema())))
                .collect();
            ordered_infos.push((node_id, is_table_scan, schema_map));
        }

        let shared_ctx = proof_tree.ctx().clone();

        let mut tables_by_node: IndexMap<
            NodeId,
            HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>,
        > = IndexMap::with_capacity(ordered_infos.len());
        // At this point, we have the nodes in an order synced with the prover
        for (node_id, is_table_scan, schema_map) in ordered_infos {
            let mut tables_for_node = HashMap::with_capacity(schema_map.len());

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

fn node_ptr_id<F, MvPCS, UvPCS>(node: &Arc<dyn VerifierNode<F, MvPCS, UvPCS>>) -> usize
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    let data_ptr = &**node as *const dyn VerifierNode<F, MvPCS, UvPCS> as *const ();
    data_ptr as usize
}
