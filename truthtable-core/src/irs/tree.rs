use std::{any::Any, collections::HashMap, sync::Arc};

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use ark_std::fmt::Debug;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion_common::Statistics;
use indexmap::IndexMap;

use super::nodes::{cost::ProvingCost, id::NodeId};
pub trait Node<B>: Any + Send + Sync + Debug
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    /// Returns the unique identifier of this node.
    fn id(&self) -> NodeId;
    /// Returns the human-readable name of this node.
    fn name(&self) -> String {
        self.id().to_string()
    }
    /// Returns a human-readable representation of this node.
    fn display(&self) -> String {
        self.name()
    }
    /// Estimates the proving cost of this node given statistics and schema.
    fn cost(&self, statistics: Statistics, schema: SchemaRef) -> ProvingCost;
}
/// The abstraction of a tree structure used in intermediate representations
#[derive(Debug, Clone)]
pub struct Tree<B>
where
B:SnarkBackend
{
    root: Arc<dyn Node<B>>,
    arena: IndexMap<NodeId, Arc<dyn Node<B>>>,
}
impl<B> Tree<B>
where
B:SnarkBackend
{
    /// Get the root node of this tree.
    fn root(&self) -> Arc<dyn Node<B>> {
        Arc::clone(&self.root)
    }

    /// Get the arena of nodes in this tree.
    pub fn arena(&self) -> &IndexMap<NodeId, Arc<dyn Node<B>>> {
        &self.arena
    }

    /// Get a node by its ID from the arena.
    pub fn get_node(&self, node_id: &NodeId) -> Option<&Arc<dyn Node<B>>> {
        self.arena.get(node_id)
    }

    /// Display the tree in Graphviz DOT format.
    fn display_graphviz(&self, inner: bool) -> String {
        todo!()
    }
}

pub trait Payload: Debug + 'static {}
