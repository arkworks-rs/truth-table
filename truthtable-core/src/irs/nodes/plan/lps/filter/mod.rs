use ark_piop::SnarkBackend;
use datafusion_expr::{Filter, LogicalPlan};

use crate::irs::nodes::Node;

/// The implementation of a filter node in the prover proof tree.
pub struct ProverNode<B>
where
    B: SnarkBackend,
{
    // The filter information from DataFusion
    filter: Filter,
    // The prover plan children nodes for the Filter expressions
    input: Node<B>,
    // The prover predicate expression node for the filter condition
    predicate: Node<B>,
}
