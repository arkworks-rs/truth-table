use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{Field, FieldRef, Schema};
use datafusion_expr::{Filter, LogicalPlan};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{
            IsLpNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
            gadget::lps::{
                filter::{
                    self, FILTER_PREDICATE_LABEL, INPUT_ACTIVATOR_LABEL, OUTPUT_ACTIVATOR_LABEL,
                },
                sort,
            },
            hints::HintDF,
        },
        payloads::PayloadStructure,
        tree::Tree,
    },
    prover::irs::VirtualizedIr as ProverVirtualizedIr,
    verifier::irs::VirtualizedIr as VerifierVirtualizedIr,
};
mod output;
use datafusion::logical_expr::Sort;
/// The implementation of a filter node in the prover proof tree.
pub struct GadgetNode<B>
where
    B: SnarkBackend,
{
    // The sort information from DataFusion
    sort: Sort,
    // The prover plan child node that is the input to this Sort
    input: Arc<Node<B>>,
    // The prover plan children nodes for the Sort expressions
    sort_exprs: Vec<Arc<Node<B>>>,
    // The gadget node for proving the sort operation
    gadget: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Sort".to_string()
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        let mut children = vec![self.input.clone()];
        children.extend(self.sort_exprs.iter().cloned());
        children.push(self.gadget.clone());
        children
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        todo!()
    }

    /// The gadget for the filter node only takes in 1. the input activator column, 2. the output activator column and 3. the binary output of the predicate column.
    /// Then the gadget proves to you that the output activator column is correctly computed from the input activator column and the predicate column.
    fn initialize_gadgets(
        &self,
        _id: NodeId,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        todo!()
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        todo!()
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        todo!()
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for GadgetNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        Some(self.gadget.as_ref().clone())
    }

    fn output(&self) -> HintDF {
        todo!()
    }
}

impl<B: SnarkBackend> IsLpNode<B> for GadgetNode<B> {
    fn from_lp(plan: LogicalPlan, self_ref: std::sync::Weak<Node<B>>) -> Self
    where
        Self: Sized,
    {
        let sort = match plan {
            LogicalPlan::Sort(sort) => sort,
            _ => panic!("Expected LogicalPlan::Sort"),
        };

        // Recurse into the input subtree and fetch the logical plan that feeds this
        // sort.
        let input = Tree::<B>::from_logical_plan(&sort.input).root().clone();

        // Recurse into the input subtree and fetch the expr that feeds this
        // sort.
        let mut sort_exprs = vec![];
        for expr in &sort.expr {
            let expr_lp =
                Tree::<B>::from_expr(&expr.expr.clone(), Some(self_ref.clone()), input.clone())
                    .root()
                    .clone();
            sort_exprs.push(expr_lp);
        }

        let gadget = Arc::new(Node::<B>::Gadget(Arc::new(sort::GadgetNode::new())));

        Self {
            sort,
            input,
            sort_exprs,
            gadget,
        }
    }

    fn lp(&self) -> LogicalPlan {
        LogicalPlan::Sort(self.sort.clone())
    }
}
