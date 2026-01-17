use std::sync::Arc;

use ark_piop::SnarkBackend;
use datafusion_common::Statistics;
use datafusion_expr::Between;
use datafusion_expr::Expr;
use datafusion_expr::expr::InList;

use crate::irs::nodes::{
    IsExprNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
};
use crate::irs::tree::Tree;

pub struct ProverNode<B: SnarkBackend> {
    pub scope: Arc<Node<B>>,
    pub expr: Arc<Node<B>>,
    pub list: Vec<Arc<Node<B>>>,
    pub parent: Option<std::sync::Weak<Node<B>>>,
    pub in_list: InList,
}

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "InList".to_string()
    }

    fn display(&self) -> String {
        format!(
            "InList\nInput: {}, List Length: {}",
            self.expr.name(),
            self.list.len()
        )
    }

    fn cost(
        &self,
        _statistics: Statistics,
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
        vec![self.expr.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ProverNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        None
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        // Produce a virtual DataFrame with the IN-list result and scope metadata.
        let scope_hint_df = match self.scope.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("InList scope cannot be a gadget node"),
        };

        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(scope_hint_df.data_frame().clone())
                .expect("in-list row-id sort should succeed");

        let mut exprs = vec![Expr::InList(self.in_list.clone())];
        crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut exprs);
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);

        let projected = input_df
            .select(exprs)
            .expect("in-list projection should succeed");

        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("in-list output sort should succeed");
        crate::irs::nodes::hints::HintDF::new_virtual(projected)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsExprNode<B> for ProverNode<B> {
    fn from_expr(
        expr: datafusion_expr::Expr,
        self_ref: std::sync::Weak<Node<B>>,
        parent: Option<std::sync::Weak<Node<B>>>,
        scope: std::sync::Arc<Node<B>>,
    ) -> Self
    where
        Self: Sized,
    {
        let in_list = match expr {
            datafusion_expr::Expr::InList(col) => col,
            _ => panic!("Expected Cast expression"),
        };

        let expr_node = Tree::<B>::from_expr(&in_list.expr, Some(self_ref.clone()), scope.clone())
            .root()
            .clone();

        let list_nodes = in_list
            .list
            .iter()
            .map(|expr| {
                Tree::<B>::from_expr(expr, Some(self_ref.clone()), scope.clone())
                    .root()
                    .clone()
            })
            .collect();

        Self {
            in_list,
            expr: expr_node,
            scope,
            parent,
            list: list_nodes,
        }
    }

    fn expr(&self) -> datafusion_expr::Expr {
        todo!()
    }

    fn parent(&self) -> crate::irs::nodes::PlanNode<B>
    where
        Self: Sized,
    {
        self.parent
            .as_ref()
            .and_then(|weak_ref| weak_ref.upgrade())
            .map(|arc_node| match arc_node.as_ref() {
                Node::Plan(plan_node) => plan_node.clone(),
                Node::Gadget(_) => panic!("Cast parent cannot be a gadget node"),
            })
            .expect("Cast node must have a parent")
    }

    fn scope(&self) -> std::sync::Arc<Node<B>>
    where
        Self: Sized,
    {
        self.scope.clone()
    }
}
