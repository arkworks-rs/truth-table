use std::sync::Arc;

use ark_piop::SnarkBackend;
use datafusion_common::Statistics;
use datafusion_expr::expr::ScalarFunction;

use crate::irs::nodes::{
    IsExprNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
};
use crate::irs::tree::Tree;

pub struct ExprNode<B: SnarkBackend> {
    pub scope: Vec<std::sync::Weak<Node<B>>>,
    pub exprs: Vec<Arc<Node<B>>>,
    pub parent: Option<std::sync::Weak<Node<B>>>,
    pub scalar_function: ScalarFunction,
}

impl<B: SnarkBackend> IsNode<B> for ExprNode<B> {
    fn name(&self) -> String {
        "Scalar Function".to_string()
    }

    fn display(&self) -> String {
        let _args = if self.exprs.is_empty() {
            "none".to_string()
        } else {
            self.exprs
                .iter()
                .map(|node| node.name())
                .collect::<Vec<_>>()
                .join(", ")
        };
        format!("ScalarFunction\nfunc: {}", self.scalar_function.name(),)
    }

    fn cost(
        &self,
        _statistics: Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        self.exprs.clone()
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ExprNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ExprNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        None
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsProverPlanNode<B> for ExprNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        todo!()
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for ExprNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        <Self as crate::irs::nodes::IsProverPlanNode<B>>::output(self)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ExprNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsExprNode<B> for ExprNode<B> {
    fn from_expr(
        expr: datafusion_expr::Expr,
        self_ref: std::sync::Weak<Node<B>>,
        parent: Option<std::sync::Weak<Node<B>>>,
        scope: Vec<std::sync::Weak<Node<B>>>,
    ) -> Self
    where
        Self: Sized,
    {
        let scalar_function = match expr {
            datafusion_expr::Expr::ScalarFunction(col) => col,
            _ => panic!("Expected ScalarFunction expression"),
        };

        let expr_nodes = scalar_function
            .args
            .iter()
            .map(|arg_expr| {
                Tree::<B>::from_expr(arg_expr, Some(self_ref.clone()), scope.clone())
                    .root()
                    .clone()
            })
            .collect::<Vec<_>>();

        Self {
            scalar_function,
            exprs: expr_nodes,
            scope,
            parent,
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

    fn scope(&self) -> Vec<std::sync::Arc<Node<B>>>
    where
        Self: Sized,
    {
        self.scope
            .iter()
            .map(|s| {
                s.upgrade()
                    .expect("ScalarFunction scope should be available")
            })
            .collect()
    }
}
