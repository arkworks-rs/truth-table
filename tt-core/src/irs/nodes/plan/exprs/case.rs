use std::sync::Arc;

use ark_piop::SnarkBackend;
use datafusion_common::Statistics;
use datafusion_expr::Case;

use crate::irs::nodes::{
    IsExprNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
};
use crate::irs::tree::Tree;

pub struct ProverNode<B: SnarkBackend> {
    pub scope: std::sync::Weak<Node<B>>,
    pub expr: Option<Arc<Node<B>>>,
    #[allow(clippy::type_complexity)]
    pub when_then: Vec<(Arc<Node<B>>, Arc<Node<B>>)>,
    pub else_expr: Option<Arc<Node<B>>>,
    pub parent: Option<std::sync::Weak<Node<B>>>,
    pub case: Case,
}

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "Case".to_string()
    }

    fn display(&self) -> String {
        let base = self
            .expr
            .as_ref()
            .map(|node| node.name())
            .unwrap_or_else(|| "none".to_string());
        let else_expr = self
            .else_expr
            .as_ref()
            .map(|node| node.name())
            .unwrap_or_else(|| "none".to_string());
        format!(
            "Case\nBase: {}, when/then pairs: {}, else: {}",
            base,
            self.when_then.len(),
            else_expr
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
        let mut children = Vec::new();
        if let Some(expr) = &self.expr {
            children.push(expr.clone());
        }
        for (when_expr, then_expr) in &self.when_then {
            children.push(when_expr.clone());
            children.push(then_expr.clone());
        }
        if let Some(else_expr) = &self.else_expr {
            children.push(else_expr.clone());
        }
        children
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ProverNode<B> {
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
}

impl<B: SnarkBackend> IsPlanNode<B> for ProverNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        None
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let scope = self
            .scope
            .upgrade()
            .expect("Case scope should be available during output");
        let scope_hint_df = match scope.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("Case scope cannot be a gadget node"),
        };

        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(scope_hint_df.data_frame().clone())
                .expect("case row-id sort should succeed");

        let mut exprs = vec![datafusion_expr::Expr::Case(self.case.clone())];
        crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut exprs);
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);

        let projected = input_df
            .select(exprs)
            .expect("case projection should succeed");

        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("case output sort should succeed");
        // Materialize CASE output so aggregate multiplicities can reference it.
        crate::irs::nodes::hints::HintDF::new_materialized(projected)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ProverNode<B> {
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
}

impl<B: SnarkBackend> IsExprNode<B> for ProverNode<B> {
    fn from_expr(
        expr: datafusion_expr::Expr,
        self_ref: std::sync::Weak<Node<B>>,
        parent: Option<std::sync::Weak<Node<B>>>,
        scope: std::sync::Weak<Node<B>>,
    ) -> Self
    where
        Self: Sized,
    {
        let case = match expr {
            datafusion_expr::Expr::Case(case_expr) => case_expr,
            _ => panic!("Expected Case expression"),
        };

        let expr_node = case.expr.as_ref().map(|base_expr| {
            Tree::<B>::from_expr(base_expr, Some(self_ref.clone()), scope.clone())
                .root()
                .clone()
        });

        let when_then = case
            .when_then_expr
            .iter()
            .map(|(when_expr, then_expr)| {
                let when_node =
                    Tree::<B>::from_expr(when_expr, Some(self_ref.clone()), scope.clone())
                        .root()
                        .clone();
                let then_node =
                    Tree::<B>::from_expr(then_expr, Some(self_ref.clone()), scope.clone())
                        .root()
                        .clone();
                (when_node, then_node)
            })
            .collect::<Vec<_>>();

        let else_node = case.else_expr.as_ref().map(|else_expr| {
            Tree::<B>::from_expr(else_expr, Some(self_ref.clone()), scope.clone())
                .root()
                .clone()
        });

        Self {
            case,
            expr: expr_node,
            when_then,
            else_expr: else_node,
            scope,
            parent,
        }
    }

    fn expr(&self) -> datafusion_expr::Expr {
        datafusion_expr::Expr::Case(self.case.clone())
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
                Node::Gadget(_) => panic!("Case parent cannot be a gadget node"),
            })
            .expect("Case node must have a parent")
    }

    fn scope(&self) -> std::sync::Arc<Node<B>>
    where
        Self: Sized,
    {
        self.scope
            .upgrade()
            .expect("Case scope should be available")
    }
}
