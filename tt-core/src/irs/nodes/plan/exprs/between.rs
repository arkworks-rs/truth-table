use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use datafusion_common::Statistics;
use datafusion_expr::{Between, Expr};
use indexmap::IndexMap;

use crate::irs::nodes::{
    IsExprNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
};
use crate::irs::tree::Tree;

pub struct ExprNode<B: SnarkBackend> {
    pub scope: Vec<std::sync::Weak<Node<B>>>,
    pub expr: Arc<Node<B>>,
    pub low: Arc<Node<B>>,
    pub high: Arc<Node<B>>,
    pub parent: Option<std::sync::Weak<Node<B>>>,
    pub between: Between,
}

impl<B: SnarkBackend> IsNode<B> for ExprNode<B> {
    fn name(&self) -> String {
        "Between".to_string()
    }

    fn display(&self) -> String {
        format!(
            "Between\nInput: {}, low: {}, high: {}",
            self.expr.name(),
            self.low.name(),
            self.high.name()
        )
    }

    fn cost(
        &self,
        _statistics: Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.expr.clone()]
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
        let scope = self.scope[0]
            .upgrade()
            .expect("Between scope should be available during output");
        let scope_hint_df = match scope.as_ref() {
            Node::Plan(plan_node) => <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsProverPlanNode<B>>::output(plan_node),
            Node::Gadget(_) => panic!("Between scope cannot be a gadget node"),
        };

        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(scope_hint_df.data_frame().clone())
                .expect("between row-id sort should succeed");

        let mut exprs = vec![Expr::Between(self.between.clone())];
        crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut exprs);
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);

        let projected = input_df
            .select(exprs)
            .expect("between projection should succeed");
        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("between output sort should succeed");

        let should_materialize: IndexMap<_, _> = projected
            .schema()
            .fields()
            .iter()
            .map(|field| {
                let is_data = field.name() != ACTIVATOR_COL_NAME && field.name() != ROW_ID_COL_NAME;
                (field.clone(), is_data)
            })
            .collect();
        crate::irs::nodes::hints::HintDF::new(projected, should_materialize)
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for ExprNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let scope = self.scope[0]
            .upgrade()
            .expect("Between scope should be available during output");
        let scope_hint_df = match scope.as_ref() {
            Node::Plan(plan_node) => <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(plan_node),
            Node::Gadget(_) => panic!("Between scope cannot be a gadget node"),
        };

        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(scope_hint_df.data_frame().clone())
                .expect("between row-id sort should succeed");

        let mut exprs = vec![Expr::Between(self.between.clone())];
        crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut exprs);
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);

        let projected = input_df
            .select(exprs)
            .expect("between projection should succeed");
        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("between output sort should succeed");

        let should_materialize: IndexMap<_, _> = projected
            .schema()
            .fields()
            .iter()
            .map(|field| {
                let is_data = field.name() != ACTIVATOR_COL_NAME && field.name() != ROW_ID_COL_NAME;
                (field.clone(), is_data)
            })
            .collect();
        crate::irs::nodes::hints::HintDF::new(projected, should_materialize)
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
        <Self as ProverNodeOps<B>>::initialize_gadget_plans(self, id, planned_ir)
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
        let between = match expr {
            datafusion_expr::Expr::Between(col) => col,
            _ => panic!("Expected Cast expression"),
        };

        let expr_node = Tree::<B>::from_expr(&between.expr, Some(self_ref.clone()), scope.clone())
            .root()
            .clone();

        let low_node = Tree::<B>::from_expr(&between.low, Some(self_ref.clone()), scope.clone())
            .root()
            .clone();

        let high_node = Tree::<B>::from_expr(&between.high, Some(self_ref.clone()), scope.clone())
            .root()
            .clone();
        Self {
            between,
            expr: expr_node,
            scope,
            parent,
            low: low_node,
            high: high_node,
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
