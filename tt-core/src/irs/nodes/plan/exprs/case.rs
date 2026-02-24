use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{DataType, Schema};
use datafusion_common::Statistics;
use datafusion_expr::{Case, Expr};

use crate::irs::nodes::{
    IsExprNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
};
use crate::irs::tree::Tree;

pub struct ExprNode<B: SnarkBackend> {
    pub scope: Vec<std::sync::Weak<Node<B>>>,
    pub expr: Option<Arc<Node<B>>>,
    #[allow(clippy::type_complexity)]
    pub when_then: Vec<(Arc<Node<B>>, Arc<Node<B>>)>,
    pub else_expr: Option<Arc<Node<B>>>,
    pub parent: Option<std::sync::Weak<Node<B>>>,
    pub case: Case,
}

impl<B: SnarkBackend> IsNode<B> for ExprNode<B> {
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
        planned_ir: &mut crate::prover::irs::OutputPlannedIr<B>,
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
            .expect("Case scope should be available during output");
        let scope_hint_df = match scope.as_ref() {
            Node::Plan(plan_node) => <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsProverPlanNode<B>>::output(plan_node),
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

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for ExprNode<B> {
    fn output(&self) -> crate::irs::nodes::verifier_hint::VerifierHint {
        let scope_hint = self.scope[0]
            .upgrade()
            .and_then(|scope| match scope.as_ref() {
                Node::Plan(plan_node) => Some(
                    <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<
                        B,
                    >>::output(plan_node),
                ),
                Node::Gadget(_) => None,
            })
            .expect("Case scope should resolve to a plan node");

        let scope_schema = scope_hint.schema();
        let case_name = Expr::Case(self.case.clone()).schema_name().to_string();
        let case_dtype = self
            .when_then
            .iter()
            .find_map(|(_, then_expr)| first_data_field_type_from_node::<B>(then_expr))
            .or_else(|| {
                self.else_expr
                    .as_ref()
                    .and_then(first_data_field_type_from_node::<B>)
            })
            .unwrap_or(DataType::Boolean);
        let case_field = Arc::new(datafusion::arrow::datatypes::Field::new(
            case_name,
            case_dtype,
            true,
        ));

        let mut output_fields = vec![case_field.clone()];
        let mut field_materialization = indexmap::IndexMap::new();
        field_materialization.insert(case_field, true);

        if scope_hint.has_activator()
            && let Some(field) = scope_schema
                .fields()
                .iter()
                .find(|field| field.name() == ACTIVATOR_COL_NAME)
                .cloned()
        {
            output_fields.push(field.clone());
            field_materialization.insert(field, false);
        }
        if scope_hint.has_row_id()
            && let Some(field) = scope_schema
                .fields()
                .iter()
                .find(|field| field.name() == ROW_ID_COL_NAME)
                .cloned()
        {
            output_fields.push(field.clone());
            field_materialization.insert(field, false);
        }

        crate::irs::nodes::verifier_hint::VerifierHint::from_field_materialization(
            Arc::new(Schema::new_with_metadata(
                output_fields
                    .into_iter()
                    .map(|field| field.as_ref().clone())
                    .collect::<Vec<_>>(),
                scope_schema.metadata().clone(),
            )),
            field_materialization,
            scope_hint.log_size(),
        )
    }
}

fn first_data_field_type_from_node<B: SnarkBackend>(node: &Arc<Node<B>>) -> Option<DataType> {
    let hint = match node.as_ref() {
        Node::Plan(plan_node) => {
            <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                plan_node,
            )
        }
        Node::Gadget(_) => return None,
    };
    hint.schema()
        .fields()
        .iter()
        .find(|field| {
            field.name() != ACTIVATOR_COL_NAME && field.name() != ROW_ID_COL_NAME
        })
        .map(|field| field.data_type().clone())
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
        planned_ir: &mut crate::verifier::irs::OutputPlannedIr<B>,
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
