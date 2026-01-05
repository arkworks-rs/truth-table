use std::sync::Arc;

use arithmetic::ACTIVATOR_EXPR;
use ark_piop::SnarkBackend;
use datafusion_common::{Column, Statistics};
use datafusion_expr::{Expr, expr::AggregateFunction};

use crate::irs::{
    nodes::{IsExprNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps},
    payloads::PayloadStructure,
};
pub const INPUT_GROUPS_LABEL: &str = "__groups__";
pub const INPUT_AGGR_EXPR_LABEL: &str = "__aggr-expr__";
#[derive(Clone)]
pub struct ProverNode<B: SnarkBackend> {
    pub aggregate_function: AggregateFunction,
    pub scope: Arc<Node<B>>,
    pub parent: Option<std::sync::Weak<Node<B>>>,
}

impl<B: SnarkBackend> ProverNode<B> {
    fn output_column_name(&self) -> String {
        Expr::AggregateFunction(self.aggregate_function.clone())
            .schema_name()
            .to_string()
    }
}

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "AggregateFunction".to_string()
    }

    fn cost(
        &self,
        _statistics: Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        vec![]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let parent_node = self
            .parent
            .as_ref()
            .and_then(|weak_ref| weak_ref.upgrade())
            .expect("AggregateFunction node must have a parent");
        let parent_id = parent_node.id();
        let parent_payload = virtualized_ir.payload_for_node(&parent_id);
        let column_name = self.output_column_name();

        let try_build_subtable =
            |table: &arithmetic::table::TrackedTable<B>, column_name: &str| -> Option<_> {
                let schema = table.schema_ref()?;
                let col_idx = schema.index_of(column_name).ok()?;
                Some(table.tracked_subtable_by_indices(&[col_idx]))
            };

        if let Some(PayloadStructure::PlanPayload(table)) = parent_payload
            && let Some(subtable) = try_build_subtable(table, &column_name)
        {
            virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(subtable)));
            return Ok(());
        }

        panic!(
            "AggregateFunction node could not find its column '{}' in parent node {:?}",
            column_name, parent_id
        );
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
        let parent_hint_df = self.parent().output();
        let column_name = self.output_column_name();
        let projected = parent_hint_df
            .data_frame()
            .clone()
            .select(vec![
                Expr::Column(Column::from_name(column_name)),
                ACTIVATOR_EXPR.clone(),
            ])
            .expect("aggregate function projection should succeed");

        crate::irs::nodes::hints::HintDF::new_virtual(projected)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let parent_node = self
            .parent
            .as_ref()
            .and_then(|weak_ref| weak_ref.upgrade())
            .expect("AggregateFunction node must have a parent");
        let parent_id = parent_node.id();
        let parent_payload = virtualized_ir.payload_for_node(&parent_id);
        let column_name = self.output_column_name();

        let try_build_subtable =
            |table: &arithmetic::table_oracle::TrackedTableOracle<B>, column_name: &str| {
                let schema = table.schema_ref()?;
                let col_idx = schema.index_of(column_name).ok()?;
                Some(table.tracked_subtable_by_indices(&[col_idx]))
            };

        if let Some(PayloadStructure::PlanPayload(table)) = parent_payload
            && let Some(subtable) = try_build_subtable(table, &column_name)
        {
            virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(subtable)));
            return Ok(());
        }

        panic!(
            "AggregateFunction node could not find its column '{}' in parent node {:?}",
            column_name, parent_id
        );
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
        expr: Expr,
        _self_ref: std::sync::Weak<Node<B>>,
        parent: Option<std::sync::Weak<Node<B>>>,
        scope: Arc<Node<B>>,
    ) -> Self
    where
        Self: Sized,
    {
        let aggregate_function = match expr {
            Expr::AggregateFunction(func) => func,
            _ => panic!("Expected AggregateFunction expression"),
        };
        Self {
            aggregate_function,
            scope,
            parent,
        }
    }

    fn expr(&self) -> Expr {
        Expr::AggregateFunction(self.aggregate_function.clone())
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
                Node::Gadget(_) => panic!("AggregateFunction parent cannot be a gadget node"),
            })
            .expect("AggregateFunction node must have a parent")
    }

    fn scope(&self) -> Arc<Node<B>>
    where
        Self: Sized,
    {
        self.scope.clone()
    }
}
