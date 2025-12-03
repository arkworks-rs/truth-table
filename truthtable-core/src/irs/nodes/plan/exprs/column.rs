use std::sync::Arc;

use arithmetic::ACTIVATOR_EXPR;
use ark_piop::SnarkBackend;
use datafusion::parquet::column;
use datafusion_common::{Column, Statistics};

use crate::irs::nodes::{IsExprNode, IsNode, IsPlanNode, Node, NodeId};

pub struct ProverNode<B: SnarkBackend> {
    pub scope: Arc<Node<B>>,
    pub column: Column,
}

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "Column".to_string()
    }

    fn cost(
        &self,
        statistics: Statistics,
        schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![]
    }

    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        use crate::prover::payloads::PayloadStructure;
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Locate the scope node id by hashing the stored scope Arc the same way arena keys
        // are derived.
        let scope_id = {
            let mut hasher = DefaultHasher::new();
            self.scope.hash(&mut hasher);
            hasher.finish()
        };

        // Fetch the scope payload to retrieve the tracked table.
        let Some(scope_payload) = virtualized_ir
            .payloads()
            .get(&scope_id)
            .and_then(|p| p.as_ref())
        else {
            return Ok(());
        };

        let scope_table = match scope_payload {
            PayloadStructure::PlanPayload(table) => table,
            PayloadStructure::GadgetPayload(_) => return Ok(()),
        };

        let Some(schema) = scope_table.schema_ref() else {
            return Ok(());
        };
        let Ok(col_idx) = schema.index_of(self.column.name()) else {
            return Ok(());
        };

        // Build a subtable containing just the requested column (plus activator if present).
        let subtable = scope_table.tracked_subtable_by_indices(&[col_idx]);

        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(subtable)));
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ProverNode<B> {
    fn gadget(&self) -> std::sync::Arc<Node<B>> {
        todo!()
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        // Project just this column and the activator from the scoped DataFrame.
        let scope_hint_df = match self.scope.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("Column scope cannot be a gadget node"),
        };

        let projected = scope_hint_df
            .data_frame()
            .clone()
            .select(vec![
                datafusion_expr::Expr::Column(self.column.clone()),
                ACTIVATOR_EXPR.clone(),
            ])
            .expect("column projection should succeed");

        crate::irs::nodes::hints::HintDF::new_virtual(projected)
    }
}

impl<B: SnarkBackend> IsExprNode<B> for ProverNode<B> {
    fn from_expr(
        _expr: datafusion_expr::Expr,
        self_ref: std::sync::Weak<Node<B>>,
        parent: Option<std::sync::Weak<Node<B>>>,
        scope: std::sync::Arc<Node<B>>,
    ) -> Self
    where
        Self: Sized,
    {
        let column = match _expr {
            datafusion_expr::Expr::Column(col) => col,
            _ => panic!("Expected Column expression"),
        };
        Self { column, scope }
    }

    fn expr(&self) -> datafusion_expr::Expr {
        todo!()
    }

    fn parent(&self) -> crate::irs::nodes::PlanNode<B>
    where
        Self: Sized,
    {
        todo!()
    }

    fn scope(&self) -> std::sync::Arc<Node<B>>
    where
        Self: Sized,
    {
        self.scope.clone()
    }
}
