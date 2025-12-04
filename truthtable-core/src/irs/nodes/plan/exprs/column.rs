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
        let scope_payload = virtualized_ir
            .payloads()
            .get(&scope_id)
            .and_then(|p| p.as_ref());

        // Helper: try to pull the requested column (and activator) from a tracked table.
        let try_build_subtable =
            |table: &arithmetic::table::TrackedTable<B>, column_name: &str| -> Option<_> {
                let schema = table.schema_ref()?;
                let col_idx = schema.index_of(column_name).ok()?;
                Some(table.tracked_subtable_by_indices(&[col_idx]))
            };

        // First try the scope payload itself.
        if let Some(PayloadStructure::PlanPayload(table)) = scope_payload {
            if let Some(subtable) = try_build_subtable(table, self.column.name()) {
                virtualized_ir
                    .set_payload_for_node(id, Some(PayloadStructure::PlanPayload(subtable)));
                return Ok(());
            }
        };

        // If the scope payload is missing the column (e.g. filtered away), walk the scope's
        // plan children to find a payload that still contains it.
        if let Some(scope_node) = virtualized_ir.tree().get_node(&scope_id) {
            for child in scope_node.children() {
                // Only plan children carry tracked tables.
                if !matches!(child.as_ref(), crate::irs::nodes::Node::Plan(_)) {
                    continue;
                }

                let mut hasher = DefaultHasher::new();
                child.hash(&mut hasher);
                let child_id = hasher.finish();

                if let Some(Some(PayloadStructure::PlanPayload(table))) =
                    virtualized_ir.payloads().get(&child_id)
                {
                    if let Some(subtable) = try_build_subtable(table, self.column.name()) {
                        virtualized_ir.set_payload_for_node(
                            id,
                            Some(PayloadStructure::PlanPayload(subtable)),
                        );
                        return Ok(());
                    }
                }
            }
        }

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
