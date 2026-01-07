use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_EXPR};
use ark_piop::SnarkBackend;
use datafusion_common::{Column, Statistics};

use crate::irs::{
    nodes::{IsExprNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps},
    payloads::PayloadStructure,
};

pub struct ProverNode<B: SnarkBackend> {
    pub scope: Arc<Node<B>>,
    pub parent: Option<std::sync::Weak<Node<B>>>,
    pub column: Column,
}

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "Column".to_string()
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
        vec![]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Locate the scope node id using the shared helper.
        let scope_id = self.scope.id();

        // Fetch the scope payload to retrieve the tracked table.
        let scope_payload = virtualized_ir.payload_for_node(&scope_id);

        // Helper: try to pull the requested column (and activator) from a tracked table.
        let try_build_subtable =
            |table: &arithmetic::table::TrackedTable<B>, column_name: &str| -> Option<_> {
                let schema = table.schema_ref()?;
                let col_idx = schema.index_of(column_name).ok()?;
                Some(table.tracked_subtable_by_indices(&[col_idx]))
            };

        // First try the scope payload itself.
        if let Some(PayloadStructure::PlanPayload(table)) = scope_payload
            && let Some(subtable) = try_build_subtable(table, self.column.name())
        {
            virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(subtable)));
            return Ok(());
        };

        panic!(
            "Column node could not find its column '{}' in scope node {:?}",
            self.column.name(),
            scope_id
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
        // Project just this column and the activator from the scoped DataFrame.
        let scope_hint_df = match self.scope.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("Column scope cannot be a gadget node"),
        };

        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(scope_hint_df.data_frame().clone())
                .expect("column row-id sort should succeed");

        let mut exprs = vec![datafusion_expr::Expr::Column(self.column.clone())];
        if self.column.name() != ACTIVATOR_COL_NAME {
            exprs.push(ACTIVATOR_EXPR.clone());
        }
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);

        let projected = input_df
            .select(exprs)
            .expect("column projection should succeed");

        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("column output sort should succeed");
        crate::irs::nodes::hints::HintDF::new_virtual(projected)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Locate the scope node id using the shared helper.
        let scope_id = self.scope.id();

        // Fetch the scope payload to retrieve the tracked table oracle.
        let scope_payload = virtualized_ir.payload_for_node(&scope_id);

        // Helper: try to pull the requested column (and activator) from a tracked table oracle.
        let try_build_subtable = |table: &arithmetic::table_oracle::TrackedTableOracle<B>,
                                  column_name: &str| {
            let schema = table.schema_ref()?;
            let col_idx = schema.index_of(column_name).ok()?;
            Some(table.tracked_subtable_by_indices(&[col_idx]))
        };

        // First try the scope payload itself.
        if let Some(PayloadStructure::PlanPayload(table)) = scope_payload
            && let Some(subtable) = try_build_subtable(table, self.column.name())
        {
            virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(subtable)));
            return Ok(());
        };

        panic!(
            "Column node could not find its column '{}' in scope node {:?}",
            self.column.name(),
            scope_id
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
        _expr: datafusion_expr::Expr,
        _self_ref: std::sync::Weak<Node<B>>,
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
        Self {
            column,
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
                Node::Gadget(_) => panic!("Column parent cannot be a gadget node"),
            })
            .expect("Column node must have a parent")
    }

    fn scope(&self) -> std::sync::Arc<Node<B>>
    where
        Self: Sized,
    {
        self.scope.clone()
    }
}
