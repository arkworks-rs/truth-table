use std::sync::Arc;

use arithmetic::ACTIVATOR_COL_NAME;
use ark_piop::SnarkBackend;
use datafusion_common::{Column, DFSchema, Statistics};

// Store column qualifiers in metadata to disambiguate same-name columns.
const QUALIFIER_METADATA_KEY: &str = "tt.qualifier";

use crate::irs::{
    nodes::{IsExprNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps},
    payloads::PayloadStructure,
};

pub struct ProverNode<B: SnarkBackend> {
    pub scope: std::sync::Weak<Node<B>>,
    pub parent: Option<std::sync::Weak<Node<B>>>,
    pub column: Column,
}

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "Column".to_string()
    }

    fn display(&self) -> String {
        format!(
            "Column\nScope: {}, column: {}",
            self.scope().name(),
            self.column
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
        vec![]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Helper: try to pull the requested column (and activator) from a tracked table.
        let try_build_subtable =
            |table: &arithmetic::table::TrackedTable<B>, column: &Column| -> Option<_> {
                let col_idx = tracked_table_index_of_column(table, column)?;
                Some(table.tracked_subtable_by_indices(&[col_idx]))
            };
        let scope = self
            .scope
            .upgrade()
            .expect("Column scope should be available during witness generation");
        // Fetch the scope payload to retrieve the tracked table.
        let scope_payload = virtualized_ir.payload_for_node(&scope.id());

        // First try the scope payload itself.
        if let Some(PayloadStructure::PlanPayload(table)) = scope_payload
            && let Some(subtable) = try_build_subtable(table, &self.column)
        {
            virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(subtable)));
            return Ok(());
        };

        let parent_name = self
            .parent
            .as_ref()
            .and_then(|weak_ref| weak_ref.upgrade())
            .map(|node| node.name())
            .unwrap_or_else(|| "<none>".to_string());

        panic!(
            "Column node could not find its column '{}' in scope node {:?} (parent={})",
            self.column.name(),
            scope.id(),
            parent_name,
        );
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
        // Project just this column and the activator from the scoped DataFrame.
        let scope = self
            .scope
            .upgrade()
            .expect("Column scope should be available during output");
        let scope_hint_df = match scope.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("Column scope cannot be a gadget node"),
        };

        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(scope_hint_df.data_frame().clone())
                .expect("column row-id sort should succeed");

        let mut exprs = vec![resolve_column_expr(input_df.schema(), &self.column)];
        if self.column.name() != ACTIVATOR_COL_NAME {
            crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut exprs);
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

fn resolve_column_expr(schema: &DFSchema, column: &Column) -> datafusion_expr::Expr {
    let name = column.name();
    if let Some(relation) = column.relation.as_ref() {
        if schema
            .iter()
            .any(|(qualifier, field)| field.name() == name && qualifier.as_ref() == Some(&relation))
        {
            return datafusion_expr::Expr::Column(column.clone());
        }
    }

    if let Some((qualifier, _)) = schema.iter().find(|(_, field)| field.name() == name) {
        return datafusion_expr::Expr::Column(Column::new(qualifier.cloned(), name));
    }

    datafusion_expr::Expr::Column(Column::new_unqualified(name))
}

// Resolve by qualifier metadata when present to disambiguate self-joins.
fn tracked_table_index_of_column<B: SnarkBackend>(
    table: &arithmetic::table::TrackedTable<B>,
    column: &Column,
) -> Option<usize> {
    let name = column.name();
    if let Some(relation) = column.relation.as_ref() {
        let relation_str = relation.to_string();
        if let Some((idx, _)) = table.tracked_polys().iter().enumerate().find(|(_, (field, _))| {
            field.name() == name
                && field
                    .metadata()
                    .get(QUALIFIER_METADATA_KEY)
                    .is_some_and(|q| q == &relation_str)
        }) {
            return Some(idx);
        }
    }
    table
        .tracked_polys()
        .iter()
        .position(|(field, _)| field.name() == name)
}

// Verifier-side version of qualifier-aware column lookup.
fn tracked_table_oracle_index_of_column<B: SnarkBackend>(
    table: &arithmetic::table_oracle::TrackedTableOracle<B>,
    column: &Column,
) -> Option<usize> {
    let name = column.name();
    if let Some(relation) = column.relation.as_ref() {
        let relation_str = relation.to_string();
        if let Some((idx, _)) = table
            .tracked_oracles()
            .iter()
            .enumerate()
            .find(|(_, (field, _))| {
                field.name() == name
                    && field
                        .metadata()
                        .get(QUALIFIER_METADATA_KEY)
                        .is_some_and(|q| q == &relation_str)
            })
        {
            return Some(idx);
        }
    }
    table
        .tracked_oracles()
        .iter()
        .position(|(field, _)| field.name() == name)
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Helper: try to pull the requested column (and activator) from a tracked table oracle.
        let try_build_subtable = |table: &arithmetic::table_oracle::TrackedTableOracle<B>,
                                  column: &Column| {
            let col_idx = tracked_table_oracle_index_of_column(table, column)?;
            Some(table.tracked_subtable_by_indices(&[col_idx]))
        };
        let scope = self
            .scope
            .upgrade()
            .expect("Column scope should be available during witness generation");
        // Fetch the scope payload to retrieve the tracked table oracle.
        let scope_payload = virtualized_ir.payload_for_node(&scope.id());

        // First try the scope payload itself.
        if let Some(PayloadStructure::PlanPayload(table)) = scope_payload
            && let Some(subtable) = try_build_subtable(table, &self.column)
        {
            virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(subtable)));
            return Ok(());
        };

        let parent_name = self
            .parent
            .as_ref()
            .and_then(|weak_ref| weak_ref.upgrade())
            .map(|node| node.name())
            .unwrap_or_else(|| "<none>".to_string());

        panic!(
            "Column node could not find its column '{}' in scope node {:?} (parent={})",
            self.column.name(),
            scope.id(),
            parent_name
        );
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
        _expr: datafusion_expr::Expr,
        _self_ref: std::sync::Weak<Node<B>>,
        parent: Option<std::sync::Weak<Node<B>>>,
        scope: std::sync::Weak<Node<B>>,
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
        self.scope
            .upgrade()
            .expect("Column scope should be available")
    }
}
