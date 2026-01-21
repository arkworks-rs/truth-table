use std::sync::Arc;

use arithmetic::table::TrackedTable;
use arithmetic::table_oracle::TrackedTableOracle;
use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, ROW_ID_COL_NAME};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::Schema;
use datafusion_common::Statistics;
use datafusion_expr::Cast;

use crate::irs::nodes::{
    IsExprNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
};
use crate::irs::payloads::PayloadStructure;
use crate::irs::tree::Tree;

pub struct ProverNode<B: SnarkBackend> {
    pub scope: Arc<Node<B>>,
    pub expr: Arc<Node<B>>,
    pub parent: Option<std::sync::Weak<Node<B>>>,
    pub cast: Cast,
}

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "Cast".to_string()
    }

    fn display(&self) -> String {
        format!(
            "Cast\nInput: {}, data_type: {:?}",
            self.expr.name(),
            self.cast.data_type
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
        // The cast output already carries a materialized data column; copy the activator
        // from the expression child so the table matches the child scope.
        let expr_id = self.expr.id();
        let expr_table = match virtualized_ir.payload_for_node(&expr_id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        let current_table = virtualized_ir
            .payload_for_node(&id)
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(table.clone()),
                _ => None,
            })
            .unwrap_or_default();

        let mut merged_polys = current_table.tracked_polys();
        if let Some((row_id_field, row_id_poly)) = expr_table
            .tracked_polys_iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
        {
            merged_polys
                .entry(row_id_field.clone())
                .or_insert_with(|| row_id_poly.clone());
        }
        if let Some(activator) = expr_table.activator_tracked_poly() {
            merged_polys.insert(ACTIVATOR_FIELD.clone(), activator);
        }

        let metadata = current_table
            .schema_ref()
            .map(|s| s.metadata().clone())
            .or_else(|| expr_table.schema_ref().map(|s| s.metadata().clone()))
            .unwrap_or_default();
        let fields = merged_polys
            .keys()
            .map(|f| f.as_ref().clone())
            .collect::<Vec<_>>();
        let schema = Some(Schema::new_with_metadata(fields, metadata));

        let log_size = match (current_table.log_size(), expr_table.log_size()) {
            (0, other) => other,
            (curr, 0) => curr,
            (curr, expr) => {
                debug_assert_eq!(curr, expr, "Cast log sizes should agree");
                curr
            }
        };

        let updated_table = TrackedTable::new(schema, merged_polys, log_size);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ProverNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        None
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let scope_hint_df = match self.scope.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("Cast scope cannot be a gadget node"),
        };

        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(scope_hint_df.data_frame().clone())
                .expect("cast row-id sort should succeed");

        let mut exprs = vec![datafusion_expr::Expr::Cast(self.cast.clone())];
        crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut exprs);
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);
        let projected = input_df
            .select(exprs)
            .expect("cast projection should succeed");

        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("cast output sort should succeed");
        // Only materialize the casted data column; keep activator/row_id virtual.
        let should_materialize = projected
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

impl<B: SnarkBackend> VerifierNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // The cast output already carries a materialized data column; copy the activator
        // from the expression child so the table matches the child scope.
        let expr_id = self.expr.id();
        let expr_table = match virtualized_ir.payload_for_node(&expr_id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        let current_table = virtualized_ir
            .payload_for_node(&id)
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(table.clone()),
                _ => None,
            })
            .unwrap_or_default();

        let mut merged_oracles = current_table.tracked_oracles();
        if let Some((row_id_field, row_id_oracle)) = expr_table
            .tracked_oracles_iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
        {
            merged_oracles
                .entry(row_id_field.clone())
                .or_insert_with(|| row_id_oracle.clone());
        }
        if let Some(activator) = expr_table.activator_tracked_poly() {
            merged_oracles.insert(ACTIVATOR_FIELD.clone(), activator);
        }

        let metadata = current_table
            .schema_ref()
            .map(|s| s.metadata().clone())
            .or_else(|| expr_table.schema_ref().map(|s| s.metadata().clone()))
            .unwrap_or_default();
        let fields = merged_oracles
            .keys()
            .map(|f| f.as_ref().clone())
            .collect::<Vec<_>>();
        let schema = Some(Schema::new_with_metadata(fields, metadata));

        let log_size = match (current_table.log_size(), expr_table.log_size()) {
            (0, other) => other,
            (curr, 0) => curr,
            (curr, expr) => {
                debug_assert_eq!(curr, expr, "Cast log sizes should agree");
                curr
            }
        };

        let updated_table = TrackedTableOracle::new(schema, merged_oracles, log_size);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
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
        scope: std::sync::Arc<Node<B>>,
    ) -> Self
    where
        Self: Sized,
    {
        let cast = match expr {
            datafusion_expr::Expr::Cast(col) => col,
            _ => panic!("Expected Cast expression"),
        };

        let expr_node = Tree::<B>::from_expr(&cast.expr, Some(self_ref.clone()), scope.clone())
            .root()
            .clone();

        Self {
            cast,
            expr: expr_node,
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

    fn scope(&self) -> std::sync::Arc<Node<B>>
    where
        Self: Sized,
    {
        self.scope.clone()
    }
}
