use std::sync::Arc;

use arithmetic::table::TrackedTable;
use arithmetic::table_oracle::TrackedTableOracle;
use arithmetic::{ACTIVATOR_FIELD, ROW_ID_COL_NAME, is_system_column};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use datafusion_common::Statistics;
use datafusion_expr::Expr;
use datafusion_expr::ExprSchemable;
use datafusion_expr::expr::InList;
use indexmap::IndexMap;

use crate::irs::nodes::{
    IsExprNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
};
use crate::irs::payloads::PayloadStructure;
use crate::irs::tree::Tree;

pub struct ExprNode<B: SnarkBackend> {
    pub scope: Vec<std::sync::Weak<Node<B>>>,
    pub expr: Arc<Node<B>>,
    pub list: Vec<Arc<Node<B>>>,
    pub parent: Option<std::sync::Weak<Node<B>>>,
    pub in_list: InList,
}

impl<B: SnarkBackend> IsNode<B> for ExprNode<B> {
    fn name(&self) -> String {
        "InList".to_string()
    }

    fn display(&self) -> String {
        format!(
            "InList\nInput: {}, List Length: {}",
            self.expr.name(),
            self.list.len()
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
        id: NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let expr_table = match virtualized_ir.payload_for_node(&self.expr.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        let current_table = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        // Keep only the IN-list result data column, then append system columns from the input.
        let mut merged_polys = IndexMap::new();
        if let Some((data_field, data_poly)) = current_table
            .tracked_polys_iter()
            .find(|(field, _)| !is_system_column(field.name()))
        {
            merged_polys.insert(data_field.clone(), data_poly.clone());
        }
        if let Some((row_id_field, row_id_poly)) = expr_table
            .tracked_polys_iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
        {
            merged_polys
                .entry(row_id_field.clone())
                .or_insert_with(|| row_id_poly.clone());
        }
        if let Some(activator) = expr_table.activator_tracked_poly() {
            // Reuse the input activator so the IN-list result stays aligned.
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
                debug_assert_eq!(curr, expr, "InList log sizes should agree");
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
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
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
        // Produce a DataFrame with the IN-list result and scope metadata.
        let scope = self.scope[0]
            .upgrade()
            .expect("InList scope should be available during output");
        let scope_hint_df = match scope.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsProverPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("InList scope cannot be a gadget node"),
        };

        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(scope_hint_df.data_frame().clone())
                .expect("in-list row-id sort should succeed");

        let mut exprs = vec![Expr::InList(self.in_list.clone())];
        crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut exprs);
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);

        let projected = input_df
            .select(exprs)
            .expect("in-list projection should succeed");

        let should_materialize: IndexMap<FieldRef, bool> = projected
            .schema()
            .fields()
            .iter()
            .map(|field| {
                let mat = !is_system_column(field.name());
                (field.clone(), mat)
            })
            .collect();

        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("in-list output sort should succeed");
        crate::irs::nodes::hints::HintDF::new(projected, should_materialize)
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for ExprNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        // Produce a DataFrame with the IN-list result and scope metadata.
        let scope = self.scope[0]
            .upgrade()
            .expect("InList scope should be available during output");
        let scope_hint_df = match scope.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("InList scope cannot be a gadget node"),
        };

        // Verifier planning only needs output schema/materialization metadata.
        // Avoid DataFusion projection execution for in-list expressions.
        let input_schema = scope_hint_df.data_frame().schema().as_arrow();
        let in_list_expr = Expr::InList(self.in_list.clone());
        let output_name = in_list_expr.schema_name().to_string();
        let output_type = in_list_expr
            .get_type(scope_hint_df.data_frame().schema())
            .unwrap_or(DataType::Boolean);
        let mut fields = vec![Field::new(output_name, output_type, true)];
        fields.extend(
            input_schema
                .fields()
                .iter()
                .filter(|field| field.name() == ROW_ID_COL_NAME)
                .map(|field| field.as_ref().clone()),
        );
        fields.extend(
            input_schema
                .fields()
                .iter()
                .filter(|field| field.name() == arithmetic::ACTIVATOR_COL_NAME)
                .map(|field| field.as_ref().clone()),
        );
        let projected = crate::irs::nodes::hints::schema_only_df(fields);

        let should_materialize: IndexMap<FieldRef, bool> = projected
            .schema()
            .fields()
            .iter()
            .map(|field| {
                let mat = !is_system_column(field.name());
                (field.clone(), mat)
            })
            .collect();

        crate::irs::nodes::hints::HintDF::new(projected, should_materialize)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ExprNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let (expr_row_id_entry, expr_activator, expr_log_size, expr_metadata) =
            match virtualized_ir.payload_for_node(&self.expr.id()) {
                Some(PayloadStructure::PlanPayload(table)) => {
                    let row_id = table
                        .tracked_oracles_iter()
                        .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
                        .map(|(field, oracle)| (field.clone(), oracle.clone()));
                    (
                        row_id,
                        table.activator_tracked_poly(),
                        table.log_size(),
                        table.schema_ref().map(|s| s.metadata().clone()),
                    )
                }
                _ => return Ok(()),
            };
        let (data_col_entry, current_log_size, current_metadata) =
            match virtualized_ir.payload_for_node(&id) {
                Some(PayloadStructure::PlanPayload(table)) => {
                    let data_entry = table
                        .tracked_oracles_iter()
                        .find(|(field, _)| !is_system_column(field.name()))
                        .map(|(field, oracle)| (field.clone(), oracle.clone()));
                    (
                        data_entry,
                        table.log_size(),
                        table.schema_ref().map(|s| s.metadata().clone()),
                    )
                }
                _ => return Ok(()),
            };

        // Keep only the IN-list result data column, then append system columns from the input.
        let mut merged_oracles = IndexMap::new();
        if let Some((data_field, data_oracle)) = data_col_entry {
            merged_oracles.insert(data_field, data_oracle);
        }
        if let Some((row_id_field, row_id_oracle)) = expr_row_id_entry {
            merged_oracles.entry(row_id_field).or_insert(row_id_oracle);
        }
        if let Some(activator) = expr_activator {
            // Reuse the input activator so the IN-list result stays aligned.
            merged_oracles.insert(ACTIVATOR_FIELD.clone(), activator);
        }

        let metadata = current_metadata.or(expr_metadata).unwrap_or_default();
        let fields = merged_oracles
            .keys()
            .map(|f| f.as_ref().clone())
            .collect::<Vec<_>>();
        let schema = Some(Schema::new_with_metadata(fields, metadata));

        let log_size = match (current_log_size, expr_log_size) {
            (0, other) => other,
            (curr, 0) => curr,
            (curr, expr) => {
                debug_assert_eq!(curr, expr, "InList log sizes should agree");
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

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
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
        let in_list = match expr {
            datafusion_expr::Expr::InList(col) => col,
            _ => panic!("Expected Cast expression"),
        };

        let expr_node = Tree::<B>::from_expr(&in_list.expr, Some(self_ref.clone()), scope.clone())
            .root()
            .clone();

        let list_nodes = in_list
            .list
            .iter()
            .map(|expr| {
                Tree::<B>::from_expr(expr, Some(self_ref.clone()), scope.clone())
                    .root()
                    .clone()
            })
            .collect();

        Self {
            in_list,
            expr: expr_node,
            scope,
            parent,
            list: list_nodes,
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
