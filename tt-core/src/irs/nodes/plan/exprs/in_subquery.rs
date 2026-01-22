use std::sync::Arc;

use arithmetic::{ACTIVATOR_FIELD, ROW_ID_COL_NAME, is_system_column};
use ark_piop::SnarkBackend;
use datafusion::arrow::array::ArrayRef;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::prelude::DataFrame;
use datafusion_common::{Result as DataFusionResult, ScalarValue, Statistics};
use datafusion_expr::expr::{InList, InSubquery};
use datafusion_expr::{Expr, lit};
use indexmap::IndexMap;
use tokio::runtime::RuntimeFlavor;

use crate::irs::nodes::{
    IsExprNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
};
use crate::irs::payloads::PayloadStructure;
use crate::irs::tree::Tree;

pub struct ProverNode<B: SnarkBackend> {
    pub scope: Arc<Node<B>>,
    pub expr: Arc<Node<B>>,
    pub subquery: Arc<Node<B>>,
    pub parent: Option<std::sync::Weak<Node<B>>>,
    pub in_subquery: InSubquery,
}

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "InSubquery".to_string()
    }

    fn display(&self) -> String {
        format!(
            "InSubquery\nExpr: {}, subquery: {}",
            self.expr.name(),
            self.subquery.name()
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
        vec![self.expr.clone(), self.subquery.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let virtualized_ir = _virtualized_ir;
        let expr_table = match virtualized_ir.payload_for_node(&self.expr.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        let current_table = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

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
        let schema = Some(datafusion::arrow::datatypes::Schema::new_with_metadata(
            fields, metadata,
        ));

        let log_size = match (current_table.log_size(), expr_table.log_size()) {
            (0, other) => other,
            (curr, 0) => curr,
            (curr, expr) => {
                debug_assert_eq!(curr, expr, "InSubquery log sizes should agree");
                curr
            }
        };

        let updated_table = arithmetic::table::TrackedTable::new(schema, merged_polys, log_size);
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
}

impl<B: SnarkBackend> IsPlanNode<B> for ProverNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        None
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let scope_hint_df = match self.scope.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("InSubquery scope cannot be a gadget node"),
        };

        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(scope_hint_df.data_frame().clone())
                .expect("in-subquery row-id sort should succeed");

        fn collect_blocking(df: DataFrame) -> DataFusionResult<Vec<RecordBatch>> {
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => match handle.runtime_flavor() {
                    RuntimeFlavor::MultiThread => {
                        tokio::task::block_in_place(|| handle.block_on(df.collect()))
                    }
                    RuntimeFlavor::CurrentThread => {
                        let handle = handle.clone();
                        std::thread::spawn(move || handle.block_on(df.collect()))
                            .join()
                            .unwrap()
                    }
                    _ => handle.block_on(df.collect()),
                },
                Err(_) => tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(df.collect()),
            }
        }

        let in_expr = if self.in_subquery.subquery.outer_ref_columns.is_empty() {
            let (session_state, _) = input_df.clone().into_parts();
            let subquery_plan = self.in_subquery.subquery.subquery.as_ref().clone();
            let subquery_df = DataFrame::new(session_state, subquery_plan);
            let batches: Vec<datafusion::arrow::record_batch::RecordBatch> =
                collect_blocking(subquery_df).expect("in-subquery should collect subquery");
            let mut values = Vec::new();
            for batch in batches.iter() {
                let batch: &datafusion::arrow::record_batch::RecordBatch = batch;
                let array: datafusion::arrow::array::ArrayRef = batch.column(0).clone();
                for idx in 0..batch.num_rows() {
                    values.push(
                        ScalarValue::try_from_array(array.as_ref(), idx)
                            .expect("in-subquery should read subquery values"),
                    );
                }
            }
            if values.is_empty() {
                if self.in_subquery.negated {
                    lit(true)
                } else {
                    lit(false)
                }
            } else {
                Expr::InList(InList::new(
                    self.in_subquery.expr.clone(),
                    values.into_iter().map(Expr::Literal).collect(),
                    self.in_subquery.negated,
                ))
            }
        } else {
            Expr::InSubquery(self.in_subquery.clone())
        };

        let mut exprs = vec![in_expr];
        crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut exprs);
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);

        let projected = input_df
            .select(exprs)
            .expect("in-subquery projection should succeed");

        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("in-subquery output sort should succeed");
        let should_materialize = projected
            .schema()
            .fields()
            .iter()
            .map(|field| (field.clone(), !is_system_column(field.name())))
            .collect();
        crate::irs::nodes::hints::HintDF::new(projected, should_materialize)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let virtualized_ir = _virtualized_ir;
        let expr_table = match virtualized_ir.payload_for_node(&self.expr.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        let current_table = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        let mut merged_oracles = IndexMap::new();
        if let Some((data_field, data_oracle)) = current_table
            .tracked_oracles_iter()
            .find(|(field, _)| !is_system_column(field.name()))
        {
            merged_oracles.insert(data_field.clone(), data_oracle.clone());
        }
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
        let schema = Some(datafusion::arrow::datatypes::Schema::new_with_metadata(
            fields, metadata,
        ));

        let log_size = match (current_table.log_size(), expr_table.log_size()) {
            (0, other) => other,
            (curr, 0) => curr,
            (curr, expr) => {
                debug_assert_eq!(curr, expr, "InSubquery log sizes should agree");
                curr
            }
        };

        let updated_table =
            arithmetic::table_oracle::TrackedTableOracle::new(schema, merged_oracles, log_size);
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
        let in_subquery = match expr {
            datafusion_expr::Expr::InSubquery(expr) => expr,
            _ => panic!("Expected InSubquery expression"),
        };

        let expr_node =
            Tree::<B>::from_expr(&in_subquery.expr, Some(self_ref.clone()), scope.clone())
                .root()
                .clone();
        let subquery_node = Tree::<B>::from_logical_plan(&in_subquery.subquery.subquery)
            .root()
            .clone();

        Self {
            in_subquery,
            expr: expr_node,
            subquery: subquery_node,
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
                Node::Gadget(_) => panic!("InSubquery parent cannot be a gadget node"),
            })
            .expect("InSubquery node must have a parent")
    }

    fn scope(&self) -> std::sync::Arc<Node<B>>
    where
        Self: Sized,
    {
        self.scope.clone()
    }
}
