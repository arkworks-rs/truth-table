use crate::{
    proof_nodes::{
        OUTPUT_PLAN_KEY, cost::ProvingCost, id::NodeId, prover::ProverNode, verifier::VerifierNode,
    },
    prover::trees::{piop_tree::ProverPIOPTree, proof_tree::ProverProofTree},
    verifier::trees::{piop_tree::VerifierPIOPTree, proof_tree::VerifierProofTree},
};
use arithmetic::{
    ACTIVATOR_COL_NAME, ctx::SharedCtx, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    verifier::structs::oracle::TrackedOracle,
};
use datafusion::{
    arrow::datatypes::{FieldRef, SchemaRef},
    logical_expr::{Expr, LogicalPlan, LogicalPlanBuilder},
    prelude::{SessionContext, col},
};
use indexmap::IndexMap;
use std::sync::Arc;
#[derive(Clone)]
pub struct ProverColumnExprNode {
    pub parent_node_id: NodeId,
    pub node_id: NodeId,
}
#[derive(Clone)]
pub struct VerifierColumnExprNode {
    pub parent_node_id: NodeId,
    pub node_id: NodeId,
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for ProverColumnExprNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn hint_generation_plans(
        &self,
        proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, (LogicalPlan, bool)> {
        let column_expr = match &self.node_id {
            NodeId::Expr(Expr::Column(column)) => column.clone(),
            _ => return IndexMap::new(),
        };

        let base_entry = column_expr
            .relation
            .as_ref()
            .and_then(|relation| {
                proof_tree
                    .proof_nodes()
                    .iter()
                    .find_map(|(node_id, node)| match node_id {
                        NodeId::LP(LogicalPlan::TableScan(scan_plan))
                            if &scan_plan.table_name == relation =>
                        {
                            node.hint_generation_plans(proof_tree)
                                .get(OUTPUT_PLAN_KEY)
                                .cloned()
                        },
                        _ => None,
                    })
            })
            .or_else(|| {
                proof_tree.node(&self.parent_node_id).and_then(|parent| {
                    parent
                        .hint_generation_plans(proof_tree)
                        .get(OUTPUT_PLAN_KEY)
                        .cloned()
                })
            });
        let (base_plan, _) = match base_entry {
            Some(entry) => entry,
            None => return IndexMap::new(),
        };

        let mut projection_exprs = vec![Expr::Column(column_expr)];
        if base_plan
            .schema()
            .field_with_unqualified_name(ACTIVATOR_COL_NAME)
            .is_ok()
        {
            projection_exprs.push(col(ACTIVATOR_COL_NAME));
        }

        let output_plan = LogicalPlanBuilder::from(base_plan)
            .project(projection_exprs)
            .unwrap()
            .build()
            .unwrap();

        IndexMap::from([(OUTPUT_PLAN_KEY.to_string(), (output_plan, false))])
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn from_expr(
        _ctx: &SessionContext,
        _prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        Self {
            node_id: NodeId::Expr(expr),
            parent_node_id,
        }
    }

    fn cost(
        &self,
        _statistics: datafusion::common::Statistics,
        _schema: datafusion::arrow::datatypes::SchemaRef,
    ) -> ProvingCost {
        todo!()
    }

    fn ctx_schema(&self, proof_tree: &ProverProofTree<F, MvPCS, UvPCS>) -> SchemaRef {
        proof_tree
            .node(&self.parent_node_id)
            .unwrap()
            .ctx_schema(proof_tree)
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
        // Fetch the columns expression
        let column_expr = match &self.node_id {
            NodeId::Expr(Expr::Column(column)) => column,
            _ => todo!(),
        };
        let table = if let Some(relation) = column_expr.relation.as_ref() {
            piop_tree
                .tracked_tables()
                .iter()
                .find_map(|(node_id, tables)| match node_id {
                    NodeId::LP(LogicalPlan::TableScan(scan_plan))
                        if &scan_plan.table_name == relation =>
                    {
                        tables.get(OUTPUT_PLAN_KEY)
                    },
                    _ => None,
                })
                .expect("table scan not found for relation")
        } else {
            let ctx_schema = self.ctx_schema(piop_tree.proof_tree());
            dbg!(ctx_schema.as_ref());
            dbg!(&piop_tree.tracked_tables());
            piop_tree
                .tracked_tables()
                .values()
                .find_map(|tables| {
                    tables.values().find(|table| {
                        table
                            .schema()
                            .as_ref()
                            .map(|schema| schema == ctx_schema.as_ref())
                            .unwrap_or(false)
                    })
                })
                .expect("table not found matching column context schema")
        };
        dbg!(table.tracked_polys());
        dbg!(&column_expr.name);
        let col = table
            .tracked_col_by_name(&column_expr.name)
            .expect("column not found in table");
        // TODO: Clean this up later
        let mut tracked_polys: IndexMap<
            Arc<datafusion::arrow::datatypes::Field>,
            ark_piop::prover::structs::polynomial::TrackedPoly<F, MvPCS, UvPCS>,
        > = IndexMap::from([(
            col.field_ref()
                .expect("Column data type should not be None")
                .clone(),
            col.data_tracked_poly().clone(),
        )]);
        tracked_polys.insert(
            Arc::new(datafusion::arrow::datatypes::Field::new(
                ACTIVATOR_COL_NAME,
                datafusion::arrow::datatypes::DataType::UInt8,
                true,
            )),
            col.activator_tracked_poly()
                .expect("Column activator polynomial should not be None")
                .clone(),
        );
        let output_table = TrackedTable::new(None, tracked_polys, table.log_size());

        piop_tree.add_table(
            self.node_id.clone(),
            OUTPUT_PLAN_KEY.to_owned(),
            output_table,
        );
    }
    fn prove_piop(
        &self,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        // No need to invoke a piop for column expressions
        Ok(())
    }
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for VerifierColumnExprNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn hint_generation_plans(
        &self,
        proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, (LogicalPlan, bool)> {
        let column_expr = match &self.node_id {
            NodeId::Expr(Expr::Column(column)) => column.clone(),
            _ => return IndexMap::new(),
        };

        let base_entry = column_expr
            .relation
            .as_ref()
            .and_then(|relation| {
                proof_tree
                    .proof_nodes()
                    .iter()
                    .find_map(|(node_id, node)| match node_id {
                        NodeId::LP(LogicalPlan::TableScan(scan_plan))
                            if &scan_plan.table_name == relation =>
                        {
                            node.hint_generation_plans(proof_tree)
                                .get(OUTPUT_PLAN_KEY)
                                .cloned()
                        },
                        _ => None,
                    })
            })
            .or_else(|| {
                proof_tree.node(&self.parent_node_id).and_then(|parent| {
                    parent
                        .hint_generation_plans(proof_tree)
                        .get(OUTPUT_PLAN_KEY)
                        .cloned()
                })
            });
        let (base_plan, _) = match base_entry {
            Some(entry) => entry,
            None => return IndexMap::new(),
        };

        let mut projection_exprs = vec![Expr::Column(column_expr)];
        if base_plan
            .schema()
            .field_with_unqualified_name(ACTIVATOR_COL_NAME)
            .is_ok()
        {
            projection_exprs.push(col(ACTIVATOR_COL_NAME));
        }

        let output_plan = LogicalPlanBuilder::from(base_plan)
            .project(projection_exprs)
            .unwrap()
            .build()
            .unwrap();

        IndexMap::from([(OUTPUT_PLAN_KEY.to_string(), (output_plan, false))])
    }
    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn from_expr(
        _ctx: &SessionContext,
        _verifier_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        Self {
            node_id: NodeId::Expr(expr),
            parent_node_id,
        }
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
        // Fetch the columns expression
        let column_expr = match &self.node_id {
            NodeId::Expr(Expr::Column(column)) => column,
            _ => todo!(),
        };
        let table = if let Some(relation) = column_expr.relation.as_ref() {
            piop_tree
                .tracked_table_oracles()
                .iter()
                .find_map(|(node_id, tables)| match node_id {
                    NodeId::LP(LogicalPlan::TableScan(scan_plan))
                        if &scan_plan.table_name == relation =>
                    {
                        tables.get(OUTPUT_PLAN_KEY)
                    },
                    _ => None,
                })
                .expect("table scan not found for relation")
        } else {
            let ctx_schema = self.ctx_schema(piop_tree.proof_tree());
            piop_tree
                .tracked_table_oracles()
                .values()
                .find_map(|tables| {
                    tables.values().find(|table| {
                        table
                            .schema()
                            .as_ref()
                            .map(|schema| schema == ctx_schema.as_ref())
                            .unwrap_or(false)
                    })
                })
                .expect("table not found matching column context schema")
        };
        let col = table
            .tracked_col_oracle_by_name(&column_expr.name)
            .expect("column not found in table");
        let mut tracked_polys: IndexMap<FieldRef, TrackedOracle<F, MvPCS, UvPCS>> = IndexMap::new();
        let data_field = col.field_ref().clone().unwrap();
        tracked_polys.insert(data_field, col.data_tracked_oracle().clone());

        let activator_field: FieldRef = Arc::new(datafusion::arrow::datatypes::Field::new(
            ACTIVATOR_COL_NAME,
            datafusion::arrow::datatypes::DataType::UInt8,
            true,
        ));
        tracked_polys.insert(
            activator_field,
            col.activator_tracked_oracle()
                .expect("Column activator polynomial should not be None")
                .clone(),
        );

        let output_table = TrackedTableOracle::new(None, tracked_polys, table.log_size());

        piop_tree.add_tracked_table_oracle(
            self.node_id.clone(),
            OUTPUT_PLAN_KEY.to_owned(),
            output_table,
        );
    }
    fn verify_piop(
        &self,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        // No need to invoke a piop for column expressions
        Ok(())
    }

    fn ctx_schema(&self, proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>) -> SchemaRef {
        proof_tree
            .node(&self.parent_node_id)
            .unwrap()
            .ctx_schema(proof_tree)
    }
}
