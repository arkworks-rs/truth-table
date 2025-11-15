use crate::{
    proof_nodes::{
        HintGenerationPlan, OUTPUT_PLAN_KEY, cost::ProvingCost, id::NodeId, prover::{ProverExprNode, ProverNode},
        verifier::VerifierNode,
    },
    prover::trees::{piop_tree::ProverPIOPTree, proof_tree::ProverProofTree},
    verifier::trees::{piop_tree::VerifierPIOPTree, proof_tree::VerifierProofTree},
};
use arithmetic::{
    ACTIVATOR_COL_NAME, col::TrackedCol, col_oracle::TrackedColOracle, ctx::SharedCtx,
    table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    verifier::structs::oracle::TrackedOracle,
};
use datafusion::{
    arrow::datatypes::FieldRef,
    logical_expr::{Expr, LogicalPlan, LogicalPlanBuilder},
    prelude::SessionContext,
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
/// Human-friendly detail string for a column expression, including its table
/// reference when present.
pub fn format_column_detail(column: &datafusion::common::Column) -> String {
    match column.relation.as_ref() {
        Some(relation) => format!("{} (table_ref = {})", column.flat_name(), relation),
        None => column.flat_name(),
    }
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
    ) -> IndexMap<String, HintGenerationPlan> {
        let column_expr = match &self.node_id {
            NodeId::Expr(Expr::Column(column)) => column.clone(),
            _ => return IndexMap::new(),
        };

        let base_entry = column_expr
            .relation
            .as_ref()
            .and_then(|relation| {
                proof_tree
                    .arena()
                    .iter()
                    .find_map(|(node_id, node)| match node_id {
                        NodeId::LP(LogicalPlan::TableScan(scan_plan))
                            if relation.resolved_eq(&scan_plan.table_name) =>
                        {
                            node.hint_generation_plans(proof_tree)
                                .get(OUTPUT_PLAN_KEY)
                                .cloned()
                        }
                        NodeId::LP(LogicalPlan::SubqueryAlias(alias_plan))
                            if relation.resolved_eq(&alias_plan.alias) =>
                        {
                            node.hint_generation_plans(proof_tree)
                                .get(OUTPUT_PLAN_KEY)
                                .cloned()
                        }
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
        let base_plan = match base_entry {
            Some(entry) => entry.plan().clone(),
            None => return IndexMap::new(),
        };

        let projection_exprs = vec![Expr::Column(column_expr.clone())];

        let output_plan = LogicalPlanBuilder::from(base_plan.clone())
            .project(projection_exprs)
            .unwrap()
            .build()
            .unwrap();

        IndexMap::from([(
            OUTPUT_PLAN_KEY.to_string(),
            HintGenerationPlan::new_virtual(OUTPUT_PLAN_KEY.to_string(), output_plan),
        )])
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        Vec::new()
    }


    fn cost(
        &self,
        _statistics: datafusion::common::Statistics,
        _schema: datafusion::arrow::datatypes::SchemaRef,
    ) -> ProvingCost {
        todo!()
    }

    fn ctx_lp_node(
        &self,
        proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverNode<F, MvPCS, UvPCS>> {
        proof_tree
            .node(&self.parent_node_id)
            .unwrap()
            .ctx_lp_node(proof_tree)
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

        let col = self.resolve_col(column_expr, piop_tree);
        let mut tracked_polys: IndexMap<
            Arc<datafusion::arrow::datatypes::Field>,
            ark_piop::prover::structs::polynomial::TrackedPoly<F, MvPCS, UvPCS>,
        > = IndexMap::new();
        tracked_polys.insert(
            col.field_ref()
                .expect("Column data type should not be None"),
            col.data_tracked_poly(),
        );

        tracked_polys.insert(
            Arc::new(datafusion::arrow::datatypes::Field::new(
                ACTIVATOR_COL_NAME,
                datafusion::arrow::datatypes::DataType::UInt8,
                true,
            )),
            col.activator_tracked_poly()
                .expect("Column activator polynomial should not be None"),
        );
        let output_table = TrackedTable::new(None, tracked_polys, col.log_size());

        piop_tree.add_table(
            self.node_id.clone(),
            OUTPUT_PLAN_KEY.to_owned(),
            output_table,
        );
    }
}

impl<F, MvPCS, UvPCS> ProverExprNode<F, MvPCS, UvPCS> for ProverColumnExprNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
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
    ) -> IndexMap<String, HintGenerationPlan> {
        let column_expr = match &self.node_id {
            NodeId::Expr(Expr::Column(column)) => column.clone(),
            _ => return IndexMap::new(),
        };

        let base_entry = column_expr
            .relation
            .as_ref()
            .and_then(|relation| {
                proof_tree
                    .arena()
                    .iter()
                    .find_map(|(node_id, node)| match node_id {
                        NodeId::LP(LogicalPlan::TableScan(scan_plan))
                            if relation.resolved_eq(&scan_plan.table_name) =>
                        {
                            node.hint_generation_plans(proof_tree)
                                .get(OUTPUT_PLAN_KEY)
                                .cloned()
                        }
                        NodeId::LP(LogicalPlan::SubqueryAlias(alias_plan))
                            if relation.resolved_eq(&alias_plan.alias) =>
                        {
                            node.hint_generation_plans(proof_tree)
                                .get(OUTPUT_PLAN_KEY)
                                .cloned()
                        }
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
        let base_plan = match base_entry {
            Some(entry) => entry.plan().clone(),
            None => return IndexMap::new(),
        };

        let projection_exprs = vec![Expr::Column(column_expr.clone())];

        let output_plan = LogicalPlanBuilder::from(base_plan)
            .project(projection_exprs)
            .unwrap()
            .build()
            .unwrap();

        IndexMap::from([(
            OUTPUT_PLAN_KEY.to_string(),
            HintGenerationPlan::new_virtual(OUTPUT_PLAN_KEY.to_string(), output_plan),
        )])
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
        let col = self.resolve_col_oracle(column_expr, piop_tree);
        let mut tracked_polys: IndexMap<FieldRef, TrackedOracle<F, MvPCS, UvPCS>> = IndexMap::new();
        tracked_polys.insert(
            col.field_ref()
                .expect("Column data type should not be None"),
            col.data_tracked_oracle(),
        );

        let activator_field: FieldRef = Arc::new(datafusion::arrow::datatypes::Field::new(
            ACTIVATOR_COL_NAME,
            datafusion::arrow::datatypes::DataType::UInt8,
            true,
        ));
        tracked_polys.insert(
            activator_field,
            col.activator_tracked_oracle()
                .expect("Column activator polynomial should not be None"),
        );

        let output_table = TrackedTableOracle::new(None, tracked_polys, col.log_size());

        piop_tree.add_tracked_table_oracle(
            self.node_id.clone(),
            OUTPUT_PLAN_KEY.to_owned(),
            output_table,
        );
    }

    fn ctx_lp_node(
        &self,
        proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>> {
        proof_tree
            .node(&self.parent_node_id)
            .unwrap()
            .ctx_lp_node(proof_tree)
    }
}

impl ProverColumnExprNode {
    fn resolve_col<F, MvPCS, UvPCS>(
        &self,
        column_expr: &datafusion::common::Column,
        piop_tree: &ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> TrackedCol<F, MvPCS, UvPCS>
    where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>> + 'static,
        UvPCS: PCS<F, Poly = LDE<F>> + 'static,
    {
        let ctx_lp_node = self.ctx_lp_node(piop_tree.proof_tree());
        if let Some(table) = piop_tree.tracked_table(&ctx_lp_node.node_id(), OUTPUT_PLAN_KEY)
            && let Some(col) = table.tracked_col_by_name(&column_expr.name)
        {
            return col;
        }

        if let Some(relation) = &column_expr.relation {
            for (node_id, _) in piop_tree.proof_tree().arena().iter() {
                let matches_reference = match node_id {
                    NodeId::LP(LogicalPlan::TableScan(scan_plan)) => {
                        relation.resolved_eq(&scan_plan.table_name)
                    }
                    NodeId::LP(LogicalPlan::SubqueryAlias(alias_plan)) => {
                        relation.resolved_eq(&alias_plan.alias)
                    }
                    _ => false,
                };

                if !matches_reference {
                    continue;
                }

                if let Some(table) = piop_tree.tracked_table(node_id, OUTPUT_PLAN_KEY)
                    && let Some(col) = table.tracked_col_by_name(&column_expr.name)
                {
                    return col;
                }
            }
        }

        panic!(
            "column {} not found in execution context",
            format_column_detail(column_expr)
        );
    }
}

impl VerifierColumnExprNode {
    fn resolve_col_oracle<F, MvPCS, UvPCS>(
        &self,
        column_expr: &datafusion::common::Column,
        piop_tree: &VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> TrackedColOracle<F, MvPCS, UvPCS>
    where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>> + 'static,
        UvPCS: PCS<F, Poly = LDE<F>> + 'static,
    {
        let ctx_lp_node = self.ctx_lp_node(piop_tree.proof_tree());
        if let Some(table) = piop_tree.tracked_table_oracle(&ctx_lp_node.node_id(), OUTPUT_PLAN_KEY)
            && let Some(col) = table.tracked_col_oracle_by_name(&column_expr.name)
        {
            return col;
        }

        if let Some(relation) = &column_expr.relation {
            for (node_id, _) in piop_tree.proof_tree().arena().iter() {
                let matches_reference = match node_id {
                    NodeId::LP(LogicalPlan::TableScan(scan_plan)) => {
                        relation.resolved_eq(&scan_plan.table_name)
                    }
                    NodeId::LP(LogicalPlan::SubqueryAlias(alias_plan)) => {
                        relation.resolved_eq(&alias_plan.alias)
                    }
                    _ => false,
                };

                if !matches_reference {
                    continue;
                }

                if let Some(table) = piop_tree.tracked_table_oracle(node_id, OUTPUT_PLAN_KEY)
                    && let Some(col) = table.tracked_col_oracle_by_name(&column_expr.name)
                {
                    return col;
                }
            }
        }

        panic!(
            "column {} not found in execution context",
            format_column_detail(column_expr)
        );
    }
}
