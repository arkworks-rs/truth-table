// Combined dbsnark-core/src/prover/nodes/exprs/literal.rs and
// dbsnark-core/src/verifier/nodes/exprs/literal.rs

use crate::{
    proof_nodes::{
        OUTPUT_PLAN_KEY, cost::ProvingCost, id::NodeId, prover::ProverNode, verifier::VerifierNode,
    },
    prover::trees::{piop_tree::ProverPIOPTree, proof_tree::ProverProofTree},
    verifier::trees::{piop_tree::VerifierPIOPTree, proof_tree::VerifierProofTree},
};
use arithmetic::{
    ACTIVATOR_COL_NAME, ctx::SharedCtx, encoding::encode_arrow_array_to_field, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    prover::Prover,
    verifier::Verifier,
};
use datafusion::{
    arrow::datatypes::{Field, Schema, SchemaRef},
    common::Statistics,
    logical_expr::{Expr, LogicalPlan, LogicalPlanBuilder},
    prelude::SessionContext,
};
use indexmap::IndexMap;
use std::sync::Arc;
#[derive(Clone)]
pub struct ProverLiteralExprNode {
    pub node_id: NodeId,
    pub parent_node_id: NodeId,
}

#[derive(Clone)]
pub struct VerifierLiteralExprNode {
    pub node_id: NodeId,
    pub parent_node_id: NodeId,
}
impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for ProverLiteralExprNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(
        &self,
        proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, (LogicalPlan, bool)> {
        let literal_expr = match &self.node_id {
            NodeId::Expr(expr @ Expr::Literal(_)) => expr.clone(),
            _ => return IndexMap::new(),
        };

        let (base_plan, _) = if let Some(entry) = first_tablescan_plan_prover(proof_tree) {
            entry
        } else {
            panic!("no tablescan plan found");
        };

        let literal_plan = LogicalPlanBuilder::from(base_plan)
            .project(vec![literal_expr.alias("literal")])
            .unwrap()
            .build()
            .unwrap();

        IndexMap::from([(OUTPUT_PLAN_KEY.to_string(), (literal_plan, false))])
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

    fn cost(&self, _statistics: Statistics, _schema: SchemaRef) -> ProvingCost {
        todo!()
    }

    fn ctx_schema(
        &self,
        proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> SchemaRef {
        proof_tree
            .node(&self.parent_node_id)
            .unwrap()
            .ctx_schema(proof_tree)
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
        prover: &mut Prover<F, MvPCS, UvPCS>,
    ) {
        let scalar = match &self.node_id {
            NodeId::Expr(Expr::Literal(value)) => value.clone(),
            _ => panic!("literal node expected literal expression"),
        };

        let array = scalar
            .to_array()
            .expect("failed to convert scalar into arrow array");

        let mut column_values = encode_arrow_array_to_field::<F>(&array)
            .expect("failed to encode literal into field elements")
            .into_iter()
            .next()
            .unwrap_or_else(|| vec![F::zero()]);

        if column_values.len() > 1 {
            panic!("literal encoding resulted in multiple field elements");
        }

        let constant_value = column_values.pop().unwrap_or_else(F::zero);

        let tracked_poly = prover.track_mat_mv_cnst_poly(0, constant_value);

        let data_type = scalar.data_type();

        let schema = Schema::new(vec![Field::new(
            "literal",
            data_type.clone(),
            scalar.is_null(),
        )]);

        let table = TrackedTable::new(
            Some(schema),
            IndexMap::from([(
                Arc::new(Field::new("literal", data_type, scalar.is_null())),
                tracked_poly,
            )]),
            0,
        );

        piop_tree.add_table(self.node_id.clone(), OUTPUT_PLAN_KEY.to_owned(), table);
    }
    fn prove_piop(
        &self,
        _prover: &mut Prover<F, MvPCS, UvPCS>,
        _piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for VerifierLiteralExprNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(
        &self,
        proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, (LogicalPlan, bool)> {
        let literal_expr = match &self.node_id {
            NodeId::Expr(expr @ Expr::Literal(_)) => expr.clone(),
            _ => return IndexMap::new(),
        };

        let (base_plan, _) = if let Some(entry) = first_tablescan_plan_verifier(proof_tree) {
            entry
        } else {
            panic!("no tablescan plan found");
        };

        let literal_plan = LogicalPlanBuilder::from(base_plan)
            .project(vec![literal_expr.alias("literal")])
            .unwrap()
            .build()
            .unwrap();

        IndexMap::from([(OUTPUT_PLAN_KEY.to_string(), (literal_plan, false))])
    }

    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn from_expr(
        _ctx: &SessionContext,
        _verifier_ctx: SharedCtx<F, MvPCS, UvPCS>,
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
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
    ) {
        let scalar = match &self.node_id {
            NodeId::Expr(Expr::Literal(value)) => value.clone(),
            _ => panic!("literal node expected literal expression"),
        };
        let array = scalar
            .to_array()
            .expect("failed to convert scalar into arrow array");

        let mut column_values = encode_arrow_array_to_field::<F>(&array)
            .expect("failed to encode literal into field elements")
            .into_iter()
            .next()
            .unwrap_or_else(|| vec![F::zero()]);

        if column_values.len() > 1 {
            panic!("literal encoding resulted in multiple field elements");
        }

        let constant_value = column_values.pop().unwrap_or_else(F::zero);

        // TODO: Make the log size correct
        let tracked_poly = verifier.track_mat_mv_cnst_oracle(0, constant_value);

        let data_type = scalar.data_type();

        let schema = Schema::new(vec![Field::new(
            "literal",
            data_type.clone(),
            scalar.is_null(),
        )]);
        let table = TrackedTableOracle::new(
            Some(schema),
            IndexMap::from([(
                Arc::new(Field::new("literal", data_type, scalar.is_null())),
                tracked_poly,
            )]),
            0,
        );

        piop_tree.add_tracked_table_oracle(self.node_id.clone(), OUTPUT_PLAN_KEY.to_owned(), table);
    }
    fn verify_piop(
        &self,
        _verifier: &mut Verifier<F, MvPCS, UvPCS>,
        _piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn ctx_schema(
        &self,
        proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> SchemaRef {
        proof_tree
            .node(&self.parent_node_id)
            .unwrap()
            .ctx_schema(proof_tree)
    }
}

fn first_tablescan_plan_prover<F, MvPCS, UvPCS>(
    proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
) -> Option<(LogicalPlan, bool)>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    proof_tree
        .proof_nodes()
        .iter()
        .find_map(|(node_id, node)| match node_id {
            NodeId::LP(LogicalPlan::TableScan(_)) => node
                .hint_generation_plans(proof_tree)
                .get(OUTPUT_PLAN_KEY)
                .cloned(),
            _ => None,
        })
}

fn first_tablescan_plan_verifier<F, MvPCS, UvPCS>(
    proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
) -> Option<(LogicalPlan, bool)>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    proof_tree
        .proof_nodes()
        .iter()
        .find_map(|(node_id, node)| match node_id {
            NodeId::LP(LogicalPlan::TableScan(_)) => node
                .hint_generation_plans(proof_tree)
                .get(OUTPUT_PLAN_KEY)
                .cloned(),
            _ => None,
        })
}
