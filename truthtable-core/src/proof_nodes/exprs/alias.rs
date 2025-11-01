use crate::{
    proof_nodes::{
        OUTPUT_PLAN_KEY, cost::ProvingCost, id::NodeId, prover::ProverNode, verifier::VerifierNode,
    },
    prover::trees::{piop_tree::ProverPIOPTree, proof_tree::ProverProofTree},
    verifier::trees::proof_tree::VerifierProofTree,
};
use arithmetic::{
    ctx::SharedCtx, table::TrackedTable, table_oracle::TrackedTableOracle, ACTIVATOR_COL_NAME,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    prover::Prover,
};
use datafusion::{
    arrow::datatypes::{Field, FieldRef, Schema, SchemaRef},
    common::Statistics,
    logical_expr::Expr,
    prelude::SessionContext,
};
use datafusion_expr::LogicalPlan;
use indexmap::IndexMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct ProverAliasExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub node_id: NodeId,
    pub input: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub parent_node_id: NodeId,
}
#[derive(Clone)]
pub struct VerifierAliasExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub node_id: NodeId,
    pub input: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub parent_node_id: NodeId,
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for ProverAliasExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        vec![&self.input]
    }

    fn from_expr(
        ctx: &SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        parent_logical_plan: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        let alias = match expr.clone() {
            Expr::Alias(alias) => alias,
            _ => panic!("expected alias expression"),
        };
        let node_id = NodeId::Expr(expr.clone());
        let input_expr = (*alias.expr).clone();
        let child = ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
            ctx,
            prover_ctx,
            input_expr,
            &node_id.clone(),
        )
        .root();
        Self {
            node_id,
            input: child,
            parent_node_id: parent_logical_plan,
        }
    }

    fn cost(&self, _statistics: Statistics, _schema: SchemaRef) -> ProvingCost {
        todo!()
    }

    fn ctx_lp_node(
        &self,
        proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
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
        let alias_name = match &self.node_id {
            NodeId::Expr(Expr::Alias(alias)) => alias.name.clone(),
            _ => panic!("expected alias expression node"),
        };

        if let Some(table) = piop_tree.tracked_table(&self.input.node_id(), OUTPUT_PLAN_KEY) {
            let mut tracked_polys: IndexMap<
                FieldRef,
                ark_piop::prover::structs::polynomial::TrackedPoly<F, MvPCS, UvPCS>,
            > = IndexMap::new();
            let mut schema_fields: Vec<FieldRef> = Vec::new();
            let mut alias_applied = false;

            for (field, poly) in table.tracked_polys_iter() {
                let new_field = if !alias_applied && field.name() != ACTIVATOR_COL_NAME {
                    alias_applied = true;
                    Arc::new(Field::new(
                        alias_name.clone(),
                        field.data_type().clone(),
                        field.is_nullable(),
                    ))
                } else {
                    field.clone()
                };
                schema_fields.push(new_field.clone());
                tracked_polys.insert(new_field, poly.clone());
            }

            let fields: Vec<Field> = schema_fields
                .iter()
                .map(|field_ref| field_ref.as_ref().clone())
                .collect();
            // Rebuild a schema that reflects the aliased column name so later lookups can resolve it.
            let new_schema = table
                .schema_ref()
                .map(|schema| Schema::new_with_metadata(fields.clone(), schema.metadata().clone()))
                .or_else(|| Some(Schema::new(fields)));

            let aliased_table = TrackedTable::new(new_schema, tracked_polys, table.log_size());

            piop_tree.add_table(
                self.node_id.clone(),
                OUTPUT_PLAN_KEY.to_string(),
                aliased_table,
            );
        }
    }
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for VerifierAliasExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        vec![&self.input]
    }

    fn from_expr(
        ctx: &SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        parent_logical_plan: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        let alias = match expr.clone() {
            Expr::Alias(alias) => alias,
            _ => panic!("expected alias expression"),
        };
        let node_id = NodeId::Expr(expr.clone());
        let input_expr = (*alias.expr).clone();
        let child = VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
            ctx,
            prover_ctx,
            input_expr,
            &node_id.clone(),
        )
        .root();
        Self {
            node_id,
            input: child,
            parent_node_id: parent_logical_plan,
        }
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
        let alias_name = match &self.node_id {
            NodeId::Expr(Expr::Alias(alias)) => alias.name.clone(),
            _ => panic!("expected alias expression node"),
        };

        if let Some(table) = piop_tree.tracked_table_oracle(&self.input.node_id(), OUTPUT_PLAN_KEY)
        {
            let mut tracked_oracles: IndexMap<FieldRef, _> = IndexMap::new();
            let mut schema_fields: Vec<FieldRef> = Vec::new();
            let mut alias_applied = false;

            for (field, oracle) in table.tracked_oracles() {
                let new_field = if !alias_applied && field.name() != ACTIVATOR_COL_NAME {
                    alias_applied = true;
                    Arc::new(Field::new(
                        alias_name.clone(),
                        field.data_type().clone(),
                        field.is_nullable(),
                    ))
                } else {
                    field.clone()
                };
                schema_fields.push(new_field.clone());
                tracked_oracles.insert(new_field, oracle);
            }

            let fields: Vec<Field> = schema_fields
                .iter()
                .map(|field_ref| field_ref.as_ref().clone())
                .collect();
            // Mirror the prover path: attach a schema carrying the alias for verifier column resolution.
            let new_schema = table
                .schema()
                .map(|schema| Schema::new_with_metadata(fields.clone(), schema.metadata().clone()))
                .or_else(|| Some(Schema::new(fields)));

            let aliased_table =
                TrackedTableOracle::new(new_schema, tracked_oracles, table.log_size());

            piop_tree.add_tracked_table_oracle(
                self.node_id.clone(),
                OUTPUT_PLAN_KEY.to_string(),
                aliased_table,
            );
        }
    }
    fn ctx_lp_node(
        &self,
        proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>> {
        proof_tree
            .node(&self.parent_node_id)
            .unwrap()
            .ctx_lp_node(proof_tree)
    }
}
