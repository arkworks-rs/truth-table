// Combined dbsnark-core/src/prover/nodes/exprs/cast.rs and
// dbsnark-core/src/verifier/nodes/exprs/cast.rs

use crate::{
    proof_nodes::{
        OUTPUT_PLAN_KEY, cost::ProvingCost, id::NodeId, prover::ProverNode, verifier::VerifierNode,
    },
    prover::trees::proof_tree::ProverProofTree,
    verifier::trees::proof_tree::VerifierProofTree,
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
};
use datafusion::{
    arrow::datatypes::{DataType, Field, Schema},
    common::scalar,
    logical_expr::{Expr, LogicalPlan},
    prelude::SessionContext,
};
use indexmap::IndexMap;
use std::sync::Arc;
#[derive(Clone)]
pub struct ProverCastExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub node_id: NodeId,
    pub parent_node_id: NodeId,
    pub input: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
}
#[derive(Clone)]
pub struct VerifierCastExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub node_id: NodeId,
    pub parent_node_id: NodeId,
    pub input: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
}
impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for ProverCastExprNode<F, MvPCS, UvPCS>
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
        let child_expr = match &expr {
            Expr::Cast(cast) => (*cast.expr).clone(),
            _ => panic!("expected cast or try_cast expression"),
        };

        let node_id = NodeId::Expr(expr);
        let child_node = ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
            ctx,
            prover_ctx.clone(),
            child_expr,
            &parent_logical_plan,
        )
        .root();

        Self {
            node_id,
            parent_node_id: parent_logical_plan,
            input: child_node,
        }
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
        proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverNode<F, MvPCS, UvPCS>> {
        proof_tree
            .node(&self.parent_node_id)
            .unwrap()
            .ctx_lp_node(proof_tree)
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
        prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
        let cast_expr = match self.node_id.to_expr() {
            Some(Expr::Cast(cast)) => cast.clone(),
            _ => panic!("expected cast expression"),
        };

        if let Some(Expr::Literal(scalar)) = self.input.node_id().to_expr() {
            dbg!(cast_expr.data_type.clone());
            let scalar = scalar
                .cast_to(&cast_expr.data_type)
                .expect("failed to cast literal value for cast expression");
            dbg!(scalar.clone());
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
            dbg!(&constant_value);
            let log_size = {
                let ctx_node = self.ctx_lp_node(piop_tree.proof_tree());
                piop_tree
                    .tracked_table(&ctx_node.node_id(), OUTPUT_PLAN_KEY)
                    .map(|table| table.log_size())
                    .unwrap_or(0)
            };
            let tracked_poly = prover.track_mat_mv_cnst_poly(log_size, constant_value);

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
                log_size,
            );

            piop_tree.add_table(self.node_id.clone(), OUTPUT_PLAN_KEY.to_owned(), table);
        } else {
            let target_type = cast_expr.data_type.clone();

            let child_table = match piop_tree.tracked_table(&self.input.node_id(), OUTPUT_PLAN_KEY)
            {
                Some(table) => table.clone(),
                None => return,
            };

            let target_type = cast_expr.data_type.clone();

            let mut columns = IndexMap::with_capacity(child_table.tracked_polys().len());
            for (field, poly) in child_table.tracked_polys() {
                let new_field = if field.name() == ACTIVATOR_COL_NAME {
                    field.clone()
                } else {
                    let base = field.as_ref();
                    let mut updated =
                        Field::new(base.name(), target_type.clone(), base.is_nullable());
                    if !base.metadata().is_empty() {
                        updated = updated.with_metadata(base.metadata().clone());
                    }
                    Arc::new(updated)
                };
                columns.insert(new_field, poly.clone());
            }

            let new_schema = child_table.schema().map(|schema| {
                let fields: Vec<Field> = schema
                    .fields()
                    .iter()
                    .map(|f| {
                        let base = f.as_ref();
                        if base.name() == ACTIVATOR_COL_NAME {
                            base.clone()
                        } else {
                            let mut updated =
                                Field::new(base.name(), target_type.clone(), base.is_nullable());
                            if !base.metadata().is_empty() {
                                updated = updated.with_metadata(base.metadata().clone());
                            }
                            updated
                        }
                    })
                    .collect();
                let mut new_schema = Schema::new(fields);
                if !schema.metadata().is_empty() {
                    new_schema = new_schema.with_metadata(schema.metadata().clone());
                }
                new_schema
            });

            let new_table = TrackedTable::new(new_schema, columns, child_table.log_size());

            piop_tree.add_table(self.node_id.clone(), OUTPUT_PLAN_KEY.to_string(), new_table);
        }
    }
    fn prove_piop(
        &self,
        prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
        piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        self.children()
            .iter()
            .try_for_each(|child| child.prove_piop(prover, piop_tree))?;
        Ok(())
    }
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for VerifierCastExprNode<F, MvPCS, UvPCS>
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
        let child_expr = match &expr {
            Expr::Cast(cast) => (*cast.expr).clone(),
            _ => panic!("expected cast or try_cast expression"),
        };

        let node_id = NodeId::Expr(expr);
        let child_node = VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
            ctx,
            prover_ctx.clone(),
            child_expr,
            &parent_logical_plan,
        )
        .root();

        Self {
            node_id,
            parent_node_id: parent_logical_plan,
            input: child_node,
        }
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
        verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
        let cast_expr = match self.node_id().to_expr() {
            Some(Expr::Cast(cast)) => cast.clone(),
            _ => panic!("expected cast expression"),
        };

        if let Some(Expr::Literal(scalar)) = self.input.node_id().to_expr() {
            let scalar = scalar
                .cast_to(&cast_expr.data_type)
                .expect("failed to cast literal value for cast expression");
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
            let log_size = {
                let ctx_node = self.ctx_lp_node(piop_tree.proof_tree());
                piop_tree
                    .tracked_table_oracle(&ctx_node.node_id(), OUTPUT_PLAN_KEY)
                    .map(|table| table.log_size())
                    .unwrap_or(0)
            };
            let tracked_poly = verifier.track_mat_mv_cnst_oracle(log_size, constant_value);

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
                log_size,
            );

            piop_tree.add_tracked_table_oracle(
                self.node_id.clone(),
                OUTPUT_PLAN_KEY.to_owned(),
                table,
            );
        } else {
            let target_type = cast_expr.data_type.clone();

            let child_table =
                match piop_tree.tracked_table_oracle(&self.input.node_id(), OUTPUT_PLAN_KEY) {
                    Some(table) => table.clone(),
                    None => return,
                };

            let target_type = cast_expr.data_type.clone();

            let mut columns = IndexMap::with_capacity(child_table.tracked_oracles().len());
            for (field, oracle) in child_table.tracked_oracles() {
                let new_field = if field.name() == ACTIVATOR_COL_NAME {
                    field.clone()
                } else {
                    let base = field.as_ref();
                    let mut updated =
                        Field::new(base.name(), target_type.clone(), base.is_nullable());
                    if !base.metadata().is_empty() {
                        updated = updated.with_metadata(base.metadata().clone());
                    }
                    Arc::new(updated)
                };
                columns.insert(new_field, oracle.clone());
            }

            let new_schema = child_table.schema().map(|schema| {
                let fields: Vec<Field> = schema
                    .fields()
                    .iter()
                    .map(|f| {
                        let base = f.as_ref();
                        if base.name() == ACTIVATOR_COL_NAME {
                            base.clone()
                        } else {
                            let mut updated =
                                Field::new(base.name(), target_type.clone(), base.is_nullable());
                            if !base.metadata().is_empty() {
                                updated = updated.with_metadata(base.metadata().clone());
                            }
                            updated
                        }
                    })
                    .collect();
                let mut new_schema = Schema::new(fields);
                if !schema.metadata().is_empty() {
                    new_schema = new_schema.with_metadata(schema.metadata().clone());
                }
                new_schema
            });

            let new_table = TrackedTableOracle::new(new_schema, columns, child_table.log_size());

            piop_tree.add_tracked_table_oracle(
                self.node_id(),
                OUTPUT_PLAN_KEY.to_string(),
                new_table,
            );
        }
    }
    fn verify_piop(
        &self,
        verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        self.children()
            .iter()
            .try_for_each(|child| child.verify_piop(verifier, piop_tree))?;
        Ok(())
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
