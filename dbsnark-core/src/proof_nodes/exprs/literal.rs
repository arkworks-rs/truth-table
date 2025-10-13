// Combined dbsnark-core/src/prover/nodes/exprs/literal.rs and
// dbsnark-core/src/verifier/nodes/exprs/literal.rs

use crate::{
    proof_nodes::{
        OUTPUT_PLAN_KEY, cost::ProvingCost, id::NodeId, prover::ProverNode, verifier::VerifierNode,
    },
    prover::trees::piop_tree::ProverPIOPTree,
    verifier::trees::piop_tree::VerifierPIOPTree,
};
use arithmetic::{
    ctx::SharedCtx, encoding::encode_arrow_array_to_field, table::TrackedTable,
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
    logical_expr::{Expr, LogicalPlan},
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
}
