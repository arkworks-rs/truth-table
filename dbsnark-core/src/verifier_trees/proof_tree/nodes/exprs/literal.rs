use crate::{id::NodeId, verifier_trees::proof_tree::nodes::VerifierNode};
use arithmetic::{encoding::encode_arrow_array_to_field, table::TrackedTable};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    prover::Prover,
};
use datafusion::{
    arrow::datatypes::{DataType, Field, Schema},
    logical_expr::Expr,
    scalar::ScalarValue,
};
use std::{collections::HashMap, sync::Arc};

#[derive(Clone)]
pub struct LiteralExprNode {
    pub node_id: NodeId,
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for LiteralExprNode
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        Vec::new()
    }

    fn from_expr(
        _ctx: &datafusion::prelude::SessionContext,
        _verifier_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        expr: Expr,
        _parent_logical_plan: datafusion::logical_expr::LogicalPlan,
    ) -> Self
    where
        Self: Sized,
    {
        Self {
            node_id: NodeId::Expr(expr),
        }
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut crate::verifier_trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
        prover: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
        todo!()
        // let scalar = match &self.node_id {
        //     NodeId::Expr(Expr::Literal(value)) => value.clone(),
        //     _ => panic!("literal node expected literal expression"),
        // };

        // let array = scalar
        //     .to_array()
        //     .expect("failed to convert scalar into arrow array");

        // let mut column_values = encode_arrow_array_to_field::<F>(&array)
        //     .expect("failed to encode literal into field elements")
        //     .into_iter()
        //     .next()
        //     .unwrap_or_else(|| vec![F::zero()]);

        // if column_values.len() > 1 {
        //     panic!("literal encoding resulted in multiple field elements");
        // }

        // let constant_value = column_values.pop().unwrap_or_else(F::zero);

        // let tracked_poly = prover.track_mat_mv_cnst_poly(0, constant_value);

        // let data_type = scalar.data_type();

        // let schema = Schema::new(vec![Field::new(
        //     "literal",
        //     data_type.clone(),
        //     scalar.is_null(),
        // )]);

        // let table = TrackedTable::new(
        //     Some(schema),
        //     Vec::from([(
        //         Arc::new(Field::new("literal", data_type, scalar.is_null())),
        //         tracked_poly,
        //     )]),
        //     1,
        // );

        // piop_tree.add_table(self.node_id.clone(), "output_plan".to_owned(),
        // table);
    }
    fn verify_piop(
        &self,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::verifier_trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}
