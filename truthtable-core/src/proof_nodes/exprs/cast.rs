// Combined truthtable-core/src/prover/nodes/exprs/cast.rs and
// truthtable-core/src/verifier/nodes/exprs/cast.rs

use crate::{
    proof_nodes::{
        OUTPUT_PLAN_KEY, cost::ProvingCost, id::NodeId, prover::{ProverExprNode, ProverNode}, verifier::{VerifierExprNode, VerifierNode},
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
    pcs::PCS,
};
use datafusion::{
    arrow::datatypes::{Field, Schema},
    logical_expr::Expr,
    prelude::SessionContext,
};
use datafusion::prelude::DataFrame;

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
        todo!()
    }


    fn add_virtual_witness(
        &self,
        piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
        prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }

    fn hint_generation_plans(
        &self,
        _proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> indexmap::IndexMap<String, DataFrame> {
        todo!()
    }

    fn arithmetic_post_process(
        &self,
        _arithmetized_tree: &mut crate::prover::trees::arithmetized_tree::ProverArithmetizedTree<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }

    fn output_data_frame(
        &self,
        _proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> DataFrame {
        todo!()
    }

    fn is_public(&self) -> bool {
        todo!()
    }

    fn prove_piop(
        &self,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> ark_piop::errors::SnarkResult<()> {
        todo!()
    }

}

impl<F, MvPCS, UvPCS> ProverExprNode<F, MvPCS, UvPCS> for ProverCastExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
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


    fn add_virtual_witness(
        &self,
        _piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }


    fn ctx_lp_node(
        &self,
        _proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>> {
        todo!()
    }



    fn hint_generation_plans(
        &self,
        _proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> indexmap::IndexMap<String, DataFrame> {
        todo!()
    }


    fn verify_piop(
        &self,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> ark_piop::errors::SnarkResult<()> {
        todo!()
    }


    fn output_data_frame(
        &self,
        _proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> DataFrame {
        todo!()
    }


    fn is_public(&self) -> bool {
        todo!()
    }

}

impl<F, MvPCS, UvPCS> VerifierExprNode<F, MvPCS, UvPCS> for VerifierCastExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
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
}


#[cfg(test)]
mod tests {

    #[test]
    fn test_cast_expression() {
        use arrow_cast::cast::can_cast_types;
        use arrow_schema::DataType;

        fn all_types() -> Vec<DataType> {
            vec![
                DataType::Boolean,
                DataType::Int8,
                DataType::Int16,
                DataType::Int32,
                DataType::Int64,
                DataType::UInt8,
                DataType::UInt16,
                DataType::UInt32,
                DataType::UInt64,
                DataType::Float16,
                DataType::Float32,
                DataType::Float64,
                DataType::Utf8,
                DataType::LargeUtf8,
                DataType::Binary,
                DataType::LargeBinary,
                DataType::Date32,
                DataType::Date64,
                DataType::Time32(arrow_schema::TimeUnit::Second),
                DataType::Time64(arrow_schema::TimeUnit::Microsecond),
                DataType::Timestamp(arrow_schema::TimeUnit::Microsecond, None),
                DataType::Interval(arrow_schema::IntervalUnit::MonthDayNano),
                DataType::Decimal128(38, 18),
                DataType::Decimal256(76, 38),
                DataType::Duration(arrow_schema::TimeUnit::Microsecond),
                DataType::List(
                    Box::new(arrow_schema::Field::new("item", DataType::Int32, true)).into(),
                ),
                DataType::FixedSizeList(
                    Box::new(arrow_schema::Field::new("item", DataType::Int32, true)).into(),
                    3,
                ),
                DataType::Struct(vec![arrow_schema::Field::new("a", DataType::Int32, true)].into()),
                DataType::Dictionary(Box::new(DataType::Int32), Box::new(DataType::Utf8)),
                // add more as needed
            ]
        }

        let types = all_types();
        for (i, from) in types.iter().enumerate() {
            for to in &types {
                if can_cast_types(from, to) {
                    println!("{from:?} -> {to:?}");
                }
            }
            if i + 1 < types.len() {
                println!("---");
            }
        }
    }
}
