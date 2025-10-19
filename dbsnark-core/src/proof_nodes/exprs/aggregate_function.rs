// Combined dbsnark-core/src/prover/nodes/exprs/aggregate_function.rs and
// dbsnark-core/src/verifier/nodes/exprs/aggregate_function.rs

use crate::{
    proof_nodes::{OUTPUT_PLAN_KEY, id::NodeId},
    prover::trees::{piop_tree::ProverPIOPTree, proof_tree::ProverProofTree},
    verifier::trees::proof_tree::VerifierProofTree,
};
use arithmetic::{
    col::TrackedCol, col_oracle::TrackedColOracle, ctx::SharedCtx, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::Prover,
};
use datafusion::{
    arrow::datatypes::SchemaRef, common::Statistics, logical_expr::Expr, prelude::SessionContext,
};
use datafusion_expr::LogicalPlan;
use indexmap::IndexMap;
use ra_toolbox::expr_piop::aggregate_function::{
    AggregateFunctionExprPIOP, AggregateFunctionPIOPProverInput, AggregateFunctionPIOPVerifierInput,
};
use std::sync::Arc;

use crate::proof_nodes::{cost::ProvingCost, prover::ProverNode, verifier::VerifierNode};
#[derive(Clone)]
pub struct ProverAggregateFunctionExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub node_id: NodeId,
    pub inputs: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
    pub parent_node_id: NodeId,
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS>
    for ProverAggregateFunctionExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        self.inputs.iter().collect()
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
        let aggregate_expr = match expr.clone() {
            Expr::AggregateFunction(agg) => agg,
            _ => panic!("expected aggregate function expression"),
        };
        let node_id = NodeId::Expr(expr.clone());
        let inputs = aggregate_expr
            .params
            .args
            .iter()
            .map(|arg| {
                ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    arg.clone(),
                    &node_id,
                )
                .root()
            })
            .collect();

        Self {
            node_id,
            inputs,
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
        _prover: &mut Prover<F, MvPCS, UvPCS>,
    ) {
        let mut collected_cols = IndexMap::new();
        let mut table_log_size: Option<usize> = None;

        for child in &self.inputs {
            let table = piop_tree
                .tracked_table(&child.node_id(), OUTPUT_PLAN_KEY)
                .unwrap_or_else(|| {
                    panic!(
                        "missing output_plan table for aggregate argument {}",
                        child.name()
                    )
                });

            let child_log_size = table.log_size();
            if let Some(expected) = table_log_size {
                assert_eq!(
                    expected, child_log_size,
                    "aggregate arguments must share the same table log size",
                );
            } else {
                table_log_size = Some(child_log_size);
            }
            let col = table.tracked_col_by_ind(0);
            let field = col.field_ref().unwrap();
            collected_cols.insert(field, col.data_tracked_poly().clone());
        }

        if collected_cols.is_empty() {
            return;
        }

        let output_table = TrackedTable::new(None, collected_cols, table_log_size.unwrap_or(0));
        piop_tree.add_table(
            self.node_id.clone(),
            OUTPUT_PLAN_KEY.to_string(),
            output_table,
        );
    }
    fn prove_piop(
        &self,
        prover: &mut Prover<F, MvPCS, UvPCS>,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let aggregate_expr = match &self.node_id {
            NodeId::Expr(Expr::AggregateFunction(agg)) => agg.clone(),
            _ => panic!("aggregate function node expected AggregateFunction expression"),
        };

        let auxiliary_table = piop_tree
            .tracked_table(&self.parent_node_id, "auxiliary")
            .unwrap_or_else(|| {
                panic!("missing auxiliary table for aggregate node {}", self.name())
            });

        let group_multiplicity_poly = auxiliary_table
            .tracked_polys()
            .into_iter()
            .next()
            .map(|(_, poly)| poly)
            .expect("auxiliary table missing multiplicity polynomial");

        let output_table = piop_tree
            .tracked_table(&self.node_id, OUTPUT_PLAN_KEY)
            .unwrap_or_else(|| {
                panic!(
                    "missing output table for aggregate function {}",
                    self.name()
                )
            });
        let aggregated_col: TrackedCol<F, MvPCS, UvPCS> = output_table.tracked_col_by_ind(0);

        let input_node = self
            .inputs
            .first()
            .unwrap_or_else(|| panic!("aggregate function {} missing argument", self.name()));
        let input_table = piop_tree
            .tracked_table(&input_node.node_id(), OUTPUT_PLAN_KEY)
            .unwrap_or_else(|| {
                panic!(
                    "missing output table for aggregate argument {}",
                    input_node.name()
                )
            });
        let input_col: TrackedCol<F, MvPCS, UvPCS> = input_table.tracked_col_by_ind(0);

        let piop_input = AggregateFunctionPIOPProverInput {
            aggregate: aggregate_expr,
            group_multiplicty_tracked_poly: group_multiplicity_poly,
            aggregated_col,
            input_col,
        };
        AggregateFunctionExprPIOP::prove(prover, piop_input)?;

        self.children()
            .iter()
            .try_for_each(|child| child.prove_piop(prover, piop_tree))?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct VerifierAggregateFunctionExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub node_id: NodeId,
    pub inputs: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    pub parent_node_id: NodeId,
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS>
    for VerifierAggregateFunctionExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        self.inputs.iter().collect()
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
        let aggregate_expr = match expr.clone() {
            Expr::AggregateFunction(agg) => agg,
            _ => panic!("expected aggregate function expression"),
        };
        let node_id = NodeId::Expr(expr.clone());
        let inputs = aggregate_expr
            .params
            .args
            .iter()
            .map(|arg| {
                VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    arg.clone(),
                    &node_id,
                )
                .root()
            })
            .collect();

        Self {
            node_id,
            inputs,
            parent_node_id: parent_logical_plan,
        }
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
        let mut collected_cols = IndexMap::new();
        let mut table_log_size: Option<usize> = None;

        for child in &self.inputs {
            let table = piop_tree
                .tracked_table_oracle(&child.node_id(), OUTPUT_PLAN_KEY)
                .unwrap_or_else(|| {
                    panic!(
                        "missing output_plan table for aggregate argument {}",
                        child.name()
                    )
                });

            let child_log_size = table.log_size();
            if let Some(expected) = table_log_size {
                assert_eq!(
                    expected, child_log_size,
                    "aggregate arguments must share the same table log size",
                );
            } else {
                table_log_size = Some(child_log_size);
            }
            let col = table.tracked_col_oracle_by_ind(0);
            let field = col.field_ref().unwrap();
            collected_cols.insert(field, col.data_tracked_oracle().clone());
        }

        if collected_cols.is_empty() {
            return;
        }

        let output_table =
            TrackedTableOracle::new(None, collected_cols, table_log_size.unwrap_or(0));
        piop_tree.add_tracked_table_oracle(
            self.node_id().clone(),
            OUTPUT_PLAN_KEY.to_string(),
            output_table,
        );
    }
    fn verify_piop(
        &self,
        verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let aggregate_expr = match &self.node_id {
            NodeId::Expr(Expr::AggregateFunction(agg)) => agg.clone(),
            _ => panic!("aggregate function node expected AggregateFunction expression"),
        };

        let auxiliary_table = piop_tree
            .tracked_table_oracle(&self.parent_node_id, "auxiliary")
            .unwrap_or_else(|| {
                panic!(
                    "missing auxiliary oracle table for aggregate node {}",
                    self.name()
                )
            });
        let group_multiplicity_oracle = auxiliary_table
            .tracked_oracles()
            .into_iter()
            .next()
            .map(|(_, oracle)| oracle)
            .expect("auxiliary oracle table missing multiplicity oracle");

        let output_table = piop_tree
            .tracked_table_oracle(&self.node_id, OUTPUT_PLAN_KEY)
            .unwrap_or_else(|| {
                panic!(
                    "missing output oracle table for aggregate function {}",
                    self.name()
                )
            });
        let aggregated_col_oracle: TrackedColOracle<F, MvPCS, UvPCS> =
            output_table.tracked_col_oracle_by_ind(0);

        let input_node = self
            .inputs
            .first()
            .unwrap_or_else(|| panic!("aggregate function {} missing argument", self.name()));
        let input_table = piop_tree
            .tracked_table_oracle(&input_node.node_id(), OUTPUT_PLAN_KEY)
            .unwrap_or_else(|| {
                panic!(
                    "missing output oracle table for aggregate argument {}",
                    input_node.name()
                )
            });
        let input_col_oracle: TrackedColOracle<F, MvPCS, UvPCS> =
            input_table.tracked_col_oracle_by_ind(0);

        let piop_input = AggregateFunctionPIOPVerifierInput {
            aggregate: aggregate_expr,
            group_multiplicty_tracked_oracle: group_multiplicity_oracle,
            aggregated_col_oracle,
            input_col_oracle,
        };
        AggregateFunctionExprPIOP::verify(verifier, piop_input)?;

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
