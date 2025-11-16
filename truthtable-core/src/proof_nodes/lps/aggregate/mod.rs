mod hints;
use crate::{
    proof_nodes::{
        HintGenerationPlan, OUTPUT_PLAN_KEY, cost::ProvingCost, id::NodeId,
        prover::{ProverGadgetNode, ProverLpNode, ProverNode},
        verifier::{VerifierNode, VerifierLpNode},
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
    piop::PIOP,
    prover::{Prover, structs::polynomial::TrackedPoly},
    verifier::structs::oracle::TrackedOracle,
};
use datafusion::{
    arrow::datatypes::{DataType, Field, FieldRef, Schema, SchemaRef},
    common::Statistics,
    logical_expr::LogicalPlan,
    prelude::{Expr, SessionContext},
};
use datafusion::prelude::DataFrame;

use indexmap::IndexMap;
use ra_toolbox::lp_piop::aggregate_check::{
    AggregatePIOP, AggregatePIOPProverInput, AggregatePIOPProverOutput, AggregatePIOPVerifierInput,
    AggregatePIOPVerifierOutput,
};
use std::sync::Arc;

pub(crate) const GROUP_MULTIPLICITY_COL_NAME: &str = "__truthtable_group_multiplicity";
pub(crate) const GROUP_INPUT_FOLDED_COL_NAME: &str = "__truthtable_group_input_folded";
pub(crate) const GROUP_OUTPUT_FOLDED_COL_NAME: &str = "__truthtable_group_output_folded";

pub(crate) fn grouping_multiplicity_field() -> Arc<Field> {
    Arc::new(Field::new(
        GROUP_MULTIPLICITY_COL_NAME,
        DataType::UInt64,
        true,
    ))
}

pub(crate) fn grouping_input_folded_field() -> Arc<Field> {
    Arc::new(Field::new(
        GROUP_INPUT_FOLDED_COL_NAME,
        DataType::Binary,
        true,
    ))
}

pub(crate) fn grouping_output_folded_field() -> Arc<Field> {
    Arc::new(Field::new(
        GROUP_OUTPUT_FOLDED_COL_NAME,
        DataType::Binary,
        true,
    ))
}

pub struct ProverAggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub group_expr_proof_tree_roots: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
    pub aggr_expr_proof_tree_roots: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
    pub input_proof_tree_root: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
}

pub struct VerifierAggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    pub group_expr_proof_tree_roots: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    pub aggr_expr_proof_tree_roots: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    pub input_proof_tree_root: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
}

impl<F, MvPCS, UvPCS> ProverLpNode<F, MvPCS, UvPCS> for ProverAggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_lp(
        ctx: &SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        _parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        // Get the aggregate logical plan
        let aggregate = match &plan {
            LogicalPlan::Aggregate(agg) => agg,
            _ => panic!("expected aggregate logical plan"),
        };
        // Get the node id of the current node
        let node_id = NodeId::LP(plan.clone());
        // Recursively build the input proof tree
        let input_proof_tree_root = ProverProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            prover_ctx.clone(),
            &aggregate.input,
            &node_id,
        )
        .root();

        // Recursively build the children by first building trees for the grouping
        // expressions
        let group_expr_proof_tree_roots: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>> = aggregate
            .group_expr
            .iter()
            .map(|expr| {
                ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    expr.clone(),
                    &node_id.clone(),
                )
                .root()
            })
            .collect();

        // Recursively build the children by first building trees for the eggregation
        // expressions
        let aggr_expr_proof_tree_roots: Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>> = aggregate
            .aggr_expr
            .iter()
            .map(|expr| {
                let is_valid_aggregate = match expr {
                    Expr::AggregateFunction(_) => true,
                    Expr::Alias(alias) => matches!(alias.expr.as_ref(), Expr::AggregateFunction(_)),
                    _ => false,
                };
                if !is_valid_aggregate {
                    panic!(
                        "expected aggregate expression to be AggregateFunction (optionally wrapped in an alias), got {expr}"
                    );
                }
                ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    expr.clone(),
                    &node_id.clone(),
                )
                .root()
            })
            .collect();

        Self {
            group_expr_proof_tree_roots,
            aggr_expr_proof_tree_roots,
            input_proof_tree_root,
            node_id,
        }
    }
}

impl<F, MvPCS, UvPCS> ProverGadgetNode<F, MvPCS, UvPCS>
    for ProverAggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        let mut children = Vec::new();
        // Note that the leftmost child is always the node corresponding to the input
        // logical plans This is crucial when traversing the proof tree in a
        // post-order fashion
        children.push(&self.input_proof_tree_root);
        self.group_expr_proof_tree_roots
            .iter()
            .for_each(|node| children.push(node));
        self.aggr_expr_proof_tree_roots
            .iter()
            .for_each(|node| children.push(node));

        children
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn child_edge_labels(&self) -> Vec<Option<String>> {
        let mut labels = Vec::new();
        labels.push(Some("input".to_string()));
        for (idx, _) in self.group_expr_proof_tree_roots.iter().enumerate() {
            labels.push(Some(format!("group_expr[{idx}]")));
        }
        for (idx, _) in self.aggr_expr_proof_tree_roots.iter().enumerate() {
            labels.push(Some(format!("agg_expr[{idx}]")));
        }
        labels
    }

    fn hint_generation_plans(
        &self,
        proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> indexmap::IndexMap<String, DataFrame> {
        todo!()
    }


    fn cost(&self, _statistics: Statistics, _schema: SchemaRef) -> ProvingCost {
        todo!()
    }


    fn add_virtual_witness(
        &self,
        piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }

    fn prove_piop(
        &self,
        prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
        piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> ark_piop::errors::SnarkResult<()> {
        todo!()
    }


    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
    }

    fn name(&self) -> String {
        self.node_id().to_string()
    }
    fn arithmetic_post_process(
        &self,
        _arithmetized_tree: &mut crate::prover::trees::arithmetized_tree::ProverArithmetizedTree<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }

}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for ProverAggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn output_data_frame(
        &self,
        _proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> DataFrame {
        todo!()
    }

    fn ctx_lp_node(
        &self,
        _proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverNode<F, MvPCS, UvPCS>> {
        todo!()
    }
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for VerifierAggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{

    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        let mut children = Vec::new();

        children.push(&self.input_proof_tree_root);
        self.group_expr_proof_tree_roots
            .iter()
            .for_each(|node| children.push(node));
        self.aggr_expr_proof_tree_roots
            .iter()
            .for_each(|node| children.push(node));

        children
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn child_edge_labels(&self) -> Vec<Option<String>> {
        let mut labels = Vec::new();
        labels.push(Some("input".to_string()));
        for (idx, _) in self.group_expr_proof_tree_roots.iter().enumerate() {
            labels.push(Some(format!("group_expr[{idx}]")));
        }
        for (idx, _) in self.aggr_expr_proof_tree_roots.iter().enumerate() {
            labels.push(Some(format!("agg_expr[{idx}]")));
        }
        labels
    }

    fn hint_generation_plans(
        &self,
        _proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> indexmap::IndexMap<String, DataFrame> {
        todo!()
    }



    fn add_virtual_witness(
        &self,
        _piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
        todo!()
    }


    fn verify_piop(
        &self,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> ark_piop::errors::SnarkResult<()> {
        todo!()
    }



    fn ctx_lp_node(
        &self,
        _proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>> {
        todo!()
    }



    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
    }

    fn name(&self) -> String {
        self.node_id().to_string()
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

impl<F, MvPCS, UvPCS> VerifierLpNode<F, MvPCS, UvPCS> for VerifierAggregateNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_lp(
        ctx: &SessionContext,
        verifier_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        _parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        // Get the aggregate logical plan
        let aggregate = match &plan {
            LogicalPlan::Aggregate(agg) => agg,
            _ => panic!("expected aggregate logical plan"),
        };
        let node_id = NodeId::LP(plan.clone());
        // Recursively build the input proof tree
        let input_proof_tree_root = VerifierProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            verifier_ctx.clone(),
            &aggregate.input,
            &node_id,
        )
        .root();

        // Recursively build the children by first building a tree for the grouping
        // expressions Note that their parent logical plan is unusually set to
        // be the input logical plan of the aggregate
        let group_expr_proof_tree_roots: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> = aggregate
            .group_expr
            .iter()
            .map(|expr| {
                VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    verifier_ctx.clone(),
                    expr.clone(),
                    &node_id.clone(),
                )
                .root()
            })
            .collect();

        for expr in &aggregate.aggr_expr {
            let is_valid_aggregate = match expr {
                Expr::AggregateFunction(_) => true,
                Expr::Alias(alias) => matches!(alias.expr.as_ref(), Expr::AggregateFunction(_)),
                _ => false,
            };

            if !is_valid_aggregate {
                panic!(
                    "expected aggregate expression to be AggregateFunction (optionally wrapped in an alias), got {expr}"
                );
            }
        }
        let aggr_expr_proof_tree_roots: Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> = aggregate
            .aggr_expr
            .iter()
            .map(|expr| {
                VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    verifier_ctx.clone(),
                    expr.clone(),
                    &node_id.clone(),
                )
                .root()
            })
            .collect();

        Self {
            group_expr_proof_tree_roots,
            aggr_expr_proof_tree_roots,
            input_proof_tree_root,
            node_id,
        }
    }
}
