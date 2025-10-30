mod hints;

use crate::{
    proof_nodes::{
        HintGenerationPlan, OUTPUT_PLAN_KEY, cost::ProvingCost, id::NodeId, prover::ProverNode,
        verifier::VerifierNode,
    },
    prover::trees::{piop_tree::ProverPIOPTree, proof_tree::ProverProofTree},
    verifier::trees::{piop_tree::VerifierPIOPTree, proof_tree::VerifierProofTree},
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
};
use datafusion::{
    logical_expr::{self as df, Join},
    prelude::SessionContext,
};
use datafusion_expr::LogicalPlan;
use hints::{build_join_hint_generation_plans, build_verifier_join_hint_generation_plans};
use indexmap::IndexMap;
use std::sync::Arc;

pub struct ProverJoinNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub left_proof_tree_root: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub right_proof_tree_root: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub on_proof_tree_roots: Vec<(
        Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
        Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    )>,
    pub filter_proof_tree_root: Option<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
    pub node_id: NodeId,
}

pub struct VerifierJoinNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub left_proof_tree_root: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub right_proof_tree_root: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub on_proof_tree_roots: Vec<(
        Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
        Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    )>,
    pub filter_proof_tree_root: Option<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    pub node_id: NodeId,
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for ProverJoinNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        let mut children = vec![&self.left_proof_tree_root, &self.right_proof_tree_root];
        for (left_on_node, right_on_node) in &self.on_proof_tree_roots {
            children.push(left_on_node);
            children.push(right_on_node);
        }

        if let Some(filter_node) = &self.filter_proof_tree_root {
            children.push(filter_node);
        }
        children
    }

    fn hint_generation_plans(
        &self,
        proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, HintGenerationPlan> {
        let _ = proof_tree;

        let plan = self
            .node_id
            .to_lp()
            .cloned()
            .expect("join node id should contain logical plan");

        build_join_hint_generation_plans(plan)
    }

    fn from_lp(
        ctx: &SessionContext,
        prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        let join = match &plan {
            LogicalPlan::Join(join) => join,
            _ => panic!("expected join logical plan"),
        };
        let node_id = NodeId::LP(plan.clone());
        let left_proof_tree_root = ProverProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            prover_ctx.clone(),
            &join.left,
            &node_id,
        )
        .root();

        let right_proof_tree_root = ProverProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            prover_ctx.clone(),
            &join.right,
            &node_id,
        )
        .root();

        let on_proof_tree_roots: Vec<(
            Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
            Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
        )> = join
            .on
            .iter()
            .map(|(left_expr, right_expr)| {
                let left_tree = ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    left_expr.clone(),
                    &node_id,
                );
                let right_tree = ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    right_expr.clone(),
                    &node_id,
                );
                (
                    Arc::clone(&left_tree.root()),
                    Arc::clone(&right_tree.root()),
                )
            })
            .collect();

        let filter_proof_tree_root: Option<Arc<dyn ProverNode<F, MvPCS, UvPCS>>> =
            match &join.filter {
                Some(filter_expr) => {
                    let filter_tree = ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                        ctx,
                        prover_ctx.clone(),
                        filter_expr.clone(),
                        &node_id,
                    );
                    Some(Arc::clone(&filter_tree.root()))
                },
                None => None,
            };

        Self {
            left_proof_tree_root,
            right_proof_tree_root,
            on_proof_tree_roots,
            filter_proof_tree_root,
            node_id,
        }
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
    }

    fn child_edge_labels(&self) -> Vec<Option<String>> {
        let mut labels = Vec::with_capacity(
            2 + self.on_proof_tree_roots.len() * 2
                + usize::from(self.filter_proof_tree_root.is_some()),
        );
        labels.push(Some("left".to_string()));
        labels.push(Some("right".to_string()));
        for (idx, _) in self.on_proof_tree_roots.iter().enumerate() {
            labels.push(Some(format!("on[{idx}].lhs")));
            labels.push(Some(format!("on[{idx}].rhs")));
        }
        if let Some(_) = &self.filter_proof_tree_root {
            labels.push(Some("filter".to_string()));
        }
        labels
    }

    fn name(&self) -> String {
        self.node_id().to_string()
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
        _proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverNode<F, MvPCS, UvPCS>> {
        todo!()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    ) {
    }
    fn prove_piop(
        &self,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
        piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        todo!()
    }
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for VerifierJoinNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        let mut children = vec![&self.left_proof_tree_root, &self.right_proof_tree_root];
        for (left_on_node, right_on_node) in &self.on_proof_tree_roots {
            children.push(left_on_node);
            children.push(right_on_node);
        }

        if let Some(filter_node) = &self.filter_proof_tree_root {
            children.push(filter_node);
        }
        children
    }

    fn hint_generation_plans(
        &self,
        proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, HintGenerationPlan> {
        let _ = proof_tree;

        let plan = self
            .node_id
            .to_lp()
            .cloned()
            .expect("join node id should contain logical plan");

        build_verifier_join_hint_generation_plans(plan)
    }

    fn from_lp(
        ctx: &SessionContext,
        verifier_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        let join = match &plan {
            LogicalPlan::Join(join) => join,
            _ => panic!("expected join logical plan"),
        };
        let node_id = NodeId::LP(plan.clone());
        let left_proof_tree_root = VerifierProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            verifier_ctx.clone(),
            &join.left,
            &node_id,
        )
        .root();

        let right_proof_tree_root = VerifierProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            verifier_ctx.clone(),
            &join.right,
            &node_id,
        )
        .root();

        let on_proof_tree_roots: Vec<(
            Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
            Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
        )> = join
            .on
            .iter()
            .map(|(left_expr, right_expr)| {
                let left_tree = VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    verifier_ctx.clone(),
                    left_expr.clone(),
                    &node_id,
                );
                let right_tree = VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    verifier_ctx.clone(),
                    right_expr.clone(),
                    &node_id,
                );
                (
                    Arc::clone(&left_tree.root()),
                    Arc::clone(&right_tree.root()),
                )
            })
            .collect();

        let filter_proof_tree_root: Option<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> =
            match &join.filter {
                Some(filter_expr) => {
                    let filter_tree = VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
                        ctx,
                        verifier_ctx.clone(),
                        filter_expr.clone(),
                        &node_id,
                    );
                    Some(Arc::clone(&filter_tree.root()))
                },
                None => None,
            };

        Self {
            left_proof_tree_root,
            right_proof_tree_root,
            on_proof_tree_roots,
            filter_proof_tree_root,
            node_id,
        }
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
    }

    fn child_edge_labels(&self) -> Vec<Option<String>> {
        let mut labels = Vec::with_capacity(
            2 + self.on_proof_tree_roots.len() * 2
                + usize::from(self.filter_proof_tree_root.is_some()),
        );
        labels.push(Some("left".to_string()));
        labels.push(Some("right".to_string()));
        for (idx, _) in self.on_proof_tree_roots.iter().enumerate() {
            labels.push(Some(format!("on[{idx}].lhs")));
            labels.push(Some(format!("on[{idx}].rhs")));
        }
        if let Some(_) = &self.filter_proof_tree_root {
            labels.push(Some("filter".to_string()));
        }
        labels
    }

    fn name(&self) -> String {
        self.node_id().to_string()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
    }

    fn verify_piop(
        &self,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        todo!()
    }

    fn ctx_lp_node(
        &self,
        _proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>> {
        todo!()
    }
}
