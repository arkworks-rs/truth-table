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
    piop::PIOP,
};
use datafusion::{
    logical_expr::{self as df, LogicalPlan, LogicalPlanBuilder},
    prelude::SessionContext,
};
use datafusion_expr::{
    Limit, SortExpr,
    logical_plan::{FetchType, SkipType},
};
use indexmap::IndexMap;
use ra_toolbox::lp_piop::limit_check::{LimitPIOP, LimitPIOPProverInput, LimitPIOPVerifierInput};
use std::sync::Arc;

pub struct ProverLimitNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub input: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
    pub limit: Limit,
}
pub struct VerifierLimitNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub input: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
    pub limit: Limit,
}
impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for ProverLimitNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        vec![&self.input]
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(
        &self,
        proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, HintGenerationPlan> {
        let child_plans = self.input.hint_generation_plans(proof_tree);
        let input_plan = child_plans
            .get(OUTPUT_PLAN_KEY)
            .unwrap_or_else(|| panic!("input proof node must expose {OUTPUT_PLAN_KEY}"))
            .plan()
            .clone();

        let output_plan = build_limit_hint_output_plan(input_plan, &self.limit);

        IndexMap::from([(
            OUTPUT_PLAN_KEY.to_string(),
            HintGenerationPlan::new_virtual(OUTPUT_PLAN_KEY.to_string(), output_plan),
        )])
    }

    fn from_lp(
        ctx: &SessionContext,
        _prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        let limit = match &plan {
            LogicalPlan::Limit(limit) => limit,
            _ => panic!("Expected Limit plan"),
        };
        let node_id = NodeId::LP(plan.clone());

        let input_node =
            ProverProofTree::<F, MvPCS, UvPCS>::from_lp(ctx, _prover_ctx, &limit.input, &node_id)
                .root();

        Self {
            input: input_node,
            node_id,
            limit: limit.clone(),
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
            .node(&self.node_id)
            .cloned()
            .unwrap_or_else(|| panic!("join node {} missing from proof tree", self.node_id))
    }

    fn prove_piop(
        &self,
        _prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Ok(())
        // let input_table = piop_tree
        //     .tracked_table(&self.input.node_id(), OUTPUT_PLAN_KEY)
        //     .unwrap_or_else(|| {
        //         panic!(
        //             "missing input tracked table for limit prover node {}",
        //             self.node_id
        //         )
        //     });
        // let output_table = piop_tree
        //     .tracked_table(&self.node_id, OUTPUT_PLAN_KEY)
        //     .unwrap_or_else(|| {
        //         panic!(
        //             "missing output tracked table for limit prover node {}",
        //             self.node_id
        //         )
        //     });

        // let limit_piop_input = LimitPIOPProverInput {
        //     limit: self.limit.clone(),
        //     input_activator_tracked_poly:
        // input_table.activator_tracked_poly(),
        //     output_activator_tracked_poly:
        // output_table.activator_tracked_poly(), };

        // LimitPIOP::<F, MvPCS, UvPCS>::prove(prover, limit_piop_input)
    }
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for VerifierLimitNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        vec![&self.input]
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(
        &self,
        proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, HintGenerationPlan> {
        let child_plans = self.input.hint_generation_plans(proof_tree);
        let input_plan = child_plans
            .get(OUTPUT_PLAN_KEY)
            .unwrap_or_else(|| panic!("input proof node must expose {OUTPUT_PLAN_KEY}"))
            .plan()
            .clone();

        let output_plan = build_limit_hint_output_plan(input_plan, &self.limit);

        IndexMap::from([(
            OUTPUT_PLAN_KEY.to_string(),
            HintGenerationPlan::new_virtual(OUTPUT_PLAN_KEY.to_string(), output_plan),
        )])
    }

    fn from_lp(
        ctx: &SessionContext,
        _prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        let limit = match &plan {
            LogicalPlan::Limit(limit) => limit,
            _ => panic!("Expected Limit plan"),
        };
        let node_id = NodeId::LP(plan.clone());

        let input_node =
            VerifierProofTree::<F, MvPCS, UvPCS>::from_lp(ctx, _prover_ctx, &limit.input, &node_id)
                .root();

        Self {
            input: input_node,
            node_id,
            limit: limit.clone(),
        }
    }

    fn verify_piop(
        &self,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        _piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Ok(())
        // let input_table = piop_tree
        //     .tracked_table_oracle(&self.input.node_id(), OUTPUT_PLAN_KEY)
        //     .unwrap_or_else(|| {
        //         panic!(
        //             "missing input tracked table oracle for limit verifier
        // node {}",             self.node_id
        //         )
        //     });
        // let output_table = piop_tree
        //     .tracked_table_oracle(&self.node_id, OUTPUT_PLAN_KEY)
        //     .unwrap_or_else(|| {
        //         panic!(
        //             "missing output tracked table oracle for limit verifier
        // node {}",             self.node_id
        //         )
        //     });

        // let limit_piop_input = LimitPIOPVerifierInput {
        //     limit: self.limit.clone(),
        //     input_activator: input_table.activator_tracked_poly(),
        //     output_activator: output_table.activator_tracked_poly(),
        // };

        // LimitPIOP::<F, MvPCS, UvPCS>::verify(verifier, limit_piop_input)
    }

    fn ctx_lp_node(
        &self,
        proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>> {
        proof_tree
            .node(&self.node_id)
            .cloned()
            .unwrap_or_else(|| panic!("join node {} missing from proof tree", self.node_id))
    }
}

fn build_limit_hint_output_plan(base_plan: LogicalPlan, limit: &Limit) -> LogicalPlan {
    let (skip, fetch) = resolve_limit_bounds(limit);
    let order_exprs: Vec<SortExpr> = base_plan
        .schema()
        .iter()
        .map(|(qualifier, field)| df::Expr::from((qualifier, field)).sort(true, true))
        .collect();

    let ordered_plan = if order_exprs.is_empty() {
        base_plan
    } else {
        LogicalPlanBuilder::from(base_plan)
            .sort(order_exprs)
            .expect("failed to impose deterministic ordering for LIMIT hints")
            .build()
            .expect("failed to build ordered LIMIT hint plan")
    };

    LogicalPlanBuilder::from(ordered_plan)
        .limit(skip, fetch)
        .expect("failed to apply LIMIT hint bounds")
        .build()
        .expect("failed to build LIMIT hint output plan")
}

fn resolve_limit_bounds(limit: &Limit) -> (usize, Option<usize>) {
    let skip = match limit
        .get_skip_type()
        .expect("failed to evaluate LIMIT skip expression")
    {
        SkipType::Literal(value) => value,
        SkipType::UnsupportedExpr => {
            panic!("LIMIT skip expressions must be literal for hint generation")
        },
    };

    let fetch = match limit
        .get_fetch_type()
        .expect("failed to evaluate LIMIT fetch expression")
    {
        FetchType::Literal(value) => value,
        FetchType::UnsupportedExpr => {
            panic!("LIMIT fetch expressions must be literal for hint generation")
        },
    };

    (skip, fetch)
}
