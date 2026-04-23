//! DataFusion-side planner rules for truth-table proofs.
//!
//! This crate sits between DataFusion and `tt-core`. It contains:
//!
//! - [`logical_plan_analyzer`] — analyzer rules that run before optimization,
//!   normalizing the logical plan into a shape the rest of the pipeline expects.
//! - [`logical_plan_optimizer`] — optimizer rules and the
//!   [`logical_plan_optimizer::OptimizationHints`] struct, which captures the
//!   data-dependent optimizer decisions that must travel with the proof so the
//!   verifier can reproduce the same plan.
//! - [`proof_plan_optimizer`] — rewrite rules that operate on the truth-table
//!   IR after it has been built from the optimized logical plan.
//!
//! The public [`ProofPlanner`] type is a placeholder for a future unified entry
//! point; today the prover and verifier call the individual rule sets directly.

use ark_piop::SnarkBackend;
use datafusion::prelude::SessionContext;
use datafusion_expr::LogicalPlan;
use tracing::instrument;
use tt_core::irs::shared_ir::InitialIr;

pub mod logical_plan_analyzer;
pub mod logical_plan_optimizer;
pub mod proof_plan_optimizer;

pub struct ProofPlanner<B: SnarkBackend> {
    _marker: std::marker::PhantomData<B>,
}
impl<B: SnarkBackend> Default for ProofPlanner<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: SnarkBackend> ProofPlanner<B> {
    pub fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
    #[instrument(level = "debug", skip_all)]
    pub async fn plan(_df_session_ctx: &SessionContext, _logical_plan: LogicalPlan) -> InitialIr<B>
    where
        B: SnarkBackend,
    {
        todo!()
    }
}
