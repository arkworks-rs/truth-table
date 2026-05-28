//! DataFusion-side planner rules for truth-table proofs.
//!
//! This crate sits between DataFusion and `tt-core`. It contains:
//!
//! - [`lp_analyzer`] — analyzer rules that run before optimization,
//!   normalizing the logical plan into a shape the rest of the pipeline expects.
//! - [`lp_optimizer`] — structural optimizer rules that rewrite the logical
//!   plan into a shape the truth-table IR can consume.
//! - [`data_dependent_lp_optimizer`] — data-dependent optimizer rules whose
//!   decisions depend on runtime row counts. The prover runs them and emits
//!   [`data_dependent_lp_optimizer::OptimizationHints`] that travel with the
//!   proof so the verifier can reproduce the same plan shape.
//! - [`pp_optimizer`] — proof-plan rewrite rules that operate on the
//!   truth-table IR after it has been built from the optimized logical plan.
//! - [`data_dependent_pp_optimizer`] — data-dependent proof-plan rules whose
//!   decisions depend on runtime IR state. Parallel to
//!   [`data_dependent_lp_optimizer`] but operates on `InitialIr<B>`.
//!
//! The public [`ProofPlanner`] type is a placeholder for a future unified entry
//! point; today the prover and verifier call the individual rule sets directly.

use ark_piop::SnarkBackend;
use datafusion::prelude::SessionContext;
use datafusion_expr::LogicalPlan;
use tracing::instrument;
use tt_core::irs::shared_ir::InitialIr;

pub mod data_dependent_lp_optimizer;
pub mod data_dependent_pp_optimizer;
pub mod lp_analyzer;
pub mod lp_optimizer;
pub mod pp_optimizer;

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
