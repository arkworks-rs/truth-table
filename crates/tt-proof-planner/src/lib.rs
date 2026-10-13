//! DataFusion-side planner rules for truth-table proofs, between DataFusion
//! and `tt-core`:
//!
//! - [`lp_analyzer`]: analyzer rules that run before optimization.
//! - [`lp_optimizer`]: structural rules that rewrite the logical plan into a
//!   shape the truth-table IR can consume.
//! - [`data_dependent_lp_optimizer`]: rules whose decisions depend on runtime
//!   row counts. The prover runs them and ships
//!   [`data_dependent_lp_optimizer::OptimizationHints`] with the proof so the
//!   verifier rebuilds the same plan.
//! - [`pp_optimizer`]: rewrite rules on the truth-table IR built from the
//!   optimized logical plan.
//! - [`data_dependent_pp_optimizer`]: the same hint mechanism on `InitialIr<B>`.
//!
//! [`ProofPlanner`] is an unimplemented placeholder: the prover and verifier
//! call the rule sets directly.

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
