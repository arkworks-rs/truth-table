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
