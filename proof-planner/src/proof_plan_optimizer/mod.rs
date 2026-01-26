use std::sync::Arc;

use ark_piop::SnarkBackend;
use tt_core::irs::shared_ir::GadgetPlannedIr;

mod truncate_empty_payload;
mod simplify_nodups;

pub use simplify_nodups::SimplifyNoDups;

pub trait ProofPlanOptimizerRule<B: SnarkBackend>: Send + Sync {
    fn name(&self) -> &'static str;
    fn optimize(&self, ir: GadgetPlannedIr<B>) -> GadgetPlannedIr<B>;
}

pub struct ProofPlanOptimizer<B: SnarkBackend> {
    rules: Vec<Arc<dyn ProofPlanOptimizerRule<B>>>,
}

impl<B: SnarkBackend> ProofPlanOptimizer<B> {
    pub fn new(rules: Vec<Arc<dyn ProofPlanOptimizerRule<B>>>) -> Self {
        Self { rules }
    }

    pub fn optimize(&self, mut ir: GadgetPlannedIr<B>) -> GadgetPlannedIr<B> {
        for rule in &self.rules {
            ir = rule.optimize(ir);
        }
        ir
    }
}

pub fn rules<B: SnarkBackend>() -> Vec<Arc<dyn ProofPlanOptimizerRule<B>>> {
    vec![
        Arc::new(truncate_empty_payload::TruncateEmptyPayload),
        Arc::new(simplify_nodups::SimplifyNoDups),
    ]
}
