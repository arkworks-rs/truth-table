use std::sync::Arc;

use ark_piop::SnarkBackend;
use tt_core::irs::shared_ir::InitialIr;

mod pkfk_specialization;

pub use pkfk_specialization::PkFkSpecializationRule;

pub trait ProofPlanOptimizerRule<B: SnarkBackend>: Send + Sync {
    fn name(&self) -> &'static str;
    fn optimize(&self, ir: InitialIr<B>) -> InitialIr<B>;
}

pub struct ProofPlanOptimizer<B: SnarkBackend> {
    rules: Vec<Arc<dyn ProofPlanOptimizerRule<B>>>,
}

impl<B: SnarkBackend> ProofPlanOptimizer<B> {
    pub fn new(rules: Vec<Arc<dyn ProofPlanOptimizerRule<B>>>) -> Self {
        Self { rules }
    }

    /// Whether PK-FK joins are proved with the PKFKJoin protocol.
    pub fn specializes_pk_fk_joins(&self) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.name() == pkfk_specialization::NAME)
    }

    pub fn optimize(&self, mut ir: InitialIr<B>) -> InitialIr<B> {
        for rule in &self.rules {
            ir = rule.optimize(ir);
        }
        ir
    }
}

pub fn rules<B: SnarkBackend>() -> Vec<Arc<dyn ProofPlanOptimizerRule<B>>> {
    vec![Arc::new(PkFkSpecializationRule)]
}
