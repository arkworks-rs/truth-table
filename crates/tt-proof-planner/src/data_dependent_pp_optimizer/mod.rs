//! Data-dependent proof-plan optimizer rules: the counterpart of
//! [`crate::data_dependent_lp_optimizer`] on the truth-table IR, after the
//! structural [`crate::pp_optimizer`] pass. The prover decides from runtime
//! information, emits [`ProofPlanOptimizationHint`]s, and the verifier replays
//! them to rebuild the prover's IR.
//!
//! There are no rules. Adding the first one needs a
//! [`ProofPlanOptimizationHint`] variant, an entry in [`rules`], a dispatch
//! arm in [`apply_proof_plan_optimization_hints`], and
//! [`ProofPlanOptimizationHints`] carried in the serialized proof.

use std::sync::Arc;

use ark_piop::SnarkBackend;
use tt_core::irs::shared_ir::InitialIr;

/// Unlike [`crate::pp_optimizer::ProofPlanOptimizerRule`], a rule returns
/// hints for the verifier to replay instead of a rewritten IR.
pub trait DataDependentProofPlanOptimizationRule<B: SnarkBackend>: Send + Sync {
    /// Stable identifier, used for diagnostics and rule filtering.
    fn name(&self) -> &str;

    /// `ir` is the structurally optimized IR.
    fn collect_hints(&self, ir: &InitialIr<B>) -> Vec<ProofPlanOptimizationHint>;
}

pub struct DataDependentProofPlanOptimizer<B: SnarkBackend> {
    rules: Vec<Arc<dyn DataDependentProofPlanOptimizationRule<B>>>,
}

impl<B: SnarkBackend> DataDependentProofPlanOptimizer<B> {
    pub fn with_rules(rules: Vec<Arc<dyn DataDependentProofPlanOptimizationRule<B>>>) -> Self {
        Self { rules }
    }

    /// For filtering, e.g. benchmarks that ablate individual rules.
    pub fn rules(&self) -> &[Arc<dyn DataDependentProofPlanOptimizationRule<B>>] {
        &self.rules
    }

    pub fn collect_hints(&self, ir: &InitialIr<B>) -> ProofPlanOptimizationHints {
        let mut hints = Vec::new();
        for rule in &self.rules {
            hints.extend(rule.collect_hints(ir));
        }
        ProofPlanOptimizationHints { hints }
    }
}

/// A decision the verifier replays. Uninhabited while there are no rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofPlanOptimizationHint {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProofPlanOptimizationHints {
    pub hints: Vec<ProofPlanOptimizationHint>,
}

impl ProofPlanOptimizationHints {
    pub fn is_empty(&self) -> bool {
        self.hints.is_empty()
    }
}

/// A no-op while [`ProofPlanOptimizationHint`] is uninhabited: the match is
/// exhaustive with zero arms.
pub fn apply_proof_plan_optimization_hints<B: SnarkBackend>(
    ir: InitialIr<B>,
    hints: &ProofPlanOptimizationHints,
) -> InitialIr<B> {
    if let Some(hint) = hints.hints.first() {
        match *hint {}
    }
    ir
}

/// The default rules, shared by production callers and benchmarks.
pub fn rules<B: SnarkBackend>() -> Vec<Arc<dyn DataDependentProofPlanOptimizationRule<B>>> {
    vec![]
}

/// Collects hints with the default [`rules`].
pub fn collect_data_dependent_pp_hints<B: SnarkBackend>(
    ir: &InitialIr<B>,
) -> ProofPlanOptimizationHints {
    DataDependentProofPlanOptimizer::with_rules(rules::<B>()).collect_hints(ir)
}
