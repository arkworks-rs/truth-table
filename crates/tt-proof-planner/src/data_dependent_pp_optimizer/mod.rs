//! Data-dependent proof-plan optimizer rules.
//!
//! Parallel to [`crate::data_dependent_lp_optimizer`], but operates on the
//! truth-table IR (`InitialIr<B>`) after the structural
//! [`crate::pp_optimizer`] pass. Rules in this module make decisions that
//! depend on runtime information only the prover sees, emit
//! [`ProofPlanOptimizationHint`]s, and the verifier replays those hints to
//! reproduce the prover's IR shape.
//!
//! The list is currently empty — this module exists as wiring for future
//! rules. When the first rule lands, the implementer should:
//!
//!  1. Add a variant to [`ProofPlanOptimizationHint`].
//!  2. Push a `Arc<RuleStruct>` into [`rules`].
//!  3. Extend [`apply_proof_plan_optimization_hints`] to dispatch on the new
//!     variant.
//!  4. Plumb [`ProofPlanOptimizationHints`] into the [`TTProof`]
//!     serialization so the verifier receives them.

use std::sync::Arc;

use ark_piop::SnarkBackend;
use tt_core::irs::shared_ir::InitialIr;

/// A data-dependent proof-plan optimization.
///
/// Parallel to [`crate::pp_optimizer::ProofPlanOptimizerRule`], but the result
/// is a set of [`ProofPlanOptimizationHint`]s the verifier will replay,
/// not a directly-rewritten IR. Hints are emitted by the prover (which has
/// access to runtime row counts via materialized payloads) and shipped with
/// the proof.
pub trait DataDependentProofPlanOptimizationRule<B: SnarkBackend>: Send + Sync {
    /// Stable identifier for this rule (used for diagnostics and rule filtering).
    fn name(&self) -> &str;

    /// Walk the structurally-optimized IR and produce any hints this rule
    /// wants the verifier to replay.
    fn collect_hints(&self, ir: &InitialIr<B>) -> Vec<ProofPlanOptimizationHint>;
}

/// Runs a configured set of [`DataDependentProofPlanOptimizationRule`]s over
/// the IR and merges their hints into a single [`ProofPlanOptimizationHints`]
/// payload.
pub struct DataDependentProofPlanOptimizer<B: SnarkBackend> {
    rules: Vec<Arc<dyn DataDependentProofPlanOptimizationRule<B>>>,
}

impl<B: SnarkBackend> DataDependentProofPlanOptimizer<B> {
    /// Build an optimizer that runs the given rules in order.
    pub fn with_rules(rules: Vec<Arc<dyn DataDependentProofPlanOptimizationRule<B>>>) -> Self {
        Self { rules }
    }

    /// Borrow the rule list (useful for filtering, e.g. benchmarks that
    /// ablate individual rules).
    pub fn rules(&self) -> &[Arc<dyn DataDependentProofPlanOptimizationRule<B>>] {
        &self.rules
    }

    /// Run every rule against `ir` and return their merged hint set.
    pub fn collect_hints(&self, ir: &InitialIr<B>) -> ProofPlanOptimizationHints {
        let mut hints = Vec::new();
        for rule in &self.rules {
            hints.extend(rule.collect_hints(ir));
        }
        ProofPlanOptimizationHints { hints }
    }
}

/// Verifier-replayable proof-plan optimization decisions. Currently has no
/// variants because there are no rules; future rules add variants here.
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

/// Apply a set of proof-plan optimization hints to an IR. Currently a no-op
/// because [`ProofPlanOptimizationHint`] has no variants; future rules add
/// dispatch arms here.
pub fn apply_proof_plan_optimization_hints<B: SnarkBackend>(
    ir: InitialIr<B>,
    hints: &ProofPlanOptimizationHints,
) -> InitialIr<B> {
    for hint in &hints.hints {
        // `ProofPlanOptimizationHint` is uninhabited today — this match is
        // exhaustive with zero arms. Add a variant + dispatch when a rule
        // is introduced.
        match *hint {}
    }
    ir
}

/// Default set of data-dependent proof-plan rules. Empty for now; production
/// callers and benchmarks both pull from this list.
pub fn rules<B: SnarkBackend>() -> Vec<Arc<dyn DataDependentProofPlanOptimizationRule<B>>> {
    vec![]
}

/// Production entry point: run the default [`DataDependentProofPlanOptimizer`]
/// over the IR.
pub fn collect_data_dependent_pp_hints<B: SnarkBackend>(
    ir: &InitialIr<B>,
) -> ProofPlanOptimizationHints {
    DataDependentProofPlanOptimizer::with_rules(rules::<B>()).collect_hints(ir)
}
