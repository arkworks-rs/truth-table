use ark_piop::SnarkBackend;
use tt_core::irs::shared_ir::InitialIr;

use super::ProofPlanOptimizerRule;

/// Request a PK/FK-specialized Join mode from schema metadata.
///
/// This is deliberately a no-op for now: the `HasOne` representation has no
/// proof constraints for its materialized PK-side output. Retaining the named
/// rule keeps the optimizer pipeline stable while every join uses the complete
/// `MANY_TO_MANY` protocol.
pub struct PkFkSpecializationRule;

impl<B: SnarkBackend> ProofPlanOptimizerRule<B> for PkFkSpecializationRule {
    fn name(&self) -> &'static str {
        "PkFkSpecialization"
    }

    fn optimize(&self, ir: InitialIr<B>) -> InitialIr<B> {
        ir
    }
}
