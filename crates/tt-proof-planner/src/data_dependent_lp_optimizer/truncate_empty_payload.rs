use datafusion::execution::context::SessionState;
use datafusion_common::{DataFusionError, Result as DataFusionResult};
use datafusion_expr::LogicalPlan;

use super::{DataDependentOptimizationRule, OptimizationHint};

/// Disabled legacy rule for data-dependent empty-subtree elimination.
/// An honest prover's row count is not an emptiness certificate. Re-enabling
/// this rule requires a verifier-checked proof tied to the original subtree;
/// replacing it with `EmptyRelation` would erase the obligations proving it.
/// Explicitly enabling this rule returns an error, just as replay does.
#[derive(Debug, Default)]
pub struct TruncateEmptyPayloadRule;

impl TruncateEmptyPayloadRule {
    pub fn new() -> Self {
        Self
    }
}

impl DataDependentOptimizationRule for TruncateEmptyPayloadRule {
    fn name(&self) -> &str {
        "truncate_empty_payload"
    }

    fn collect_hints(
        &self,
        _session_state: &SessionState,
        _plan: &LogicalPlan,
    ) -> DataFusionResult<Vec<OptimizationHint>> {
        Err(unsupported_truncation())
    }
}

pub(super) fn unsupported_truncation() -> DataFusionError {
    DataFusionError::Plan(
        "Truncate optimization hints are unsupported without a verifier-checked emptiness proof"
            .to_string(),
    )
}
