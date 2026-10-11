//! The DataFusion session the prover and the verifier compute with.

use datafusion::prelude::{SessionConfig, SessionContext};

/// A session whose plans run in one partition.
///
/// DataFusion's default is one partition per core, and it merges partitions
/// in the order their batches arrive, so the rows of a scan, a join or an
/// aggregate come out in an order that depends on scheduling. The prover
/// commits to those rows: under the default the same query over the same
/// data gives a different proof from one run to the next, and a different
/// order of result rows when the query does not sort them. With one
/// partition the order is that of the plan.
///
/// Every session is built here, the ones that only carry a schema too, so
/// that no dataframe can pick up the default from the session it was read
/// into.
pub fn session_context() -> SessionContext {
    SessionContext::new_with_config(SessionConfig::new().with_target_partitions(1))
}
