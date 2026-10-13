//! The DataFusion session the prover and the verifier compute with.

use std::future::Future;

use datafusion::prelude::{SessionConfig, SessionContext};
use datafusion_common::{DataFusionError, Result};
use tokio::runtime::{Builder, Handle, RuntimeFlavor};

/// A session whose plans run in one partition.
///
/// DataFusion's default is one partition per core, merged in the order their
/// batches arrive, so row order depends on scheduling. The prover commits to
/// those rows, so the proof would differ from run to run. Every session is
/// built here, the schema-only ones too, so that no dataframe picks up the
/// default from the session it was read into.
pub fn session_context() -> SessionContext {
    SessionContext::new_with_config(SessionConfig::new().with_target_partitions(1))
}

/// Runs a DataFusion future, such as `df.collect()`, to completion from
/// synchronous code, inside or outside a tokio runtime. A current-thread
/// runtime cannot block on itself, so there the future runs on a runtime of
/// its own in a new thread.
pub fn block_on<T, Fut>(future: Fut) -> Result<T>
where
    T: Send + 'static,
    Fut: Future<Output = Result<T>> + Send + 'static,
{
    fn new_runtime() -> Result<tokio::runtime::Runtime> {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| DataFusionError::Execution(e.to_string()))
    }
    match Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::CurrentThread => {
            std::thread::spawn(move || new_runtime()?.block_on(future))
                .join()
                .map_err(|_| {
                    DataFusionError::Execution("dataframe collection thread panicked".to_string())
                })?
        }
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(future)),
        Err(_) => new_runtime()?.block_on(future),
    }
}
