use std::future::Future;

use tokio::runtime::{Builder, Handle};

/// Runs an async future to completion without requiring callers to manage a
/// Tokio runtime explicitly.
pub(crate) fn block_on<F>(future: F) -> F::Output
where
    F: Future,
{
    match Handle::try_current() {
        Ok(handle) => handle.block_on(future),
        Err(_) => Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime")
            .block_on(future),
    }
}
