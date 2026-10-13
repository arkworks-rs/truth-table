use std::future::Future;

use tokio::runtime::{Builder, Handle};

/// Blocks on `future` on the current Tokio runtime, or on a fresh one if
/// there is none.
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
