use std::path::{Path, PathBuf};

/// Returns the root directory of the `truth-table` workspace.
pub fn workspace_root_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("tt-exec crate should live inside truth-table/crates")
        .to_path_buf()
}

/// Returns the shared workspace directory used for generated keys, proofs, and
/// other reusable artifacts.
pub fn workspace_artifacts_dir() -> PathBuf {
    workspace_root_dir().join("artifacts")
}
