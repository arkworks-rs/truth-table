//! Cfg-flipped SNARK backend used by the `tt` CLI runners and the benches.
//!
//! Default: BN254. Enable the `bls12-381` feature on `tt-exec` (or, from a
//! downstream like `third-party-bench`, on its forwarding feature) to swap in
//! BLS12-381. The micro benchmark uses this to produce a TT@BLS12-381 column
//! for parity with systems that hard-code BLS12-381 (e.g. QEDB).

#[cfg(not(feature = "bls12-381"))]
pub use ark_piop::DefaultSnarkBackend as BenchBackend;

#[cfg(feature = "bls12-381")]
pub use ark_piop::Bls12_381SnarkBackend as BenchBackend;

/// Human-readable name of the active backend curve. Emitted by the bench
/// harness so the parsing pipeline can tag rows with a `curve` column.
#[cfg(not(feature = "bls12-381"))]
pub const BACKEND_NAME: &str = "bn254";
#[cfg(feature = "bls12-381")]
pub const BACKEND_NAME: &str = "bls12_381";
