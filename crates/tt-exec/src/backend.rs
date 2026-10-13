//! SNARK backend of the `tt` runners and the benches: BN254 by default,
//! BLS12-381 with the `bls12-381` feature (`third-party-bench` forwards it),
//! for parity with systems that hard-code that curve, e.g. QEDB.

#[cfg(not(feature = "bls12-381"))]
pub use ark_piop::DefaultSnarkBackend as BenchBackend;

#[cfg(feature = "bls12-381")]
pub use ark_piop::Bls12_381SnarkBackend as BenchBackend;

/// Name of the active curve. Tags bench rows with a `curve` column and keeps
/// the key, SRS and oracle files of the two curves apart.
#[cfg(not(feature = "bls12-381"))]
pub const BACKEND_NAME: &str = "bn254";
#[cfg(feature = "bls12-381")]
pub const BACKEND_NAME: &str = "bls12_381";
