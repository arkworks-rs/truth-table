//! TruthTable++ string order PIOPs (§7, appendix §13): Character Projection
//! (PIOP 5), Lexicographic Sortedness (PIOP 10), String Sort (PIOP 11) and
//! Rank Certification (PIOP 12). Their comparisons over several keys run on
//! the sort check ([`contig_sort::piop`](crate::irs::nodes::utils::contig_sort::piop)),
//! which plays the Lexicographic Sort Check (PIOP 27).

use ark_piop::{errors::SnarkError, verifier::errors::VerifierError};

pub mod character_projection;
pub mod rank_certification;
pub mod sortedness;
pub mod string_sort;

/// The width of a character projection key, whose values are in
/// `[−1, 2^α)` with `α = 8` (§7.2): `α + 1`.
pub const PROJECTION_WIDTH: usize = 9;

fn check_failed(message: &str) -> SnarkError {
    SnarkError::VerifierError(VerifierError::VerifierCheckFailed(message.to_string()))
}
