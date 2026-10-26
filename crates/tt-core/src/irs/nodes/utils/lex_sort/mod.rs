//! The lexicographic order checks of TruthTable++ (§7, appendix §13): sorting on
//! several keys with chained tie indicators, and the character-level checks
//! a string order is proved with.

use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_piop::{
    SnarkBackend, prover::structs::polynomial::TrackedPoly,
    verifier::structs::oracle::TrackedOracle,
};

pub mod piop;
pub mod rank_certification;
#[cfg(test)]
pub(crate) mod sortedness;

fn data_polys<B: SnarkBackend>(table: &TrackedTable<B>) -> Vec<TrackedPoly<B>> {
    table
        .data_tracked_polys_indices()
        .into_iter()
        .map(|i| table.tracked_col_by_ind(i).data_tracked_poly())
        .collect()
}

fn data_oracles<B: SnarkBackend>(table: &TrackedTableOracle<B>) -> Vec<TrackedOracle<B>> {
    table
        .data_tracked_oracles_indices()
        .into_iter()
        .map(|i| table.tracked_col_oracle_by_ind(i).data_tracked_oracle())
        .collect()
}
