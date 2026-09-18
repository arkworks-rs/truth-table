pub mod activator_consistency_check;
pub mod bool;
pub mod broadcast_check;
pub mod contig_sort;
pub mod data_preserving_update_check;
pub mod eq;
pub mod factor_placement;
pub mod gen_sort;
pub mod geq;
pub mod keyed_sumcheck;
pub mod length_filtering_check;
pub mod leq;
pub mod lookup;
pub mod match_pair_check;
pub mod multi_character_pattern_matching;
pub mod neq;
pub mod nodup;
pub mod perm;
pub mod prescr_perm;
pub mod remat;
pub mod result_check;
pub mod rotation_check;
pub mod sign;
pub mod supp;
pub mod sweep_factors;

use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_piop::{
    SnarkBackend,
    errors::{SnarkError, SnarkResult},
    verifier::errors::VerifierError,
};

fn row_domain_error(message: impl Into<String>) -> SnarkError {
    SnarkError::VerifierError(VerifierError::VerifierCheckFailed(message.into()))
}

/// Validate the release-critical invariants of a table's row-domain columns.
///
/// Side-domain segments are deliberately excluded: strings and other split
/// encodings may store those segments on smaller, separate domains. Every
/// row-domain data polynomial and its paired activator must belong to the same
/// proof tracker and the table's declared log size. This includes constants:
/// downstream lookup and counting code derives iteration domains from stored
/// polynomial sizes, so accepting a scalar with a different ambient size can
/// make separate checks reason about different numbers of rows.
/// `TrackedTable` constructors historically checked these conditions only
/// under debug assertions, so proof code must call this before trusting
/// `table.log_size()` or combining its columns algebraically.
pub(crate) fn validate_tracked_table_row_domain<B: SnarkBackend>(
    table: &TrackedTable<B>,
    label: &str,
) -> SnarkResult<()> {
    let mut representative: Option<ark_piop::prover::structs::polynomial::TrackedPoly<B>> = None;
    for (field, column) in table.tracked_cols_iter() {
        for (suffix, data, activator) in column.segments_iter() {
            let segment = suffix
                .map(|suffix| format!("{}{suffix}", field.name()))
                .unwrap_or_else(|| field.name().to_string());
            if let Some(first) = &representative {
                if !first.same_tracker(data) {
                    return Err(row_domain_error(format!(
                        "{label} segment {segment} belongs to a different proof tracker"
                    )));
                }
            } else {
                representative = Some(data.clone());
            }
            if data.log_size() != table.log_size() {
                return Err(row_domain_error(format!(
                    "{label} segment {segment} has log size {}, expected {}",
                    data.log_size(),
                    table.log_size()
                )));
            }
            if let Some(activator) = activator {
                if !data.same_tracker(activator) {
                    return Err(row_domain_error(format!(
                        "{label} activator for segment {segment} belongs to a different proof tracker"
                    )));
                }
                if activator.log_size() != table.log_size() {
                    return Err(row_domain_error(format!(
                        "{label} activator for segment {segment} has log size {}, expected {}",
                        activator.log_size(),
                        table.log_size()
                    )));
                }
            }
        }
    }
    if representative.is_none() {
        return Err(row_domain_error(format!(
            "{label} must contain at least one row-domain column"
        )));
    }
    Ok(())
}

/// Verifier-side mirror of [`validate_tracked_table_row_domain`].
pub(crate) fn validate_tracked_oracle_table_row_domain<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    label: &str,
) -> SnarkResult<()> {
    let mut representative: Option<ark_piop::verifier::structs::oracle::TrackedOracle<B>> = None;
    for (field, column) in table.tracked_col_oracles_iter() {
        for (suffix, data, activator) in column.segments_iter() {
            let segment = suffix
                .map(|suffix| format!("{}{suffix}", field.name()))
                .unwrap_or_else(|| field.name().to_string());
            if let Some(first) = &representative {
                if !first.same_tracker(data) {
                    return Err(row_domain_error(format!(
                        "{label} segment {segment} belongs to a different proof tracker"
                    )));
                }
            } else {
                representative = Some(data.clone());
            }
            if data.log_size() != table.log_size() {
                return Err(row_domain_error(format!(
                    "{label} segment {segment} has log size {}, expected {}",
                    data.log_size(),
                    table.log_size()
                )));
            }
            if let Some(activator) = activator {
                if !data.same_tracker(activator) {
                    return Err(row_domain_error(format!(
                        "{label} activator for segment {segment} belongs to a different proof tracker"
                    )));
                }
                if activator.log_size() != table.log_size() {
                    return Err(row_domain_error(format!(
                        "{label} activator for segment {segment} has log size {}, expected {}",
                        activator.log_size(),
                        table.log_size()
                    )));
                }
            }
        }
    }
    if representative.is_none() {
        return Err(row_domain_error(format!(
            "{label} must contain at least one row-domain oracle"
        )));
    }
    Ok(())
}
