use arithmetic::col::TrackedCol;
use ark_piop::{SnarkBackend, arithmetic::mat_poly::mle::MLE};

use crate::irs::nodes::utils::lookup::{
    active_mask_from_optional, expected_lookup_multiplicities_from_values,
};

/// The MLE of the multiplicities of the super column's elements in the
/// claimed included columns, counted over all of them together. A value's
/// count sits on its first active super row; later duplicates get 0.
pub fn calc_inclusion_multiplicity<B>(
    included_cols: &[TrackedCol<B>],
    super_col: &TrackedCol<B>,
) -> MLE<B::F>
where
    B: SnarkBackend,
{
    let super_evals = super_col.data_tracked_poly().evaluations();
    let super_active = active_mask_from_optional(
        super_col
            .activator_tracked_poly()
            .map(|sel| sel.evaluations())
            .as_ref(),
        super_evals.len(),
    );

    let mut included_evals = Vec::new();
    let mut included_active = Vec::new();
    for included_col in included_cols {
        let evals = included_col.data_tracked_poly().evaluations();
        included_active.extend(active_mask_from_optional(
            included_col
                .activator_tracked_poly()
                .map(|sel| sel.evaluations())
                .as_ref(),
            evals.len(),
        ));
        included_evals.extend(evals);
    }

    let counts = expected_lookup_multiplicities_from_values::<B>(
        &[super_evals],
        &[included_evals],
        &super_active,
        &included_active,
    );
    MLE::from_u64s(counts, super_col.log_size())
}
