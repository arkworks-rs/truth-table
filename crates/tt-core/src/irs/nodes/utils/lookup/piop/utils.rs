use super::multiplicity_count::vec_multiplicity_count;
use arithmetic::col::TrackedCol;
use ark_ff::Zero;
use ark_piop::{SnarkBackend, arithmetic::mat_poly::mle::MLE};

// TODO: Check if it can be optimized. Also, put in the paper
/// The MLE of the multiplicities of the super column's elements in the
/// claimed included column. A value's count sits on its first active super
/// row; later duplicates get 0.
pub fn calc_inclusion_multiplicity<B>(
    included_col: &TrackedCol<B>,
    super_col: &TrackedCol<B>,
) -> MLE<B::F>
where
    B: SnarkBackend,
{
    let included_col_evals = included_col.data_tracked_poly().evaluations();
    let super_col_evals = super_col.data_tracked_poly().evaluations();

    let super_col_nv = super_col.log_size();
    let super_col_len = super_col_evals.len();

    let super_col_activator_evals = super_col
        .activator_tracked_poly()
        .as_ref()
        .map(|sel| sel.evaluations());

    let mut included_col_mults_map = match included_col.activator_tracked_poly() {
        Some(sel) => vec_multiplicity_count::<B::F>(&included_col_evals, Some(&sel.evaluations())),
        None => vec_multiplicity_count::<B::F>(&included_col_evals, None),
    };

    let mut super_col_mult_evals = Vec::with_capacity(super_col_len);

    for (i, &val) in super_col_evals.iter().enumerate() {
        if let Some(ref activator_evals) = super_col_activator_evals
            && activator_evals[i] == B::F::zero()
        {
            super_col_mult_evals.push(0);
            continue;
        }

        if let Some(&included_col_mult) = included_col_mults_map.get(&val) {
            super_col_mult_evals.push(included_col_mult);
            included_col_mults_map.insert(val, 0);
        } else {
            super_col_mult_evals.push(0);
        }
    }

    MLE::from_u64s(super_col_mult_evals, super_col_nv)
}
