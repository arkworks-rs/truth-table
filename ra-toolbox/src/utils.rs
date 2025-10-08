use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    prover::structs::polynomial::TrackedPoly,
    verifier::structs::oracle::TrackedOracle,
};

pub fn fold_polys<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    cols: &[TrackedCol<F, MvPCS, UvPCS>],
    challs: &[F],
) -> TrackedCol<F, MvPCS, UvPCS> {
    let folding_size = cols.len();
    let activator = cols[0].activator_tracked_poly().clone();
    #[cfg(debug_assertions)]
    {
        debug_assert_eq!(folding_size, challs.len());
        for col in cols.iter() {
            debug_assert_eq!(col.activator_tracked_poly(), activator);
        }
    }
    let mut folded: TrackedPoly<F, MvPCS, UvPCS> = &cols[0].data_tracked_poly() * challs[0];
    for i in 1..cols.len() {
        folded += &(&cols[i].data_tracked_poly() * challs[i]);
    }
    TrackedCol::new(folded, activator.clone(), None)
}

pub fn fold_coms<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    tracked_col_oracles: &[TrackedColOracle<F, MvPCS, UvPCS>],
    challs: &[F],
) -> TrackedColOracle<F, MvPCS, UvPCS> {
    let num_vars = tracked_col_oracles[0].log_size();
    let folding_size = tracked_col_oracles.len();
    let activator = tracked_col_oracles[0].activator_tracked_oracle().clone();
    #[cfg(debug_assertions)]
    {
        debug_assert_eq!(folding_size, challs.len());
        for col in tracked_col_oracles.iter() {
            debug_assert_eq!(col.activator_tracked_oracle(), activator);
            debug_assert_eq!(col.log_size(), num_vars);
        }
    }
    let mut folded: TrackedOracle<F, MvPCS, UvPCS> =
        &tracked_col_oracles[0].data_tracked_oracle() * (challs[0]);
    for i in 1..tracked_col_oracles.len() {
        folded = &folded + &(&tracked_col_oracles[i].data_tracked_oracle() * (challs[i]));
    }
    TrackedColOracle::new(folded, activator, None)
}
