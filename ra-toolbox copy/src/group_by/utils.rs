use arithmetic::col::{ArithCol, ArithColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    prover::structs::polynomial::TrackedPoly,
    verifier::structs::oracle::TrackedOracle,
};

pub fn fold_polys<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    cols: &[ArithCol<F, MvPCS, UvPCS>],
    challs: &[F],
) -> ArithCol<F, MvPCS, UvPCS> {
    let folding_size = cols.len();
    let actv = cols[0].actvtr_poly().clone();
    #[cfg(debug_assertions)]
    {
        debug_assert_eq!(folding_size, challs.len());
        for col in cols.iter() {
            debug_assert_eq!(col.actvtr_poly(), actv);
        }
    }
    let mut folded: TrackedPoly<F, MvPCS, UvPCS> = cols[0].data_poly() * challs[0];
    for i in 1..cols.len() {
        folded += &(cols[i].data_poly() * challs[i]);
    }
    ArithCol::new(None, folded, actv.cloned())
}

pub fn fold_coms<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    arith_col_oracles: &[ArithColOracle<F, MvPCS, UvPCS>],
    challs: &[F],
) -> ArithColOracle<F, MvPCS, UvPCS> {
    let num_vars = arith_col_oracles[0].num_vars();
    let folding_size = arith_col_oracles.len();
    let actv = arith_col_oracles[0].actv.clone();
    #[cfg(debug_assertions)]
    {
        debug_assert_eq!(folding_size, challs.len());
        for col in arith_col_oracles.iter() {
            debug_assert_eq!(col.actv, actv);
            debug_assert_eq!(col.num_vars(), num_vars);
        }
    }
    let mut folded: TrackedOracle<F, MvPCS, UvPCS> = &arith_col_oracles[0].inner * (challs[0]);
    for i in 1..arith_col_oracles.len() {
        folded = &folded + &(&arith_col_oracles[i].inner * (challs[i]));
    }
    ArithColOracle::new(None, folded, actv, num_vars)
}
