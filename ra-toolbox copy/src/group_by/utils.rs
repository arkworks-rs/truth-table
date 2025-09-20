use arithmetic::col::{ArithCol, ColCom};
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
    col_comms: &[ColCom<F, MvPCS, UvPCS>],
    challs: &[F],
) -> ColCom<F, MvPCS, UvPCS> {
    let num_vars = col_comms[0].num_vars();
    let folding_size = col_comms.len();
    let actv = col_comms[0].actv.clone();
    #[cfg(debug_assertions)]
    {
        debug_assert_eq!(folding_size, challs.len());
        for col in col_comms.iter() {
            debug_assert_eq!(col.actv, actv);
            debug_assert_eq!(col.num_vars(), num_vars);
        }
    }
    let mut folded: TrackedOracle<F, MvPCS, UvPCS> = &col_comms[0].inner * (challs[0]);
    for i in 1..col_comms.len() {
        folded = &folded + &(&col_comms[i].inner * (challs[i]));
    }
    ColCom::new(None, folded, actv, num_vars)
}
