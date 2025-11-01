use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{
        lde::LDE,
        mle::MLE,
        utils::{build_eq_x_r, build_sparse_eq_x_r},
    },
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{Prover, structs::polynomial::TrackedPoly},
    verifier::{
        Verifier,
        structs::oracle::{Oracle, TrackedOracle},
    },
};
use ark_poly::Polynomial;
use derivative::Derivative;
use std::marker::PhantomData;

use crate::{
    local_single_col_sort_check::{self, LocalSingleColSortCheckProverInput},
    zero_expr_check::{ZeroExprCheckPIOP, ZeroExprCheckProverInput},
};

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct MultiColSortCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub tracked_cols: Vec<TrackedCol<F, MvPCS, UvPCS>>,
    pub tie_indicator_tracked_cols: Vec<TrackedCol<F, MvPCS, UvPCS>>,
    pub shift_tracked_cols: Vec<TrackedCol<F, MvPCS, UvPCS>>,
    pub ascending: bool,
    pub strict: bool,
}

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for MultiColSortCheckProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            tracked_cols: self
                .tracked_cols
                .iter()
                .map(|col| col.deep_clone(prover.clone()))
                .collect(),
            tie_indicator_tracked_cols: self
                .tie_indicator_tracked_cols
                .iter()
                .map(|col| col.deep_clone(prover.clone()))
                .collect(),
            shift_tracked_cols: self
                .shift_tracked_cols
                .iter()
                .map(|col| col.deep_clone(prover.clone()))
                .collect(),
            ascending: self.ascending,
            strict: self.strict,
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct MultiColSortCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub tracked_col_oracles: Vec<TrackedColOracle<F, MvPCS, UvPCS>>,
    pub tie_indicator_tracked_col_oracles: Vec<TrackedColOracle<F, MvPCS, UvPCS>>,
    pub shift_tracked_col_oracles: Vec<TrackedColOracle<F, MvPCS, UvPCS>>,
    pub ascending: bool,
    pub strict: bool,
}

pub struct MultiColSortCheckPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    PhantomData<F>,
    PhantomData<MvPCS>,
    PhantomData<UvPCS>,
);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for MultiColSortCheckPIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = MultiColSortCheckProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierInput = MultiColSortCheckVerifierInput<F, MvPCS, UvPCS>;
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(_input: Self::ProverInput) -> SnarkResult<()> {
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let activator_tracked_poly = input.tracked_cols[0].activator_tracked_poly();
        let num_cols = input.tracked_cols.len();
        let num_vars = input.tracked_cols[0].data_tracked_poly().log_size();
        let mut current_diff_col: Option<TrackedCol<F, MvPCS, UvPCS>> = None;

        for i in 0..num_cols {
            let tie_indicator_col = if i == 0 {
                Self::first_tie_indicator_col(prover, num_vars, activator_tracked_poly.clone())
            } else {
                let zero_expr_check_prover_input = ZeroExprCheckProverInput {
                    tracked_col: current_diff_col.clone().unwrap(),
                    selector_col: Some(input.tie_indicator_tracked_cols[i - 1].clone()),
                };
                ZeroExprCheckPIOP::prove(prover, zero_expr_check_prover_input)?;
                input.tie_indicator_tracked_cols[i].clone()
            };

            let local_single_col_sort_check_prover_input = LocalSingleColSortCheckProverInput {
                tracked_col: input.tracked_cols[i].clone(),
                tie_indicator_col,
                shift_col: input.shift_tracked_cols[i].clone(),
                ascending: input.ascending,
                strict: input.strict,
                is_last_col: i == num_cols - 1,
            };
            let local_single_col_sort_check_prover_output =
                local_single_col_sort_check::LocalSingleColSortCheckPIOP::prove(
                    prover,
                    local_single_col_sort_check_prover_input,
                )?;
            current_diff_col = Some(local_single_col_sort_check_prover_output.diff_col);
        }

        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        _input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let _ = verifier;
        Ok(())
    }
}

impl<F, MvPCS, UvPCS> MultiColSortCheckPIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn first_tie_indicator_col(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        num_vars: usize,
        activator_tracked_poly: Option<TrackedPoly<F, MvPCS, UvPCS>>,
    ) -> TrackedCol<F, MvPCS, UvPCS> {
        let one_tracked_poly = prover.track_mat_mv_cnst_poly(num_vars, F::one());
        let last_eq_poly = build_eq_x_r(&vec![F::one(); num_vars]).unwrap();
        let tracked_last_eq_poly = prover.track_mat_mv_poly(last_eq_poly.as_ref().clone());
        let first_tie_indicator_tracked_poly = &one_tracked_poly - &tracked_last_eq_poly;
        TrackedCol::new(
            first_tie_indicator_tracked_poly,
            activator_tracked_poly,
            None,
        )
    }

    fn first_tie_indicator_col_oracle(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        num_vars: usize,
        activator_tracked_oracle: Option<TrackedOracle<F, MvPCS, UvPCS>>,
    ) -> TrackedColOracle<F, MvPCS, UvPCS> {
        let one_tracked_oracle = verifier.track_mat_mv_cnst_oracle(num_vars, F::one());
        let last_eq_sparse_poly = build_sparse_eq_x_r(&vec![F::one(); num_vars]).unwrap();
        let last_eq_sparse_oracle = Oracle::new_multivariate(num_vars, move |point: Vec<F>| {
            Ok(last_eq_sparse_poly.evaluate(&point))
        });
        let tracked_last_eq_oracle = verifier.track_oracle(last_eq_sparse_oracle);
        let first_tie_indicator_tracked_oracle = &one_tracked_oracle - &tracked_last_eq_oracle;
        TrackedColOracle::new(
            first_tie_indicator_tracked_oracle,
            activator_tracked_oracle,
            None,
        )
    }
}
