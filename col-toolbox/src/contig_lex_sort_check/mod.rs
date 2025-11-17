use arithmetic::{
    col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
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
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{
        Verifier,
        structs::oracle::{Oracle, TrackedOracle},
    },
};
use ark_poly::Polynomial;
use derivative::Derivative;
use std::marker::PhantomData;

use crate::{
    local_single_col_sort_check::{
        LocalSingleColSortCheckPIOP, LocalSingleColSortCheckProverInput,
        LocalSingleColSortCheckVerifierInput,
    },
    zero_expr_check::{ZeroExprCheckPIOP, ZeroExprCheckProverInput, ZeroExprCheckVerifierInput},
};

#[cfg(test)]
mod test;

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct ContigLexSortCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub tracked_table: TrackedTable<F, MvPCS, UvPCS>,
    pub tie_indicator_tracked_table: Option<TrackedTable<F, MvPCS, UvPCS>>,
    pub shift_tracked_table: TrackedTable<F, MvPCS, UvPCS>,
    pub ascending: Vec<bool>,
    pub strict: Vec<bool>,
}

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for ContigLexSortCheckProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, prover: ArgProver<F, MvPCS, UvPCS>) -> Self {
        Self {
            tracked_table: self.tracked_table.deep_clone(prover.clone()),
            tie_indicator_tracked_table: self
                .tie_indicator_tracked_table
                .as_ref()
                .map(|table| table.deep_clone(prover.clone())),
            shift_tracked_table: self.shift_tracked_table.deep_clone(prover),
            ascending: self.ascending.clone(),
            strict: self.strict.clone(),
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct ContigLexSortCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub tie_indicator_tracked_table_oracle: Option<TrackedTableOracle<F, MvPCS, UvPCS>>,
    pub shift_tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub ascending: Vec<bool>,
    pub strict: Vec<bool>,
}

pub struct ContigLexSortCheckPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    PhantomData<F>,
    PhantomData<MvPCS>,
    PhantomData<UvPCS>,
);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for ContigLexSortCheckPIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = ContigLexSortCheckProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierInput = ContigLexSortCheckVerifierInput<F, MvPCS, UvPCS>;
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(_input: Self::ProverInput) -> SnarkResult<()> {
        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let num_cols = input.tracked_table.num_data_tracked_cols();
        let activator_tracked_poly = input.tracked_table.activator_tracked_poly();
        let num_vars = input.tracked_table.log_size();

        let mut current_diff_col: Option<TrackedCol<F, MvPCS, UvPCS>> = None;

        for i in 0..num_cols {
            let tracked_col = input.tracked_table.tracked_col_by_ind(i);
            let shift_col = input.shift_tracked_table.tracked_col_by_ind(i);
            let tie_indicator_col = if i == 0 {
                Self::first_tie_indicator_col(prover, num_vars, activator_tracked_poly.clone())
            } else {
                let selector_col = input
                    .tie_indicator_tracked_table
                    .clone()
                    .unwrap()
                    .tracked_col_by_ind(i - 1)
                    .clone();
                let zero_expr_check_prover_input = ZeroExprCheckProverInput {
                    tracked_col: current_diff_col.clone().unwrap(),
                    selector_col: selector_col.clone(),
                };

                ZeroExprCheckPIOP::prove(prover, zero_expr_check_prover_input)?;
                selector_col
            };

            let local_single_col_sort_check_prover_input = LocalSingleColSortCheckProverInput {
                tracked_col,
                tie_indicator_col,
                shift_col,
                ascending: input.ascending[i],
                strict: input.strict[i],
                is_last_col: i == num_cols - 1,
            };
            let local_single_col_sort_check_prover_output = LocalSingleColSortCheckPIOP::prove(
                prover,
                local_single_col_sort_check_prover_input,
            )?;
            current_diff_col = Some(local_single_col_sort_check_prover_output.diff_col);
        }

        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let num_col_oracles = input.tracked_table_oracle.num_data_tracked_col_oracles();

        let activator_tracked_oracle = input.tracked_table_oracle.activator_tracked_poly();
        let num_vars = input.tracked_table_oracle.log_size();
        let mut current_diff_col_oracle: Option<TrackedColOracle<F, MvPCS, UvPCS>> = None;

        for i in 0..num_col_oracles {
            let tracked_col_oracle = input.tracked_table_oracle.tracked_col_oracle_by_ind(i);
            let shift_col_oracle = input
                .shift_tracked_table_oracle
                .tracked_col_oracle_by_ind(i);
            let tie_indicator_col_oracle = if i == 0 {
                Some(Self::first_tie_indicator_col_oracle(
                    verifier,
                    num_vars,
                    activator_tracked_oracle.clone(),
                ))
            } else {
                let selector_col_oracle = input
                    .tie_indicator_tracked_table_oracle
                    .clone()
                    .unwrap()
                    .tracked_col_oracle_by_ind(i - 1)
                    .clone();
                let zero_expr_check_verifier_input = ZeroExprCheckVerifierInput {
                    tracked_col_oracle: current_diff_col_oracle.clone().unwrap(),
                    selector_col_oracle: selector_col_oracle.clone(),
                };
                ZeroExprCheckPIOP::verify(verifier, zero_expr_check_verifier_input)?;
                Some(selector_col_oracle)
            };

            let local_single_col_sort_check_verifier_input = LocalSingleColSortCheckVerifierInput {
                tracked_col_oracle,
                tie_indicator_col_oracle,
                shift_col_oracle,
                ascending: input.ascending[i],
                strict: input.strict[i],
                is_last_col_oracle: i == num_col_oracles - 1,
            };
            let local_single_col_sort_check_verifier_output = LocalSingleColSortCheckPIOP::verify(
                verifier,
                local_single_col_sort_check_verifier_input,
            )?;
            current_diff_col_oracle =
                Some(local_single_col_sort_check_verifier_output.diff_col_oracle);
        }
        Ok(())
    }
}

impl<F, MvPCS, UvPCS> ContigLexSortCheckPIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn first_tie_indicator_col(
        prover: &mut ArgProver<F, MvPCS, UvPCS>,
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
