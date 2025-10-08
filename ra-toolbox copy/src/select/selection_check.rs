////////////// Imports //////////////

use arithmetic::{
    col::{TrackedCol, TrackedColOracle},
    table::{TrackedTable, TrackedTableOracle},
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::Prover,
    verifier::Verifier,
};
use ark_std::{cfg_iter, cfg_iter_mut, end_timer, start_timer};
use col_toolbox::{
    no_zeros_check::{NoZerosCheck, NoZerosCheckProverInput, NoZerosCheckVerifierInput},
    sign_check::{SignCheckPIOP, SignCheckProverInput, SignCheckVerifierInput},
};
use derivative::Derivative;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use std::{collections::HashSet, marker::PhantomData};

use super::structs::{SelectConfig, WhereClause};
use ark_piop::errors::SnarkResult;

pub struct SelectionCheckPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    PhantomData<F>,
    PhantomData<MvPCS>,
    PhantomData<UvPCS>,
);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct SelectionCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub query_input_table: TrackedTable<F, MvPCS, UvPCS>,
    pub query_output_table: TrackedTable<F, MvPCS, UvPCS>,
    pub select_conf: SelectConfig<F>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for SelectionCheckProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            query_input_table: self.query_input_table.deep_clone(prover.clone()),
            query_output_table: self.query_output_table.deep_clone(prover),
            select_conf: self.select_conf.clone(),
        }
    }
}

pub struct SelectionCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub query_output_tracked_Table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub query_input_tracked_Table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub select_conf: SelectConfig<F>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for SelectionCheckPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = SelectionCheckProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = SelectionCheckVerifierInput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        match input.select_conf.where_clause {
            WhereClause::Eq(col_ind, filter) => Ok(()),
            WhereClause::Geq(col_ind, filter) => Ok(()),
            WhereClause::Leq(col_ind, filter) => Ok(()),
            _ => Ok(()),
        }
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        match input.select_conf.where_clause {
            WhereClause::Eq(col_ind, filter) => Self::prove_eq_selection(
                prover,
                input.query_input_table.col(col_ind),
                input.query_output_table.col(col_ind),
                filter,
            )?,
            WhereClause::Geq(col_ind, filter) => Self::prove_geq_selection(
                prover,
                input.query_input_table.col(col_ind),
                input.query_output_table.col(col_ind),
                filter,
            )?,
            WhereClause::Leq(col_ind, filter) => Self::prove_leq_selection(
                prover,
                input.query_input_table.col(col_ind),
                input.query_output_table.col(col_ind),
                filter,
            )?,
            _ => unimplemented!(),
        };
        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        match input.select_conf.where_clause {
            WhereClause::Eq(col_ind, filter) => Self::verify_eq_selection(
                verifier,
                input.query_input_tracked_Table_oracle.col(col_ind),
                input.query_output_tracked_Table_oracle.col(col_ind),
                filter,
            )?,
            WhereClause::Geq(col_ind, filter) => Self::verify_geq_selection(
                verifier,
                input.query_input_tracked_Table_oracle.col(col_ind),
                input.query_output_tracked_Table_oracle.col(col_ind).clone(),
                filter,
            )?,
            WhereClause::Leq(col_ind, filter) => Self::verify_leq_selection(
                verifier,
                input.query_input_tracked_Table_oracle.col(col_ind),
                input.query_output_tracked_Table_oracle.col(col_ind).clone(),
                filter,
            )?,
            _ => unimplemented!(),
        };
        Ok(())
    }
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    SelectionCheckPIOP<F, MvPCS, UvPCS>
{
    fn build_selected_and_non_selected_cols(
        input_col: &TrackedCol<F, MvPCS, UvPCS>,
        output_col: &TrackedCol<F, MvPCS, UvPCS>,
        filter: F,
    ) -> (TrackedCol<F, MvPCS, UvPCS>, TrackedCol<F, MvPCS, UvPCS>) {
        let selected_activator = input_col.activator_tracked_poly().unwrap() * (output_col.activator_tracked_poly().unwrap());

        let complement = output_col.activator_tracked_poly().unwrap() * (-F::one());
        let complement = &complement + F::one();
        let non_selected_activator = input_col.activator_tracked_poly().unwrap() * &complement;
        let shifted_inner = (input_col.data_tracked_poly()) - filter;

        (
            TrackedCol::new(
                input_col.data_type().clone(),
                shifted_inner.clone(),
                Some(selected_activator),
            ),
            TrackedCol::new(
                input_col.data_type().clone(),
                shifted_inner,
                Some(non_selected_activator),
            ),
        )
    }

    fn build_selected_and_non_selected_tracked_col_oracles(
        input_tracked_col_oracle: &TrackedColOracle<F, MvPCS, UvPCS>,
        output_tracked_col_oracle: &TrackedColOracle<F, MvPCS, UvPCS>,
        filter: F,
    ) -> (TrackedColOracle<F, MvPCS, UvPCS>, TrackedColOracle<F, MvPCS, UvPCS>) {
        let selected_activator =
            input_tracked_col_oracle.activator.as_ref().unwrap() * (output_tracked_col_oracle.activator.as_ref().unwrap());

        let non_selected_activator = input_tracked_col_oracle.activator.as_ref().unwrap()
            * &(&(output_tracked_col_oracle.activator.as_ref().unwrap() * (-F::one())) + F::one());

        let shifted_inner = &input_tracked_col_oracle.inner - filter;

        (
            TrackedColOracle {
                data_type: input_tracked_col_oracle.data_type.clone(),
                inner: shifted_inner.clone(),
                activator: Some(selected_activator),
                num_vars: input_tracked_col_oracle.num_vars,
            },
            TrackedColOracle {
                data_type: input_tracked_col_oracle.data_type.clone(),
                inner: shifted_inner,
                activator: Some(non_selected_activator),
                num_vars: input_tracked_col_oracle.num_vars,
            },
        )
    }

    fn prove_eq_selection(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input_col: TrackedCol<F, MvPCS, UvPCS>,
        output_col: TrackedCol<F, MvPCS, UvPCS>,
        eq_filter: F,
    ) -> SnarkResult<()> {
        let (selected_col, non_selected_col) =
            Self::build_selected_and_non_selected_cols(&input_col, &output_col, eq_filter);
        // check wether all of the selected rows equal to eq_filter

        prover.add_mv_zerocheck_claim(selected_col.activated_data_tracked_poly().id())?;

        // check all of the rows that were not selected are not equal eq_filter
        let no_zeros_check_prover_input = NoZerosCheckProverInput {
            col: non_selected_col,
        };
        NoZerosCheck::prove(prover, no_zeros_check_prover_input)?;
        Ok(())
    }

    fn verify_eq_selection(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input_tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
        output_tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
        eq_filter: F,
    ) -> SnarkResult<()> {
        let (selected_tracked_col_oracle, non_selected_tracked_col_oracle) =
            Self::build_selected_and_non_selected_tracked_col_oracles(
                &input_tracked_col_oracle,
                &output_tracked_col_oracle,
                eq_filter,
            );
        verifier.add_zerocheck_claim(selected_tracked_col_oracle.effective_comm().id);
        let no_zeros_check_verifier_input = NoZerosCheckVerifierInput {
            tracked_col_oracle: non_selected_tracked_col_oracle,
        };
        NoZerosCheck::verify(verifier, no_zeros_check_verifier_input)?;
        Ok(())
    }

    fn prove_geq_selection(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input_col: TrackedCol<F, MvPCS, UvPCS>,
        output_col: TrackedCol<F, MvPCS, UvPCS>,
        geq_filter: F,
    ) -> SnarkResult<()> {
        let (selected_col, non_selected_col) =
            Self::build_selected_and_non_selected_cols(&input_col, &output_col, geq_filter);
        // Check if the selected ones are greater than or equal to the filter
        // The selected ones are the ones that are active in both the input and output
        // tables

        let non_neg_sign_check_prover_input = SignCheckProverInput {
            col: selected_col,
            sign: col_toolbox::sign_check::Sign::NoneNegative,
        };
        SignCheckPIOP::prove(prover, non_neg_sign_check_prover_input)?;

        // Check if the non-selected ones are less than the filter
        // The non-selected ones are the ones that were active in the input table but
        // not in the output table
        let neg_sign_check_prover_input = SignCheckProverInput {
            col: non_selected_col,
            sign: col_toolbox::sign_check::Sign::Negative,
        };
        SignCheckPIOP::prove(prover, neg_sign_check_prover_input)?;

        Ok(())
    }

    fn verify_geq_selection(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input_tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
        output_tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
        geq_filter: F,
    ) -> SnarkResult<()> {
        let (selected_tracked_col_oracle, non_selected_tracked_col_oracle) =
            Self::build_selected_and_non_selected_tracked_col_oracles(
                &input_tracked_col_oracle,
                &output_tracked_col_oracle,
                geq_filter,
            );
        // Check if the selected ones are greater than or equal to the filter
        // The selected ones are the ones that are active in both the input and output
        let non_neg_sign_check_verifier_input = SignCheckVerifierInput {
            tracked_col_oracle: selected_tracked_col_oracle,
            sign: col_toolbox::sign_check::Sign::NoneNegative,
        };
        SignCheckPIOP::verify(verifier, non_neg_sign_check_verifier_input)?;

        // Check if the selected one are greater than or equal to the filter
        // The non-selected ones are the ones that were active in the input table but
        // not in the output table
        let neg_sign_check_verifier_input = SignCheckVerifierInput {
            tracked_col_oracle: non_selected_tracked_col_oracle,
            sign: col_toolbox::sign_check::Sign::Negative,
        };

        SignCheckPIOP::verify(verifier, neg_sign_check_verifier_input)?;

        Ok(())
    }

    fn prove_leq_selection(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input_col: TrackedCol<F, MvPCS, UvPCS>,
        output_col: TrackedCol<F, MvPCS, UvPCS>,
        geq_filter: F,
    ) -> SnarkResult<()> {
        let (selected_col, non_selected_col) =
            Self::build_selected_and_non_selected_cols(&input_col, &output_col, geq_filter);
        // Check if the selected ones are greater than or equal to the filter
        // The selected ones are the ones that are active in both the input and output
        // tables
        let non_pos_sign_check_prover_input = SignCheckProverInput {
            col: selected_col,
            sign: col_toolbox::sign_check::Sign::NonePositive,
        };

        SignCheckPIOP::prove(prover, non_pos_sign_check_prover_input)?;
        // Check if the non-selected ones are less than the filter
        // The non-selected ones are the ones that were active in the input table but
        // not in the output table
        let pos_sign_check_prover_input = SignCheckProverInput {
            col: non_selected_col,
            sign: col_toolbox::sign_check::Sign::Positive,
        };

        SignCheckPIOP::prove(prover, pos_sign_check_prover_input)?;

        Ok(())
    }

    fn verify_leq_selection(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input_tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
        output_tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
        geq_filter: F,
    ) -> SnarkResult<()> {
        let (selected_tracked_col_oracle, non_selected_tracked_col_oracle) =
            Self::build_selected_and_non_selected_tracked_col_oracles(
                &input_tracked_col_oracle,
                &output_tracked_col_oracle,
                geq_filter,
            );
        // Check if the selected ones are greater than or equal to the filter
        // The selected ones are the ones that are active in both the input and output
        let non_neg_sign_check_verifier_input = SignCheckVerifierInput {
            tracked_col_oracle: selected_tracked_col_oracle,
            sign: col_toolbox::sign_check::Sign::NonePositive,
        };
        SignCheckPIOP::verify(verifier, non_neg_sign_check_verifier_input)?;

        // Check if the selected one are greater than or equal to the filter
        // The non-selected ones are the ones that were active in the input table but
        // not in the output table
        let neg_sign_check_verifier_input = SignCheckVerifierInput {
            tracked_col_oracle: non_selected_tracked_col_oracle,
            sign: col_toolbox::sign_check::Sign::Positive,
        };

        SignCheckPIOP::verify(verifier, neg_sign_check_verifier_input)?;

        Ok(())
    }

    fn broadcast_activator_col(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input_col: TrackedCol<F, MvPCS, UvPCS>,
        output_col: TrackedCol<F, MvPCS, UvPCS>,
    ) -> SnarkResult<TrackedCol<F, MvPCS, UvPCS>> {
        // let mut selected_hash_set: HashSet<F> = HashSet::new();
        let output_inner_evals = output_col.data_tracked_poly().evaluations();
        let selected_hash_set: HashSet<F> = match output_col.activator_tracked_poly() {
            Some(ref activator_tr_p) => {
                let output_activator_evals = activator_tr_p.evaluations();
                cfg_iter!(output_activator_evals)
                    .zip(cfg_iter!(output_inner_evals))
                    .filter(|(is_active, _inner_eval)| {
                        // Filter the evaluations where the activator is one and the inner
                        // evaluation is not zero
                        is_active.is_one()
                    })
                    .map(|(_, inner_eval)| {
                        // Collect the inner evaluations that are selected
                        *inner_eval
                    })
                    .collect::<HashSet<F>>() // Collect into a HashSet
            },
            None => {
                // If there is no activator, just use the inner evaluations directly
                // This means all evaluations in the output column are selected
                // Collect all inner evaluations into a HashSet
                cfg_iter!(output_inner_evals)
                    .map(|inner_eval| *inner_eval)
                    .collect::<HashSet<F>>()
            },
        };
        let mut broadcasted_selector_evals = vec![F::zero(); 1 << input_col.num_vars()]; // Initialize with zeroes
        let input_inner_evals = input_col.data_tracked_poly().evaluations(); // Get the inner evaluations of the input column
        cfg_iter_mut!(broadcasted_selector_evals)
            .zip(cfg_iter!(input_inner_evals)) // Zip the broadcasted selector evaluations with the input inner evaluations
            .for_each(|(broadcast_eval, inner_eval)| {
                // For each evaluation in the input column, check if it is in the selected set
                if selected_hash_set.contains(inner_eval) {
                    *broadcast_eval = F::one(); // Mark as one if it is in the selected set
                }
            });
        let broadcasted_selector_mle =
            MLE::from_evaluations_vec(input_col.num_vars(), broadcasted_selector_evals.clone());

        let broadcasted_activator = prover.track_and_commit_mat_mv_poly(&broadcasted_selector_mle)?;
        Ok(TrackedCol::new(
            input_col.data_type(),
            input_col.data_tracked_poly().clone(),
            Some(broadcasted_activator),
        ))
    }

    fn broadcast_activator_tracked_col_oracle(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input_tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    ) -> SnarkResult<TrackedColOracle<F, MvPCS, UvPCS>> {
        let broadcasted_activator_id = verifier.peek_next_id(); // Get the next ID for the broadcasted activator
        let broadcasted_activator_tr_com = verifier.track_mv_com_by_id(broadcasted_activator_id)?;
        Ok(TrackedColOracle {
            data_type: input_tracked_col_oracle.data_type.clone(),
            inner: input_tracked_col_oracle.inner.clone(),
            activator: Some(broadcasted_activator_tr_com),
            num_vars: input_tracked_col_oracle.num_vars,
        })
    }
}
