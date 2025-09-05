////////////// Imports //////////////

use arithmetic::{
    col::{ArithCol, ColCom},
    table::{ArithTable, TableComm},
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::Prover,
    timed,
    verifier::Verifier,
};
use ark_std::{cfg_iter, cfg_iter_mut, end_timer, start_timer};
use col_toolbox::{
    no_zeros_check::{NoZerosCheck, NoZerosCheckProverInput, NoZerosCheckVerifierInput},
    sign_check::{SignCheckPIOP, SignCheckProverInput, SignCheckVerifierInput},
};
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

pub struct SelectionCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub query_input_table: ArithTable<F, MvPCS, UvPCS>,
    pub query_output_table: ArithTable<F, MvPCS, UvPCS>,
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
    pub query_output_table_comm: TableComm<F, MvPCS, UvPCS>,
    pub query_input_table_comm: TableComm<F, MvPCS, UvPCS>,
    pub select_conf: SelectConfig<F>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for SelectionCheckPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = SelectionCheckProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = SelectionCheckVerifierInput<F, MvPCS, UvPCS>;

    #[timed]
    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        match input.select_conf.where_clause {
            WhereClause::Eq(col_ind, filter) => Ok(()),
            WhereClause::Geq(col_ind, filter) => Ok(()),
            WhereClause::Leq(col_ind, filter) => Ok(()),
            _ => Ok(()),
        }
    }

    #[timed]
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

    #[timed]
    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        match input.select_conf.where_clause {
            WhereClause::Eq(col_ind, filter) => Self::verify_eq_selection(
                verifier,
                input.query_input_table_comm.col(col_ind),
                input.query_output_table_comm.col(col_ind),
                filter,
            )?,
            WhereClause::Geq(col_ind, filter) => Self::verify_geq_selection(
                verifier,
                input.query_input_table_comm.col(col_ind),
                input.query_output_table_comm.col(col_ind).clone(),
                filter,
            )?,
            WhereClause::Leq(col_ind, filter) => Self::verify_leq_selection(
                verifier,
                input.query_input_table_comm.col(col_ind),
                input.query_output_table_comm.col(col_ind).clone(),
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
    #[timed]
    fn build_selected_and_non_selected_cols(
        input_col: &ArithCol<F, MvPCS, UvPCS>,
        output_col: &ArithCol<F, MvPCS, UvPCS>,
        filter: F,
    ) -> (ArithCol<F, MvPCS, UvPCS>, ArithCol<F, MvPCS, UvPCS>) {
        let selected_actv = input_col
            .actvtr_poly()
            .unwrap()
            * (output_col.actvtr_poly().unwrap());

        let complement = output_col.actvtr_poly().unwrap() * (-F::one());
        let complement = &complement + F::one();
        let non_selected_actv =
            input_col.actvtr_poly().unwrap() * &complement;
        let shifted_inner = (input_col.data_poly()) - filter;

        (
            ArithCol::new(
                input_col.data_type().clone(),
                shifted_inner.clone(),
                Some(selected_actv),
            ),
            ArithCol::new(
                input_col.data_type().clone(),
                shifted_inner,
                Some(non_selected_actv),
            ),
        )
    }

    #[timed]
    fn build_selected_and_non_selected_col_comms(
        input_col_comm: &ColCom<F, MvPCS, UvPCS>,
        output_col_comm: &ColCom<F, MvPCS, UvPCS>,
        filter: F,
    ) -> (ColCom<F, MvPCS, UvPCS>, ColCom<F, MvPCS, UvPCS>) {
        let selected_actv =
            input_col_comm.actv.as_ref().unwrap() * (output_col_comm.actv.as_ref().unwrap());

        let non_selected_actv = input_col_comm.actv.as_ref().unwrap()
            * &(&(output_col_comm.actv.as_ref().unwrap() * (-F::one())) + F::one());

        let shifted_inner = &input_col_comm.inner - filter;

        (
            ColCom {
                data_type: input_col_comm.data_type.clone(),
                inner: shifted_inner.clone(),
                actv: Some(selected_actv),
                num_vars: input_col_comm.num_vars,
            },
            ColCom {
                data_type: input_col_comm.data_type.clone(),
                inner: shifted_inner,
                actv: Some(non_selected_actv),
                num_vars: input_col_comm.num_vars,
            },
        )
    }

    #[timed]
    fn prove_eq_selection(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input_col: ArithCol<F, MvPCS, UvPCS>,
        output_col: ArithCol<F, MvPCS, UvPCS>,
        eq_filter: F,
    ) -> SnarkResult<()> {
        let (selected_col, non_selected_col) =
            Self::build_selected_and_non_selected_cols(&input_col, &output_col, eq_filter);
        // check wether all of the selected rows equal to eq_filter

        prover.add_mv_zerocheck_claim(selected_col.activated_data_poly().id())?;

        // check all of the rows that were not selected are not equal eq_filter
        let no_zeros_check_prover_input = NoZerosCheckProverInput {
            col: non_selected_col,
        };
        NoZerosCheck::prove(prover, no_zeros_check_prover_input)?;
        Ok(())
    }

    #[timed]
    fn verify_eq_selection(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input_col_comm: ColCom<F, MvPCS, UvPCS>,
        output_col_comm: ColCom<F, MvPCS, UvPCS>,
        eq_filter: F,
    ) -> SnarkResult<()> {
        let (selected_col_comm, non_selected_col_comm) =
            Self::build_selected_and_non_selected_col_comms(
                &input_col_comm,
                &output_col_comm,
                eq_filter,
            );
        verifier.add_zerocheck_claim(selected_col_comm.effective_comm().id);
        let no_zeros_check_verifier_input = NoZerosCheckVerifierInput {
            col_comm: non_selected_col_comm,
        };
        NoZerosCheck::verify(verifier, no_zeros_check_verifier_input)?;
        Ok(())
    }

    fn prove_geq_selection(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input_col: ArithCol<F, MvPCS, UvPCS>,
        output_col: ArithCol<F, MvPCS, UvPCS>,
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
        input_col_comm: ColCom<F, MvPCS, UvPCS>,
        output_col_comm: ColCom<F, MvPCS, UvPCS>,
        geq_filter: F,
    ) -> SnarkResult<()> {
        let (selected_col_comm, non_selected_col_comm) =
            Self::build_selected_and_non_selected_col_comms(
                &input_col_comm,
                &output_col_comm,
                geq_filter,
            );
        // Check if the selected ones are greater than or equal to the filter
        // The selected ones are the ones that are active in both the input and output
        let non_neg_sign_check_verifier_input = SignCheckVerifierInput {
            col_comm: selected_col_comm,
            sign: col_toolbox::sign_check::Sign::NoneNegative,
        };
        SignCheckPIOP::verify(verifier, non_neg_sign_check_verifier_input)?;

        // Check if the selected one are greater than or equal to the filter
        // The non-selected ones are the ones that were active in the input table but
        // not in the output table
        let neg_sign_check_verifier_input = SignCheckVerifierInput {
            col_comm: non_selected_col_comm,
            sign: col_toolbox::sign_check::Sign::Negative,
        };

        SignCheckPIOP::verify(verifier, neg_sign_check_verifier_input)?;

        Ok(())
    }

    fn prove_leq_selection(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input_col: ArithCol<F, MvPCS, UvPCS>,
        output_col: ArithCol<F, MvPCS, UvPCS>,
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
        input_col_comm: ColCom<F, MvPCS, UvPCS>,
        output_col_comm: ColCom<F, MvPCS, UvPCS>,
        geq_filter: F,
    ) -> SnarkResult<()> {
        let (selected_col_comm, non_selected_col_comm) =
            Self::build_selected_and_non_selected_col_comms(
                &input_col_comm,
                &output_col_comm,
                geq_filter,
            );
        // Check if the selected ones are greater than or equal to the filter
        // The selected ones are the ones that are active in both the input and output
        let non_neg_sign_check_verifier_input = SignCheckVerifierInput {
            col_comm: selected_col_comm,
            sign: col_toolbox::sign_check::Sign::NonePositive,
        };
        SignCheckPIOP::verify(verifier, non_neg_sign_check_verifier_input)?;

        // Check if the selected one are greater than or equal to the filter
        // The non-selected ones are the ones that were active in the input table but
        // not in the output table
        let neg_sign_check_verifier_input = SignCheckVerifierInput {
            col_comm: non_selected_col_comm,
            sign: col_toolbox::sign_check::Sign::Positive,
        };

        SignCheckPIOP::verify(verifier, neg_sign_check_verifier_input)?;

        Ok(())
    }

    #[timed]
    fn broadcast_actv_col(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input_col: ArithCol<F, MvPCS, UvPCS>,
        output_col: ArithCol<F, MvPCS, UvPCS>,
    ) -> SnarkResult<ArithCol<F, MvPCS, UvPCS>> {
        // let mut selected_hash_set: HashSet<F> = HashSet::new();
        let output_inner_evals = output_col.data_poly().evaluations();
        let selected_hash_set: HashSet<F> = match output_col.actvtr_poly() {
            Some(ref actv_tr_p) => {
                let output_actv_evals = actv_tr_p.evaluations();
                cfg_iter!(output_actv_evals)
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
        let input_inner_evals = input_col.data_poly().evaluations(); // Get the inner evaluations of the input column
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

        let broadcasted_actv = prover.track_and_commit_mat_mv_poly(&broadcasted_selector_mle)?;
        Ok(ArithCol::new(
            input_col.data_type(),
            input_col.data_poly().clone(),
            Some(broadcasted_actv),
        ))
    }

    fn broadcast_actv_col_com(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input_col_com: ColCom<F, MvPCS, UvPCS>,
    ) -> SnarkResult<ColCom<F, MvPCS, UvPCS>> {
        let broadcasted_actv_id = verifier.peek_next_id(); // Get the next ID for the broadcasted activator
        let broadcasted_actv_tr_com = verifier.track_mv_com_by_id(broadcasted_actv_id)?;
        Ok(ColCom {
            data_type: input_col_com.data_type.clone(),
            inner: input_col_com.inner.clone(),
            actv: Some(broadcasted_actv_tr_com),
            num_vars: input_col_com.num_vars,
        })
    }
}
