use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{SnarkError, SnarkResult},
    pcs::PCS,
    piop::PIOP,
    prover::errors::{HonestProverError, ProverError},
};
use col_toolbox::binary_check::{BinaryCheckPIOP, BinaryCheckProverInput};

use super::{
    SelectCheckPIOP,
    selection_check::SelectionCheckProverInput,
    structs::{SelectProverInput, WhereClause},
};

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    SelectCheckPIOP<F, MvPCS, UvPCS>
{
    #[cfg(feature = "honest-prover")]
    pub(crate) fn honest_prover_check_helper(
        input: SelectProverInput<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let binary_check_input = BinaryCheckProverInput {
            activator: input.output_table.activator_tracked_poly().as_ref().unwrap().clone(),
        };
        BinaryCheckPIOP::<F, MvPCS, UvPCS>::honest_prover_check(binary_check_input)?;
        let selection_check_prover_input = SelectionCheckProverInput {
            query_input_table: input.input_table.clone(),
            query_output_table: input.output_table.clone(),
            select_conf: input.select_conf.clone(),
        };
        Self::selection_honest_prover_check_helper(selection_check_prover_input)
    }

    #[cfg(feature = "honest-prover")]
    pub(crate) fn selection_honest_prover_check_helper(
        input: SelectionCheckProverInput<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        match input.select_conf.where_clause {
            WhereClause::Eq(col_ind, filter) => {
                let input_col = input.query_input_table.col(col_ind);
                let in_data_vec = input_col.data_tracked_poly().evaluations();
                let output_col = input.query_output_table.col(col_ind);
                let out_data_vec = output_col.data_tracked_poly().evaluations();
                let all_one_vec = vec![F::one(); in_data_vec.len()];
                let filter_closure = |x: F| x == filter;
                let (in_activator_vec, out_activator_vec) =
                    match (input_col.activator_tracked_poly(), output_col.activator_tracked_poly()) {
                        (None, None) => (all_one_vec.clone(), all_one_vec),
                        (Some(input_activator), None) => {
                            let input_activator_vec = input_activator.evaluations();
                            (input_activator_vec, all_one_vec)
                        },
                        (None, Some(output_activator)) => {
                            let output_activator_vec = output_activator.evaluations();
                            (all_one_vec, output_activator_vec)
                        },
                        (Some(input_activator), Some(output_activator)) => {
                            let input_activator_vec = input_activator.evaluations();
                            let output_activator_vec = output_activator.evaluations();
                            (input_activator_vec, output_activator_vec)
                        },
                    };

                Self::filter_check_helper(
                    in_data_vec,
                    in_activator_vec,
                    out_data_vec,
                    out_activator_vec,
                    filter_closure,
                )
            },
            // TODO: Add the rest of the cases
            _ => Ok(()),
        }
    }

    #[cfg(feature = "honest-prover")]
    fn filter_check_helper<Filter>(
        in_data_vec: impl IntoIterator<Item = F>,
        in_activator_vec: impl IntoIterator<Item = F>,
        out_data_vec: impl IntoIterator<Item = F>,
        out_activator_vec: impl IntoIterator<Item = F>,
        f: Filter,
    ) -> SnarkResult<()>
    where
        Filter: Fn(F) -> bool,
    {
        if in_data_vec
            .into_iter()
            .zip(in_activator_vec)
            .zip(out_data_vec)
            .zip(out_activator_vec)
            .enumerate()
            .any(|(i, (((in_data, in_activator), out_data), out_activator))| {
                if in_activator.is_zero() {
                    // If the input is not activated, and the output is activated, then throw an
                    // error
                    if out_activator.is_one() {
                        return true;
                    } else {
                        // If the input is not activated, and the output is not activated, then
                        // throw an error
                        return false;
                    }
                } else if f(in_data) {
                    // the same as the in_data, then throw an error
                    if (out_activator.is_zero() || out_data != in_data) {
                        return true;
                    } else {
                        // If the in_data passes the filter, and the out_data is not activated, then
                        // throw an error
                        return false;
                    }
                } else {
                    // If the in_data does not pass the filter, if the out_data is activated, then
                    // throw an error

                    if (out_activator.is_one()) {
                        return true;
                    } else {
                        // If the in_data does not pass the filter, and the out_data is not
                        // activated, then throw an error
                        return false;
                    }
                }
            })
        {
            {
                Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )))
            }
        } else {
            Ok(())
        }
    }
}
