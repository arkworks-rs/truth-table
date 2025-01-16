mod test;
use ark_ec::pairing::Pairing;
use ark_poly::DenseMultilinearExtension;
use ark_std::{end_timer, start_timer, One};
use std::marker::PhantomData;

use crate::{
    subroutines::{pcs::PolynomialCommitmentScheme, ZeroCheck},
    tracker::prelude::*,
    col_toolbox::no_zeros_check::{NoZerosCheck, },
    col_toolbox::binary_check::SelectorValidIOP,
};

pub struct SelEqPIOP<F:PrimeField, PCS: PolynomialCommitmentScheme<F>>(
    PhantomData<F>,
    PhantomData<PCS>,
);

impl<F:PrimeField, PCS: PolynomialCommitmentScheme<F>> SelEqPIOP<F, PCS>
where
    PCS: PolynomialCommitmentScheme<F>,
    F:PrimeField
{
    pub fn prove(
        tracker: &mut ProverTrackerRef<F, PCS>,
        input_col: &Col<F, PCS>,
        output_col: &Col<F, PCS>,
        eq_filter: F,
    ) -> Result<(), PolyIOPErrors> {
        let timer = start_timer!(|| " SELECT COLUMN WHERE A=B prove");
        // check input shape is correct
        if input_col.num_vars() != output_col.num_vars() {
            return Err(PolyIOPErrors::InvalidParameters(
                "Select-Eq Error: fx and gx have different number of variables".to_string(),
            ));
        }
        let nv = input_col.num_vars();

        let select_valid = start_timer!(|| " Select valid");
        // First check the output column activator is valid or not
        SelectorValidIOP::<F, PCS>::prove(tracker, &output_col.actv_poly)?;
        end_timer!(timer);

        // Then check wether all of the selected rows equal to eq_filter
        let filtered_rows = start_timer!(|| " filtered rows");
        let zero_col = output_col
            .inner_poly
            .add_scalar(-eq_filter)
            .mul_poly(&output_col.actv_poly);
        tracker.add_zerocheck_claim(zero_col.id);
        end_timer!(filtered_rows);

        // Finally check all of the rows that were not selected are not equal to
        // eq_filter
        let non_filtered_rows = start_timer!(|| " filtered rows");
        let one_minus_sel = output_col
            .actv_poly
            .mul_scalar(-F::one())
            .add_scalar(F::one());
        let poly_minus_filter = output_col.inner_poly.add_scalar(-eq_filter);
        NoZerosCheck::prove(
            tracker,
            &Col {
                inner_poly: poly_minus_filter,
                actv_poly: one_minus_sel,
            },
        )?;
        end_timer!(non_filtered_rows);
        end_timer!(timer);
        Ok(())
    }

    pub fn verify(
        tracker: &mut VerifierTrackerRef<F, PCS>,
        input_col: &ColComm<F, PCS>,
        output_col: &ColComm<F, PCS>,
        eq_filter: F,
    ) -> Result<(), PolyIOPErrors> {
        let timer = start_timer!(|| " SELECT COLUMN WHERE A=B verify");

        SelectorValidIOP::<F, PCS>::verify(tracker, &input_col.selector)?;

        let zero_col = output_col
            .poly
            .add_scalar(-eq_filter)
            .mul_comms(&output_col.selector);
        tracker.add_zerocheck_claim(zero_col.id);
        let one_minus_sel = input_col
            .selector
            .mul_scalar(-F::one())
            .add_scalar(F::one());
        let poly_minus_filter = output_col.poly.add_scalar(-eq_filter);
        NoZerosCheck::verify(
            tracker,
            &ColComm::new(poly_minus_filter, one_minus_sel, output_col.num_vars()),
        )?;

        end_timer!(timer);
        Ok(())
    }
}
