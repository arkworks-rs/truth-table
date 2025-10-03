use std::marker::PhantomData;

use arithmetic::{
    col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{SnarkError::ProverError, SnarkResult},
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{
        Prover,
        errors::{HonestProverError::FalseClaim, ProverError::HonestProverError},
    },
    verifier::Verifier,
};
use datafusion::logical_expr::Filter;
use derivative::Derivative;
#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct FilterPIOPProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub filter: Filter,
    pub predicate_col: TrackedCol<F, MvPCS, UvPCS>,
    pub input_tracked_Table: TrackedTable<F, MvPCS, UvPCS>,
    pub output_tracked_Table: TrackedTable<F, MvPCS, UvPCS>,
}

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for FilterPIOPProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            filter: self.filter.clone(),
            predicate_col: self.predicate_col.deep_clone(prover.clone()),
            input_tracked_Table: self.input_tracked_Table.deep_clone(prover.clone()),
            output_tracked_Table: self.output_tracked_Table.deep_clone(prover),
        }
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct FilterPIOPVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub filter: Filter,
    pub predicate_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    pub input_tracked_Table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub output_tracked_Table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
}

pub struct FilterPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    PhantomData<F>,
    PhantomData<MvPCS>,
    PhantomData<UvPCS>,
);

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for FilterPIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = FilterPIOPProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = FilterPIOPVerifierInput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        // Create the selected and non-selected activator columns
        let zero_poly = match (
            input.input_tracked_Table.actvtr_poly(),
            input.output_tracked_Table.actvtr_poly(),
        ) {
            (Some(in_actv), Some(out_actv)) => {
                &out_actv - &(&in_actv * &input.predicate_col.activated_data_poly())
            },
            (Some(in_actv), None) => {
                &(&in_actv * &input.predicate_col.activated_data_poly()) + F::one().neg()
            },
            (None, Some(out_actv)) => &out_actv - &input.predicate_col.activated_data_poly(),
            (None, None) => &input.predicate_col.activated_data_poly() + F::one().neg(),
        };
        // Check if the zero polynomial is indeed zero on the domain
        for val in zero_poly.evaluations().iter() {
            if !val.is_zero() {
                return Err(ProverError(HonestProverError(FalseClaim)));
            }
        }

        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let zero_poly = match (
            input.input_tracked_Table.actvtr_poly(),
            input.output_tracked_Table.actvtr_poly(),
        ) {
            (Some(in_actv), Some(out_actv)) => {
                &out_actv - &(&in_actv * &input.predicate_col.activated_data_poly())
            },
            (Some(in_actv), None) => {
                &(&in_actv * &input.predicate_col.activated_data_poly()) + F::one().neg()
            },
            (None, Some(out_actv)) => &out_actv - &input.predicate_col.activated_data_poly(),
            (None, None) => &input.predicate_col.activated_data_poly() + F::one().neg(),
        };
        prover.add_mv_zerocheck_claim(zero_poly.id())?;

        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let zero_oracle = match (
            input.input_tracked_Table_oracle.actvtr_poly(),
            input.output_tracked_Table_oracle.actvtr_poly(),
        ) {
            (Some(in_actv), Some(out_actv)) => {
                &out_actv - &(&in_actv * &input.predicate_oracle.activated_data_oracle())
            },
            (Some(in_actv), None) => {
                &(&in_actv * &input.predicate_oracle.activated_data_oracle()) + F::one().neg()
            },
            (None, Some(out_actv)) => &out_actv - &input.predicate_oracle.activated_data_oracle(),
            (None, None) => &input.predicate_oracle.activated_data_oracle() + F::one().neg(),
        };
        verifier.add_zerocheck_claim(zero_oracle.id());

        Ok(())
    }
}

#[cfg(test)]
mod test;
