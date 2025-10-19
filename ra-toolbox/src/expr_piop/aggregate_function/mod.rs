use crate::expr_piop::impl_expr_piop_deep_clone;
use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::{PrimeField, Zero};
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{Prover, structs::polynomial::TrackedPoly},
    verifier::{Verifier, structs::oracle::TrackedOracle},
};
use datafusion::logical_expr::expr::AggregateFunction;
use derivative::Derivative;

const AGG_COUNT: &str = "count";
const AGG_SUM: &str = "sum";
const AGG_MAX: &str = "max";
const AGG_MIN: &str = "min";
const AGG_AVG: &str = "avg";
const AGG_APPROX_DISTINCT: &str = "approx_distinct";
const AGG_VAR: &str = "var";
const AGG_VARIANCE: &str = "variance";
const AGG_VAR_SAMP: &str = "var_samp";
const AGG_VARIANCE_SAMP: &str = "variance_samp";
const AGG_VAR_POP: &str = "var_pop";
const AGG_VARIANCE_POP: &str = "variance_pop";
const AGG_STDDEV: &str = "stddev";
const AGG_STD: &str = "std";
const AGG_STDDEV_SAMP: &str = "stddev_samp";
const AGG_STD_SAMP: &str = "std_samp";
const AGG_STDDEV_POP: &str = "stddev_pop";
const AGG_STD_POP: &str = "std_pop";
const AGG_MEDIAN: &str = "median";
const AGG_FIRST: &str = "first";
const AGG_FIRST_VALUE: &str = "first_value";
const AGG_LAST: &str = "last";
const AGG_LAST_VALUE: &str = "last_value";
#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct AggregateFunctionPIOPProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub aggregate: AggregateFunction,
    pub group_multiplicty_tracked_poly: TrackedPoly<F, MvPCS, UvPCS>,
    pub aggregated_col: TrackedCol<F, MvPCS, UvPCS>,
    pub input_col: TrackedCol<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for AggregateFunctionPIOPProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, new_prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            aggregate: self.aggregate.clone(),
            group_multiplicty_tracked_poly: self
                .group_multiplicty_tracked_poly
                .deep_clone(new_prover.clone()),
            aggregated_col: self.aggregated_col.deep_clone(new_prover.clone()),
            input_col: self.input_col.deep_clone(new_prover),
        }
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct AggregateFunctionPIOPVerifierInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub aggregate: datafusion::logical_expr::expr::AggregateFunction,
    pub group_multiplicty_tracked_oracle: TrackedOracle<F, MvPCS, UvPCS>,
    pub aggregated_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    pub input_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
}

pub struct AggregateFunctionExprPIOP<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    std::marker::PhantomData<F>,
    std::marker::PhantomData<MvPCS>,
    std::marker::PhantomData<UvPCS>,
);

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for AggregateFunctionExprPIOP<F, MvPCS, UvPCS>
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = AggregateFunctionPIOPProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = AggregateFunctionPIOPVerifierInput<F, MvPCS, UvPCS>;

    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        // TODO
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let AggregateFunctionPIOPProverInput {
            aggregate,
            group_multiplicty_tracked_poly,
            aggregated_col,
            input_col,
        } = input;

        match aggregate.func.name() {
            "count" => {
                dbg!(&group_multiplicty_tracked_poly.evaluations()[1489]);
                dbg!(&aggregated_col.data_tracked_poly().evaluations()[1489]);
                dbg!(&aggregated_col.activator_tracked_poly().unwrap().evaluations()[1489]);
                dbg!(&input_col.data_tracked_poly().evaluations()[1489]);
                dbg!(&input_col.activator_tracked_poly().unwrap().evaluations()[1489]);
                let zero_poly = match input_col.activator_tracked_poly() {
                    Some(activator_poly) => {
                        &(&aggregated_col.activated_data_tracked_poly()
                            - &group_multiplicty_tracked_poly)
                            * &activator_poly
                    },
                    None => {
                        &aggregated_col.activated_data_tracked_poly()
                            - &group_multiplicty_tracked_poly
                    },
                };
                dbg!(zero_poly.evaluations().into_iter().sum::<F>());
                dbg!(
                    zero_poly
                        .evaluations()
                        .iter()
                        .enumerate()
                        .filter(|(i, element)| !element.is_zero())
                        .collect::<Vec<_>>()
                );
                // prover.add_mv_zerocheck_claim(zero_poly.id())?;
                Ok(())
            },
            "sum" => todo!("AggregateFunctionExprPIOP::prove_inner sum"),
            "max" => todo!("AggregateFunctionExprPIOP::prove_inner max"),
            "min" => todo!("AggregateFunctionExprPIOP::prove_inner min"),
            "avg" => todo!("AggregateFunctionExprPIOP::prove_inner avg"),
            "approx_distinct" => {
                todo!("AggregateFunctionExprPIOP::prove_inner approx_distinct")
            },
            "var" | "variance" => todo!("AggregateFunctionExprPIOP::prove_inner variance"),
            "var_samp" | "variance_samp" => {
                todo!("AggregateFunctionExprPIOP::prove_inner variance_samp")
            },
            "var_pop" | "variance_pop" => {
                todo!("AggregateFunctionExprPIOP::prove_inner variance_pop")
            },
            "stddev" | "std" => todo!("AggregateFunctionExprPIOP::prove_inner stddev"),
            "stddev_samp" | "std_samp" => {
                todo!("AggregateFunctionExprPIOP::prove_inner stddev_samp")
            },
            "stddev_pop" | "std_pop" => {
                todo!("AggregateFunctionExprPIOP::prove_inner stddev_pop")
            },
            "median" => todo!("AggregateFunctionExprPIOP::prove_inner median"),
            "first" | "first_value" => {
                todo!("AggregateFunctionExprPIOP::prove_inner first_value")
            },
            "last" | "last_value" => {
                todo!("AggregateFunctionExprPIOP::prove_inner last_value")
            },
            other => todo!("AggregateFunctionExprPIOP::prove_inner unsupported aggregate {other}"),
        }
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let AggregateFunctionPIOPVerifierInput {
            aggregate,
            group_multiplicty_tracked_oracle,
            aggregated_col_oracle,
            input_col_oracle,
        } = input;

        match aggregate.func.name() {
            "count" => {
                let zero_col_oracle = match input_col_oracle.activator_tracked_oracle() {
                    Some(activator_poly) => {
                        &(&aggregated_col_oracle.activated_data_tracked_oracle()
                            - &group_multiplicty_tracked_oracle)
                            * &activator_poly
                    },
                    None => {
                        &aggregated_col_oracle.activated_data_tracked_oracle()
                            - &group_multiplicty_tracked_oracle
                    },
                };
                // verifier.add_zerocheck_claim(zero_col_oracle.id());
                Ok(())
            },
            "sum" => todo!("AggregateFunctionExprPIOP::verify sum"),
            "max" => todo!("AggregateFunctionExprPIOP::verify max"),
            "min" => todo!("AggregateFunctionExprPIOP::verify min"),
            "avg" => todo!("AggregateFunctionExprPIOP::verify avg"),
            "approx_distinct" => {
                todo!("AggregateFunctionExprPIOP::verify approx_distinct")
            },
            "var" | "variance" => todo!("AggregateFunctionExprPIOP::verify variance"),
            "var_samp" | "variance_samp" => {
                todo!("AggregateFunctionExprPIOP::verify variance_samp")
            },
            "var_pop" | "variance_pop" => {
                todo!("AggregateFunctionExprPIOP::verify variance_pop")
            },
            "stddev" | "std" => todo!("AggregateFunctionExprPIOP::verify stddev"),
            "stddev_samp" | "std_samp" => {
                todo!("AggregateFunctionExprPIOP::verify stddev_samp")
            },
            "stddev_pop" | "std_pop" => {
                todo!("AggregateFunctionExprPIOP::verify stddev_pop")
            },
            "median" => todo!("AggregateFunctionExprPIOP::verify median"),
            "first" | "first_value" => {
                todo!("AggregateFunctionExprPIOP::verify first_value")
            },
            "last" | "last_value" => {
                todo!("AggregateFunctionExprPIOP::verify last_value")
            },
            other => todo!("AggregateFunctionExprPIOP::verify unsupported aggregate {other}"),
        }
    }
}
