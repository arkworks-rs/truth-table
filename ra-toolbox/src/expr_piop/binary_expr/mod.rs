use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::PrimeField;
#[cfg(feature = "honest-prover")]
use ark_piop::prover::structs::polynomial::TrackedPoly;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{SnarkError::ProverError, SnarkResult},
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{
        self, Prover,
        errors::{HonestProverError::FalseClaim, ProverError::HonestProverError},
    },
    verifier::Verifier,
};
use col_toolbox::{
    binary_check::{BinaryCheckPIOP, BinaryCheckProverInput, BinaryCheckVerifierInput},
    no_zeros_check::{NoZerosCheck, NoZerosCheckProverInput, NoZerosCheckVerifierInput},
};
use datafusion::logical_expr::Operator;
use derivative::Derivative;
#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct BinaryExprPIOPProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub op: Operator,
    pub left_col: TrackedCol<F, MvPCS, UvPCS>,
    pub right_col: TrackedCol<F, MvPCS, UvPCS>,
    pub output_col: TrackedCol<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for BinaryExprPIOPProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            op: self.op,
            left_col: self.left_col.deep_clone(prover.clone()),
            right_col: self.right_col.deep_clone(prover.clone()),
            output_col: self.output_col.deep_clone(prover),
        }
    }
}

#[derive(Clone, Debug)]
pub struct BinaryExprPIOPVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub op: Operator,
    pub left_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    pub right_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    pub output_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
}

pub struct BinaryExprPIOP<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    std::marker::PhantomData<F>,
    std::marker::PhantomData<MvPCS>,
    std::marker::PhantomData<UvPCS>,
);

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for BinaryExprPIOP<F, MvPCS, UvPCS>
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = BinaryExprPIOPProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = BinaryExprPIOPVerifierInput<F, MvPCS, UvPCS>;
    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        if input.left_col.data_poly().log_size() != input.right_col.data_poly().log_size()
            || input.left_col.data_poly().log_size() != input.output_col.data_poly().log_size()
        {
            return Err(ProverError(HonestProverError(FalseClaim)));
        }

        let left_act = input.left_col.actvtr_poly();
        let right_act = input.right_col.actvtr_poly();
        let output_act = input.output_col.actvtr_poly();
        if !activators_match::<F, MvPCS, UvPCS>(left_act, right_act)
            || !activators_match::<F, MvPCS, UvPCS>(left_act, output_act)
            || !activators_match::<F, MvPCS, UvPCS>(right_act, output_act)
        {
            return Err(ProverError(HonestProverError(FalseClaim)));
        }
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        match input.op {
            Operator::And => {},
            Operator::Or => {
                let binary_check_prover_input = BinaryCheckProverInput {
                    predicate: input.output_col.activated_data_poly().clone(),
                };
                BinaryCheckPIOP::prove(prover, binary_check_prover_input)?;





            },
            Operator::Eq => {
                let binary_check_prover_input = BinaryCheckProverInput {
                    predicate: input.output_col.activated_data_poly().clone(),
                };
                BinaryCheckPIOP::prove(prover, binary_check_prover_input)?;

                let actv = input.left_col.actvtr_poly();
                let zero_poly = match actv {
                    Some(actv_poly) => {
                        &(input.left_col.data_poly() - input.right_col.data_poly())
                            * &(input.output_col.data_poly() * actv_poly)
                    },
                    None => {
                        &(input.left_col.data_poly() - input.right_col.data_poly())
                            * input.output_col.data_poly()
                    },
                };
                prover.add_mv_zerocheck_claim(zero_poly.id())?;

                let no_zero_col = TrackedCol::new(
                    None,
                    &(input.left_col.data_poly() - input.right_col.data_poly())
                        * &(input.output_col.data_poly() - F::one()),
                    actv.cloned(),
                );
                NoZerosCheck::<F, MvPCS, UvPCS>::prove(
                    prover,
                    NoZerosCheckProverInput { col: no_zero_col },
                )?;
            },
            Operator::NotEq => todo!(),
            Operator::Lt => todo!(),
            Operator::LtEq => todo!(),
            Operator::Gt => todo!(),
            Operator::GtEq => todo!(),
            _ => panic!("Unsupported binary operator in BinaryExprPIOP"),
        }
        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        match input.op {
            Operator::And => todo!(),
            Operator::Or => todo!(),
            Operator::Eq => {
                let binary_check_verifier_input = BinaryCheckVerifierInput {
                    predicate_oracle: input.output_col_oracle.activated_data_oracle().clone(),
                };
                BinaryCheckPIOP::verify(verifier, binary_check_verifier_input)?;

                let actv = input.left_col_oracle.actvtr_oracle();
                let zero_oracle = match actv {
                    Some(actv_poly) => {
                        &(input.left_col_oracle.data_oracle()
                            - input.right_col_oracle.data_oracle())
                            * &(input.output_col_oracle.data_oracle() * actv_poly)
                    },
                    None => {
                        &(input.left_col_oracle.data_oracle()
                            - input.right_col_oracle.data_oracle())
                            * input.output_col_oracle.data_oracle()
                    },
                };
                verifier.add_zerocheck_claim(zero_oracle.id());

                let no_zero_oracle = TrackedColOracle::new(
                    None,
                    &(input.left_col_oracle.data_oracle() - input.right_col_oracle.data_oracle())
                        * &(input.output_col_oracle.data_oracle() - F::one()),
                    actv.cloned(),
                    input.left_col_oracle.num_vars(),
                );
                NoZerosCheck::<F, MvPCS, UvPCS>::verify(
                    verifier,
                    NoZerosCheckVerifierInput {
                        tracked_col_oracle: no_zero_oracle,
                    },
                )?;
            },
            Operator::NotEq => todo!(),
            Operator::Lt => todo!(),
            Operator::LtEq => todo!(),
            Operator::Gt => todo!(),
            Operator::GtEq => todo!(),
            _ => panic!("Unsupported binary operator in BinaryExprPIOP"),
        }
        Ok(())
    }
}

#[cfg(feature = "honest-prover")]
fn activators_match<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    lhs: Option<&TrackedPoly<F, MvPCS, UvPCS>>,
    rhs: Option<&TrackedPoly<F, MvPCS, UvPCS>>,
) -> bool {
    match (lhs, rhs) {
        (None, None) => true,
        (Some(poly), None) | (None, Some(poly)) => activator_is_all_ones(poly),
        (Some(lhs_poly), Some(rhs_poly)) => {
            lhs_poly.log_size() == rhs_poly.log_size()
                && lhs_poly.evaluations() == rhs_poly.evaluations()
        },
    }
}
#[cfg(feature = "honest-prover")]
fn activator_is_all_ones<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    poly: &TrackedPoly<F, MvPCS, UvPCS>,
) -> bool {
    poly.evaluations().into_iter().all(|val| val == F::one())
}
