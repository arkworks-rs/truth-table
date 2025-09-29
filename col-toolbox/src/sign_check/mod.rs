//! A PIOP to prove that a column is positive, non-negative, negative, or
//! non-positive
// Moew precisely, this PIOP checks if the activated elements of column with a
// specific type (e.g. UInt8, UInt16, Int32, etc.) are positive, non-negative,
// negative, or non-positive based on the `Sign` enum provided. This is mainly
// done by using inclusion checks in their respective range polynomials which
// are provided at the setup time.

#[cfg(test)]
mod test;

mod utils;
use crate::{
    inclusion_check::{InclusionCheckPIOP, InclusionCheckProverInput, InclusionCheckVerifierInput},
    no_zeros_check::{NoZerosCheck, NoZerosCheckProverInput, NoZerosCheckVerifierInput},
};
use arithmetic::col::{ArithCol, ColCom};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{SnarkError, SnarkResult},
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::Prover,
    verifier::{Verifier, structs::oracle::Oracle},
};
use ark_poly::Polynomial;
use ark_std::{cfg_iter, end_timer, start_timer};
use datafusion::arrow::datatypes::DataType;
use derivative::Derivative;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::{marker::PhantomData, sync::Arc};

#[derive(Debug, Clone, Copy)]
pub enum Sign {
    Positive,
    NoneNegative,
    Negative,
    NonePositive,
}

pub struct SignCheckPIOP<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    PhantomData<F>,
    PhantomData<MvPCS>,
    PhantomData<UvPCS>,
);
#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct SignCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub col: ArithCol<F, MvPCS, UvPCS>,
    pub sign: Sign,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for SignCheckProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, new_prover: Prover<F, MvPCS, UvPCS>) -> Self {
        SignCheckProverInput {
            col: self.col.deep_clone(new_prover),
            sign: self.sign,
        }
    }
}

pub struct SignCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub col_comm: ColCom<F, MvPCS, UvPCS>,
    pub sign: Sign,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for SignCheckPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = SignCheckProverInput<F, MvPCS, UvPCS>;
    type VerifierInput = SignCheckVerifierInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        // TODO
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        prover_input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        match prover_input.sign {
            Sign::NoneNegative => {
                SignCheckPIOP::prove_non_neg(prover, &prover_input.col)?;
            },
            Sign::Positive => {
                SignCheckPIOP::prove_positive(prover, &prover_input.col)?;
            },
            Sign::Negative => {
                SignCheckPIOP::prove_negative(prover, &prover_input.col)?;
            },
            Sign::NonePositive => {
                SignCheckPIOP::prove_none_positive(prover, &prover_input.col)?;
            },
        }
        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        verifier_input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        match verifier_input.sign {
            Sign::Positive => {
                Self::verify_positive(verifier, &verifier_input.col_comm)?;
            },
            Sign::NoneNegative => {
                Self::verify_non_neg(verifier, &verifier_input.col_comm)?;
            },
            Sign::Negative => {
                Self::verify_negative(verifier, &verifier_input.col_comm)?;
            },
            Sign::NonePositive => {
                Self::verify_none_positive(verifier, &verifier_input.col_comm)?;
            },
        }
        Ok(())
    }
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    SignCheckPIOP<F, MvPCS, UvPCS>
{
    pub fn prove_positive(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        col: &ArithCol<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Self::prove_non_neg(prover, col)?;
        NoZerosCheck::prove(prover, NoZerosCheckProverInput { col: col.clone() })?;
        Ok(())
    }

    pub fn verify_positive(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        col_comm: &ColCom<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Self::verify_non_neg(verifier, col_comm)?;
        NoZerosCheck::verify(
            verifier,
            NoZerosCheckVerifierInput {
                col_comm: col_comm.clone(),
            },
        )?;
        Ok(())
    }

    pub fn prove_negative(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        col: &ArithCol<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Self::prove_none_positive(prover, col)?;
        NoZerosCheck::prove(prover, NoZerosCheckProverInput { col: col.clone() })?;
        Ok(())
    }

    pub fn verify_negative(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        col_comm: &ColCom<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Self::verify_none_positive(verifier, col_comm)?;
        NoZerosCheck::verify(
            verifier,
            NoZerosCheckVerifierInput {
                col_comm: col_comm.clone(),
            },
        )?;
        Ok(())
    }
    pub fn prove_none_positive(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        col: &ArithCol<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let negated_col = ArithCol::new(
            col.data_type().clone(),
            &col.data_poly().clone() * (-F::one()),
            col.actvtr_poly().cloned(),
        );
        Self::prove_non_neg(prover, &negated_col)?;
        Ok(())
    }

    pub fn verify_none_positive(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        col_comm: &ColCom<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let negated_comm = ColCom::new(
            col_comm.data_type.clone(),
            &col_comm.inner.clone() * (-F::one()),
            col_comm.actv.clone(),
            col_comm.num_vars,
        );
        Self::verify_non_neg(verifier, &negated_comm)?;
        Ok(())
    }
    pub fn prove_non_neg(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        col: &ArithCol<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        match col.data_type().as_ref().unwrap() {
            DataType::UInt8 => {
                let inclusion_check_prover_input = InclusionCheckProverInput {
                    included_col: col.clone(),
                    super_col: ArithCol::new(
                        None,
                        prover.track_mat_mv_poly(Self::dense_range_poly_by_nv(8).unwrap()),
                        None,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(prover, inclusion_check_prover_input)?;
            },
            DataType::Int8 => {
                let inclusion_check_prover_input = InclusionCheckProverInput {
                    included_col: col.clone(),
                    super_col: ArithCol::new(
                        None,
                        prover.track_mat_mv_poly(Self::dense_range_poly_by_nv(7).unwrap()),
                        None,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(prover, inclusion_check_prover_input)?;
            },
            DataType::UInt16 => {
                let inclusion_check_prover_input = InclusionCheckProverInput {
                    included_col: col.clone(),
                    super_col: ArithCol::new(
                        None,
                        prover.track_mat_mv_poly(Self::dense_range_poly_by_nv(16).unwrap()),
                        None,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(prover, inclusion_check_prover_input)?;
            },
            DataType::Int16 => {
                let inclusion_check_prover_input = InclusionCheckProverInput {
                    included_col: col.clone(),
                    super_col: ArithCol::new(
                        None,
                        prover.track_mat_mv_poly(Self::dense_range_poly_by_nv(15).unwrap()),
                        None,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(prover, inclusion_check_prover_input)?;
            },
            DataType::UInt32 => {
                let (high_col, low_col) = Self::prove_non_neg_uint32(prover, col)?;
                let high_inclusion_check_prover_input = InclusionCheckProverInput {
                    included_col: high_col.clone(),
                    super_col: ArithCol::new(
                        None,
                        prover.track_mat_mv_poly(Self::dense_range_poly_by_nv(16).unwrap()),
                        None,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(
                    prover,
                    high_inclusion_check_prover_input,
                )?;
                let low_inclusion_check_prover_input = InclusionCheckProverInput {
                    included_col: low_col.clone(),
                    super_col: ArithCol::new(
                        None,
                        prover.track_mat_mv_poly(Self::dense_range_poly_by_nv(16).unwrap()),
                        None,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(
                    prover,
                    low_inclusion_check_prover_input,
                )?;
            },
            DataType::Int32 => {
                let (high_col, low_col) = Self::prove_non_neg_uint32(prover, col)?;
                let high_inclusion_check_prover_input = InclusionCheckProverInput {
                    included_col: high_col.clone(),
                    super_col: ArithCol::new(
                        None,
                        prover.track_mat_mv_poly(Self::dense_range_poly_by_nv(15).unwrap()),
                        None,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(
                    prover,
                    high_inclusion_check_prover_input,
                )?;
                let low_inclusion_check_prover_input = InclusionCheckProverInput {
                    included_col: low_col.clone(),
                    super_col: ArithCol::new(
                        None,
                        prover.track_mat_mv_poly(Self::dense_range_poly_by_nv(16).unwrap()),
                        None,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(
                    prover,
                    low_inclusion_check_prover_input,
                )?;
            },

            _ => {
                return Err(SnarkError::DummyError);
            },
        }
        Ok(())
    }

    pub fn verify_non_neg(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        col_comm: &ColCom<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        match col_comm.data_type.as_ref().unwrap() {
            DataType::UInt8 => {
                let inclusion_check_prover_input = InclusionCheckVerifierInput {
                    included_col_comm: col_comm.clone(),
                    super_col_comm: ColCom::new(
                        None,
                        verifier.track_oracle(Oracle::Multivariate(Arc::new(move |x| {
                            Ok(Self::sparse_range_poly_by_nv(8)?.evaluate(&x))
                        }))),
                        None,
                        8,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(
                    verifier,
                    inclusion_check_prover_input,
                )?;
            },

            DataType::Int8 => {
                let inclusion_check_prover_input = InclusionCheckVerifierInput {
                    included_col_comm: col_comm.clone(),
                    super_col_comm: ColCom::new(
                        None,
                        verifier.track_oracle(Oracle::Multivariate(Arc::new(move |x| {
                            Ok(Self::sparse_range_poly_by_nv(7)?.evaluate(&x))
                        }))),
                        None,
                        7,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(
                    verifier,
                    inclusion_check_prover_input,
                )?;
            },

            DataType::UInt16 => {
                let inclusion_check_prover_input = InclusionCheckVerifierInput {
                    included_col_comm: col_comm.clone(),
                    super_col_comm: ColCom::new(
                        None,
                        verifier.track_oracle(Oracle::Multivariate(Arc::new(move |x| {
                            Ok(Self::sparse_range_poly_by_nv(16)?.evaluate(&x))
                        }))),
                        None,
                        16,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(
                    verifier,
                    inclusion_check_prover_input,
                )?;
            },
            DataType::UInt32 => {
                let (high_col_com, low_col_com) = Self::verify_non_neg_uint32(verifier, col_comm)?;
                let high_inclusion_check_verifier_input = InclusionCheckVerifierInput {
                    included_col_comm: high_col_com.clone(),
                    super_col_comm: ColCom::new(
                        None,
                        verifier.track_oracle(Oracle::Multivariate(Arc::new(move |x| {
                            Ok(Self::sparse_range_poly_by_nv(16)?.evaluate(&x))
                        }))),
                        None,
                        16,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(
                    verifier,
                    high_inclusion_check_verifier_input,
                )?;
                let low_inclusion_check_verifier_input = InclusionCheckVerifierInput {
                    included_col_comm: low_col_com.clone(),
                    super_col_comm: ColCom::new(
                        None,
                        verifier.track_oracle(Oracle::Multivariate(Arc::new(move |x| {
                            Ok(Self::sparse_range_poly_by_nv(16)?.evaluate(&x))
                        }))),
                        None,
                        16,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(
                    verifier,
                    low_inclusion_check_verifier_input,
                )?;
            },

            DataType::Int32 => {
                let (high_col_com, low_col_com) = Self::verify_non_neg_uint32(verifier, col_comm)?;
                let high_inclusion_check_verifier_input = InclusionCheckVerifierInput {
                    included_col_comm: high_col_com.clone(),
                    super_col_comm: ColCom::new(
                        None,
                        verifier.track_oracle(Oracle::Multivariate(Arc::new(move |x| {
                            Ok(Self::sparse_range_poly_by_nv(15)?.evaluate(&x))
                        }))),
                        None,
                        15,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(
                    verifier,
                    high_inclusion_check_verifier_input,
                )?;
                let low_inclusion_check_verifier_input = InclusionCheckVerifierInput {
                    included_col_comm: low_col_com.clone(),
                    super_col_comm: ColCom::new(
                        None,
                        verifier.track_oracle(Oracle::Multivariate(Arc::new(move |x| {
                            Ok(Self::sparse_range_poly_by_nv(16)?.evaluate(&x))
                        }))),
                        None,
                        16,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(
                    verifier,
                    low_inclusion_check_verifier_input,
                )?;
            },

            _ => {
                return Err(SnarkError::DummyError);
            },
        }
        Ok(())
    }

    #[allow(clippy::complexity)]
    pub fn prove_non_neg_uint32(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        col: &ArithCol<F, MvPCS, UvPCS>,
    ) -> SnarkResult<(ArithCol<F, MvPCS, UvPCS>, ArithCol<F, MvPCS, UvPCS>)> {
        let col_inner_evals = col.data_poly().evaluations();
        let (high_vals, low_vals): (Vec<F>, Vec<F>) = cfg_iter!(col_inner_evals)
            .map(|eval| {
                let big = eval.into_bigint(); // Returns BigInteger representation
                let n = big.as_ref()[0] as u32;
                let (high, low) = Self::split_u32_into_u16s(n);
                (F::from(high as u64), F::from(low as u64))
            })
            .unzip();

        let high_tr_p = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(col.num_vars(), high_vals))?;
        let low_tr_p = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(col.num_vars(), low_vals))?;

        let zero_tr_p = match &col.actvtr_poly() {
            Some(actv) => {
                let combined = col.data_poly() - &(&(&high_tr_p * F::from(1 << 16)) + &low_tr_p);
                &combined * *actv
            },
            None => col.data_poly() - &(&(&high_tr_p * F::from(1 << 16)) + &low_tr_p),
        };

        prover.add_mv_zerocheck_claim(zero_tr_p.id())?; // Add a zero check claim for the combined polynomial        

        Ok((
            ArithCol::new(
                col.data_type().clone(),
                high_tr_p,
                col.actvtr_poly().cloned(),
            ),
            ArithCol::new(
                col.data_type().clone(),
                low_tr_p,
                col.actvtr_poly().cloned(),
            ),
        ))
    }

    #[allow(clippy::complexity)]
    pub fn verify_non_neg_uint32(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        col_com: &ColCom<F, MvPCS, UvPCS>,
    ) -> SnarkResult<(ColCom<F, MvPCS, UvPCS>, ColCom<F, MvPCS, UvPCS>)> {
        let col_inner = col_com.inner.clone();
        let col_actv = col_com.actv.clone();
        let high_tr_id = verifier.peek_next_id();
        let high_tr_c = verifier.track_mv_com_by_id(high_tr_id)?;
        let low_tr_id = verifier.peek_next_id();
        let low_tr_c = verifier.track_mv_com_by_id(low_tr_id)?;

        let zero_tr_p = match &col_actv {
            Some(actv) => &(&col_inner - &(&(&high_tr_c * (F::from(1 << 16))) + &low_tr_c)) * actv,
            None => &col_inner - &(&(&high_tr_c * (F::from(1 << 16))) + &low_tr_c),
        };

        verifier.add_zerocheck_claim(zero_tr_p.id()); // Add a zero check claim for the combined polynomial        

        Ok((
            ColCom {
                data_type: col_com.data_type.clone(),
                inner: high_tr_c,
                actv: col_actv.clone(),
                num_vars: col_com.num_vars,
            },
            ColCom {
                data_type: col_com.data_type.clone(),
                inner: low_tr_c,
                actv: col_actv.clone(),
                num_vars: col_com.num_vars,
            },
        ))
    }

    #[allow(clippy::complexity)]
    pub fn prove_non_neg_int32(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        col: &ArithCol<F, MvPCS, UvPCS>,
    ) -> SnarkResult<(ArithCol<F, MvPCS, UvPCS>, ArithCol<F, MvPCS, UvPCS>)> {
        let col_inner_evals = col.data_poly().evaluations();
        let (high_vals, low_vals): (Vec<F>, Vec<F>) = cfg_iter!(col_inner_evals)
            .map(|eval| {
                let big = eval.into_bigint(); // Returns BigInteger representation
                let n = big.as_ref()[0] as i32;
                let (high, low) = Self::split_i32_into_i16s(n);
                (F::from(high as u64), F::from(low as u64))
            })
            .unzip();

        let high_tr_p = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(col.num_vars(), high_vals))?;
        let low_tr_p = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(col.num_vars(), low_vals))?;

        let zero_tr_p = match &col.actvtr_poly() {
            Some(actv) => {
                let combined = col.data_poly() - &(&(&high_tr_p * F::from(1 << 16)) + &low_tr_p);
                &combined * *actv
            },
            None => col.data_poly() - &(&(&high_tr_p * F::from(1 << 16)) + &low_tr_p),
        };

        prover.add_mv_zerocheck_claim(zero_tr_p.id())?; // Add a zero check claim for the combined polynomial        

        Ok((
            ArithCol::new(
                col.data_type().clone(),
                high_tr_p,
                col.actvtr_poly().cloned(),
            ),
            ArithCol::new(
                col.data_type().clone(),
                low_tr_p,
                col.actvtr_poly().cloned(),
            ),
        ))
    }

    #[allow(clippy::complexity)]
    pub fn verify_non_neg_int32(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        col_com: &ColCom<F, MvPCS, UvPCS>,
    ) -> SnarkResult<(ColCom<F, MvPCS, UvPCS>, ColCom<F, MvPCS, UvPCS>)> {
        let col_inner = col_com.inner.clone();
        let col_actv = col_com.actv.clone();
        let high_tr_id = verifier.peek_next_id();
        let high_tr_c = verifier.track_mv_com_by_id(high_tr_id)?;
        let low_tr_id = verifier.peek_next_id();
        let low_tr_c = verifier.track_mv_com_by_id(low_tr_id)?;

        let zero_tr_p = match &col_actv {
            Some(actv) => &(&col_inner - &(&(&high_tr_c * F::from(1 << 16)) + &low_tr_c)) * actv,
            None => &col_inner - &(&(&high_tr_c * F::from(1 << 16)) + &low_tr_c),
        };

        verifier.add_zerocheck_claim(zero_tr_p.id()); // Add a zero check claim for the combined polynomial        

        Ok((
            ColCom {
                data_type: col_com.data_type.clone(),
                inner: high_tr_c,
                actv: col_actv.clone(),
                num_vars: col_com.num_vars,
            },
            ColCom {
                data_type: col_com.data_type.clone(),
                inner: low_tr_c,
                actv: col_actv.clone(),
                num_vars: col_com.num_vars,
            },
        ))
    }

    fn split_u32_into_u16s(n: u32) -> (u16, u16) {
        let high = (n >> 16) as u16;
        let low = (n & 0xFFFF) as u16;
        (high, low)
    }

    fn split_i32_into_i16s(n: i32) -> (i16, i16) {
        let high = (n >> 16) as i16;
        let low = (n & 0xFFFF) as i16;
        (high, low)
    }
}
