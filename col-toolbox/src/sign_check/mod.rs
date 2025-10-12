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
use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
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
    pub col: TrackedCol<F, MvPCS, UvPCS>,
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
    pub tracked_col_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
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
                Self::verify_positive(verifier, &verifier_input.tracked_col_oracle)?;
            },
            Sign::NoneNegative => {
                Self::verify_non_neg(verifier, &verifier_input.tracked_col_oracle)?;
            },
            Sign::Negative => {
                Self::verify_negative(verifier, &verifier_input.tracked_col_oracle)?;
            },
            Sign::NonePositive => {
                Self::verify_none_positive(verifier, &verifier_input.tracked_col_oracle)?;
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
        col: &TrackedCol<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Self::prove_non_neg(prover, col)?;
        NoZerosCheck::prove(prover, NoZerosCheckProverInput { col: col.clone() })?;
        Ok(())
    }

    pub fn verify_positive(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        tracked_col_oracle: &TrackedColOracle<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Self::verify_non_neg(verifier, tracked_col_oracle)?;
        NoZerosCheck::verify(
            verifier,
            NoZerosCheckVerifierInput {
                tracked_col_oracle: tracked_col_oracle.clone(),
            },
        )?;
        Ok(())
    }

    pub fn prove_negative(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        col: &TrackedCol<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Self::prove_none_positive(prover, col)?;
        NoZerosCheck::prove(prover, NoZerosCheckProverInput { col: col.clone() })?;
        Ok(())
    }

    pub fn verify_negative(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        tracked_col_oracle: &TrackedColOracle<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        Self::verify_none_positive(verifier, tracked_col_oracle)?;
        NoZerosCheck::verify(
            verifier,
            NoZerosCheckVerifierInput {
                tracked_col_oracle: tracked_col_oracle.clone(),
            },
        )?;
        Ok(())
    }
    pub fn prove_none_positive(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        col: &TrackedCol<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let negated_col = TrackedCol::new(
            &col.data_tracked_poly().clone() * (-F::one()),
            col.activator_tracked_poly(),
            col.field_ref().clone(),
        );
        Self::prove_non_neg(prover, &negated_col)?;
        Ok(())
    }

    pub fn verify_none_positive(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        tracked_col_oracle: &TrackedColOracle<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let negated_comm = TrackedColOracle::new(
            &tracked_col_oracle.data_tracked_oracle().clone() * (-F::one()),
            tracked_col_oracle.activator_tracked_oracle().clone(),
            tracked_col_oracle.field_ref().clone(),
        );
        Self::verify_non_neg(verifier, &negated_comm)?;
        Ok(())
    }
    pub fn prove_non_neg(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        col: &TrackedCol<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let field_ref = col.field_ref().unwrap();
        let data_type = field_ref.data_type();
        dbg!(data_type);
        match data_type {
            DataType::UInt8 => {
                let inclusion_check_prover_input = InclusionCheckProverInput {
                    included_cols: vec![col.clone()],
                    super_col: TrackedCol::new(
                        prover.track_mat_mv_poly(Self::dense_range_poly_by_nv(8).unwrap()),
                        None,
                        None,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(prover, inclusion_check_prover_input)?;
            },
            DataType::Int8 => {
                let inclusion_check_prover_input = InclusionCheckProverInput {
                    included_cols: vec![col.clone()],
                    super_col: TrackedCol::new(
                        prover.track_mat_mv_poly(Self::dense_range_poly_by_nv(7).unwrap()),
                        None,
                        None,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(prover, inclusion_check_prover_input)?;
            },
            DataType::UInt16 => {
                let inclusion_check_prover_input = InclusionCheckProverInput {
                    included_cols: vec![col.clone()],
                    super_col: TrackedCol::new(
                        prover.track_mat_mv_poly(Self::dense_range_poly_by_nv(16).unwrap()),
                        None,
                        None,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(prover, inclusion_check_prover_input)?;
            },
            DataType::Int16 => {
                let inclusion_check_prover_input = InclusionCheckProverInput {
                    included_cols: vec![col.clone()],
                    super_col: TrackedCol::new(
                        prover.track_mat_mv_poly(Self::dense_range_poly_by_nv(15).unwrap()),
                        None,
                        None,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(prover, inclusion_check_prover_input)?;
            },
            DataType::UInt32 => {
                let (chunk3, chunk2, chunk1, chunk0) = Self::prove_non_neg_uint32(prover, col)?;
                for segment in [chunk3, chunk2, chunk1, chunk0] {
                    let inclusion_check_prover_input = InclusionCheckProverInput {
                        included_cols: vec![segment],
                        super_col: TrackedCol::new(
                            prover.track_mat_mv_poly(Self::dense_range_poly_by_nv(16).unwrap()),
                            None,
                            None,
                        ),
                    };
                    InclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(
                        prover,
                        inclusion_check_prover_input,
                    )?;
                }
            },
            DataType::Int32 => {
                let (chunk3, chunk2, chunk1, chunk0) = Self::prove_non_neg_int32(prover, col)?;
                let top_inclusion_check_prover_input = InclusionCheckProverInput {
                    included_cols: vec![chunk3.clone()],
                    super_col: TrackedCol::new(
                        prover.track_mat_mv_poly(Self::dense_range_poly_by_nv(15).unwrap()),
                        None,
                        None,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(
                    prover,
                    top_inclusion_check_prover_input,
                )?;
                for segment in [chunk2, chunk1, chunk0] {
                    let inclusion_check_prover_input = InclusionCheckProverInput {
                        included_cols: vec![segment],
                        super_col: TrackedCol::new(
                            prover.track_mat_mv_poly(Self::dense_range_poly_by_nv(16).unwrap()),
                            None,
                            None,
                        ),
                    };
                    InclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(
                        prover,
                        inclusion_check_prover_input,
                    )?;
                }
            },
            DataType::UInt64 => {
                let (chunk3, chunk2, chunk1, chunk0) = Self::prove_non_neg_uint64(prover, col)?;
                for segment in [chunk3, chunk2, chunk1, chunk0] {
                    let inclusion_check_prover_input = InclusionCheckProverInput {
                        included_cols: vec![segment],
                        super_col: TrackedCol::new(
                            prover.track_mat_mv_poly(Self::dense_range_poly_by_nv(16).unwrap()),
                            None,
                            None,
                        ),
                    };
                    InclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(
                        prover,
                        inclusion_check_prover_input,
                    )?;
                }
            },
            DataType::Int64 => {
                let (chunk3, chunk2, chunk1, chunk0) = Self::prove_non_neg_int64(prover, col)?;
                let top_inclusion_check_prover_input = InclusionCheckProverInput {
                    included_cols: vec![chunk3.clone()],
                    super_col: TrackedCol::new(
                        prover.track_mat_mv_poly(Self::dense_range_poly_by_nv(15).unwrap()),
                        None,
                        None,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(
                    prover,
                    top_inclusion_check_prover_input,
                )?;
                for segment in [chunk2, chunk1, chunk0] {
                    let inclusion_check_prover_input = InclusionCheckProverInput {
                        included_cols: vec![segment],
                        super_col: TrackedCol::new(
                            prover.track_mat_mv_poly(Self::dense_range_poly_by_nv(16).unwrap()),
                            None,
                            None,
                        ),
                    };
                    InclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(
                        prover,
                        inclusion_check_prover_input,
                    )?;
                }
            },

            _ => {
                return Err(SnarkError::DummyError);
            },
        }
        Ok(())
    }

    pub fn verify_non_neg(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        tracked_col_oracle: &TrackedColOracle<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let field_ref = tracked_col_oracle.field_ref().unwrap();
        let data_type = field_ref.data_type();
        match *data_type {
            DataType::UInt8 => {
                let inclusion_check_prover_input = InclusionCheckVerifierInput {
                    included_tracked_col_oracles: vec![tracked_col_oracle.clone()],
                    super_tracked_col_oracle: TrackedColOracle::new(
                        verifier.track_oracle(Oracle::new_multivariate(8, move |x| {
                            Ok(Self::sparse_range_poly_by_nv(8)?.evaluate(&x))
                        })),
                        None,
                        None,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(
                    verifier,
                    inclusion_check_prover_input,
                )?;
            },

            DataType::Int8 => {
                let inclusion_check_prover_input = InclusionCheckVerifierInput {
                    included_tracked_col_oracles: vec![tracked_col_oracle.clone()],
                    super_tracked_col_oracle: TrackedColOracle::new(
                        verifier.track_oracle(Oracle::new_multivariate(7, move |x| {
                            Ok(Self::sparse_range_poly_by_nv(7)?.evaluate(&x))
                        })),
                        None,
                        None,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(
                    verifier,
                    inclusion_check_prover_input,
                )?;
            },

            DataType::UInt16 => {
                let inclusion_check_prover_input = InclusionCheckVerifierInput {
                    included_tracked_col_oracles: vec![tracked_col_oracle.clone()],
                    super_tracked_col_oracle: TrackedColOracle::new(
                        verifier.track_oracle(Oracle::new_multivariate(16, move |x| {
                            Ok(Self::sparse_range_poly_by_nv(16)?.evaluate(&x))
                        })),
                        None,
                        None,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(
                    verifier,
                    inclusion_check_prover_input,
                )?;
            },
            DataType::UInt32 => {
                let (chunk3, chunk2, chunk1, chunk0) =
                    Self::verify_non_neg_uint32(verifier, tracked_col_oracle)?;
                for segment in [chunk3, chunk2, chunk1, chunk0] {
                    let inclusion_check_verifier_input = InclusionCheckVerifierInput {
                        included_tracked_col_oracles: vec![segment],
                        super_tracked_col_oracle: TrackedColOracle::new(
                            verifier.track_oracle(Oracle::new_multivariate(16, move |x| {
                                Ok(Self::sparse_range_poly_by_nv(16)?.evaluate(&x))
                            })),
                            None,
                            None,
                        ),
                    };
                    InclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(
                        verifier,
                        inclusion_check_verifier_input,
                    )?;
                }
            },

            DataType::Int32 => {
                let (chunk3, chunk2, chunk1, chunk0) =
                    Self::verify_non_neg_int32(verifier, tracked_col_oracle)?;
                let top_inclusion_check_verifier_input = InclusionCheckVerifierInput {
                    included_tracked_col_oracles: vec![chunk3.clone()],
                    super_tracked_col_oracle: TrackedColOracle::new(
                        verifier.track_oracle(Oracle::new_multivariate(15, move |x| {
                            Ok(Self::sparse_range_poly_by_nv(15)?.evaluate(&x))
                        })),
                        None,
                        None,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(
                    verifier,
                    top_inclusion_check_verifier_input,
                )?;
                for segment in [chunk2, chunk1, chunk0] {
                    let inclusion_check_verifier_input = InclusionCheckVerifierInput {
                        included_tracked_col_oracles: vec![segment],
                        super_tracked_col_oracle: TrackedColOracle::new(
                            verifier.track_oracle(Oracle::new_multivariate(16, move |x| {
                                Ok(Self::sparse_range_poly_by_nv(16)?.evaluate(&x))
                            })),
                            None,
                            None,
                        ),
                    };
                    InclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(
                        verifier,
                        inclusion_check_verifier_input,
                    )?;
                }
            },

            DataType::UInt64 => {
                let (chunk3, chunk2, chunk1, chunk0) =
                    Self::verify_non_neg_uint64(verifier, tracked_col_oracle)?;
                for segment in [chunk3, chunk2, chunk1, chunk0] {
                    let inclusion_check_verifier_input = InclusionCheckVerifierInput {
                        included_tracked_col_oracles: vec![segment],
                        super_tracked_col_oracle: TrackedColOracle::new(
                            verifier.track_oracle(Oracle::new_multivariate(16, move |x| {
                                Ok(Self::sparse_range_poly_by_nv(16)?.evaluate(&x))
                            })),
                            None,
                            None,
                        ),
                    };
                    InclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(
                        verifier,
                        inclusion_check_verifier_input,
                    )?;
                }
            },

            DataType::Int64 => {
                let (chunk3, chunk2, chunk1, chunk0) =
                    Self::verify_non_neg_int64(verifier, tracked_col_oracle)?;
                let top_inclusion_check_verifier_input = InclusionCheckVerifierInput {
                    included_tracked_col_oracles: vec![chunk3.clone()],
                    super_tracked_col_oracle: TrackedColOracle::new(
                        verifier.track_oracle(Oracle::new_multivariate(15, move |x| {
                            Ok(Self::sparse_range_poly_by_nv(15)?.evaluate(&x))
                        })),
                        None,
                        None,
                    ),
                };
                InclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(
                    verifier,
                    top_inclusion_check_verifier_input,
                )?;
                for segment in [chunk2, chunk1, chunk0] {
                    let inclusion_check_verifier_input = InclusionCheckVerifierInput {
                        included_tracked_col_oracles: vec![segment],
                        super_tracked_col_oracle: TrackedColOracle::new(
                            verifier.track_oracle(Oracle::new_multivariate(16, move |x| {
                                Ok(Self::sparse_range_poly_by_nv(16)?.evaluate(&x))
                            })),
                            None,
                            None,
                        ),
                    };
                    InclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(
                        verifier,
                        inclusion_check_verifier_input,
                    )?;
                }
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
        col: &TrackedCol<F, MvPCS, UvPCS>,
    ) -> SnarkResult<(
        TrackedCol<F, MvPCS, UvPCS>,
        TrackedCol<F, MvPCS, UvPCS>,
        TrackedCol<F, MvPCS, UvPCS>,
        TrackedCol<F, MvPCS, UvPCS>,
    )> {
        let evaluations = col.data_tracked_poly().evaluations();
        let log_size = col.log_size();
        let mut chunk3_vals = Vec::with_capacity(evaluations.len());
        let mut chunk2_vals = Vec::with_capacity(evaluations.len());
        let mut chunk1_vals = Vec::with_capacity(evaluations.len());
        let mut chunk0_vals = Vec::with_capacity(evaluations.len());

        for eval in evaluations.iter() {
            let big = eval.into_bigint();
            let n = big.as_ref()[0] as u32;
            let [chunk3, chunk2, chunk1, chunk0] = Self::split_u32_into_u16s(n);
            chunk3_vals.push(F::from(chunk3 as u64));
            chunk2_vals.push(F::from(chunk2 as u64));
            chunk1_vals.push(F::from(chunk1 as u64));
            chunk0_vals.push(F::from(chunk0 as u64));
        }

        let chunk3_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, chunk3_vals))?;
        let chunk2_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, chunk2_vals))?;
        let chunk1_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, chunk1_vals))?;
        let chunk0_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, chunk0_vals))?;

        let recomposed = &(&(&(&chunk3_poly * F::from(1u64 << 48))
            + &(&chunk2_poly * F::from(1u64 << 32)))
            + &(&chunk1_poly * F::from(1u64 << 16)))
            + &chunk0_poly;

        let combined = &col.data_tracked_poly() - &recomposed;
        let zero_poly = match &col.activator_tracked_poly() {
            Some(activator) => &combined * activator,
            None => combined,
        };
        prover.add_mv_zerocheck_claim(zero_poly.id())?;

        Ok((
            TrackedCol::new(
                chunk3_poly,
                col.activator_tracked_poly(),
                col.field_ref().clone(),
            ),
            TrackedCol::new(
                chunk2_poly,
                col.activator_tracked_poly(),
                col.field_ref().clone(),
            ),
            TrackedCol::new(
                chunk1_poly,
                col.activator_tracked_poly(),
                col.field_ref().clone(),
            ),
            TrackedCol::new(
                chunk0_poly,
                col.activator_tracked_poly(),
                col.field_ref().clone(),
            ),
        ))
    }

    #[allow(clippy::complexity)]
    pub fn verify_non_neg_uint32(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        tracked_col_oracle: &TrackedColOracle<F, MvPCS, UvPCS>,
    ) -> SnarkResult<(
        TrackedColOracle<F, MvPCS, UvPCS>,
        TrackedColOracle<F, MvPCS, UvPCS>,
        TrackedColOracle<F, MvPCS, UvPCS>,
        TrackedColOracle<F, MvPCS, UvPCS>,
    )> {
        let col_inner = tracked_col_oracle.data_tracked_oracle().clone();
        let col_activator = tracked_col_oracle.activator_tracked_oracle().clone();

        let chunk3_id = verifier.peek_next_id();
        let chunk3_poly = verifier.track_mv_com_by_id(chunk3_id)?;
        let chunk2_id = verifier.peek_next_id();
        let chunk2_poly = verifier.track_mv_com_by_id(chunk2_id)?;
        let chunk1_id = verifier.peek_next_id();
        let chunk1_poly = verifier.track_mv_com_by_id(chunk1_id)?;
        let chunk0_id = verifier.peek_next_id();
        let chunk0_poly = verifier.track_mv_com_by_id(chunk0_id)?;

        let recomposed = &(&(&(&chunk3_poly * F::from(1u64 << 48))
            + &(&chunk2_poly * F::from(1u64 << 32)))
            + &(&chunk1_poly * F::from(1u64 << 16)))
            + &chunk0_poly;

        let combined = &col_inner - &recomposed;
        let zero_poly = match &col_activator {
            Some(activator) => &combined * activator,
            None => combined,
        };
        verifier.add_zerocheck_claim(zero_poly.id());

        let chunk3_oracle = TrackedColOracle::new(
            chunk3_poly,
            col_activator.clone(),
            tracked_col_oracle.field_ref().clone(),
        );
        let chunk2_oracle = TrackedColOracle::new(
            chunk2_poly,
            col_activator.clone(),
            tracked_col_oracle.field_ref().clone(),
        );
        let chunk1_oracle = TrackedColOracle::new(
            chunk1_poly,
            col_activator.clone(),
            tracked_col_oracle.field_ref().clone(),
        );
        let chunk0_oracle = TrackedColOracle::new(
            chunk0_poly,
            col_activator,
            tracked_col_oracle.field_ref().clone(),
        );

        Ok((chunk3_oracle, chunk2_oracle, chunk1_oracle, chunk0_oracle))
    }

    #[allow(clippy::complexity)]
    pub fn prove_non_neg_int32(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        col: &TrackedCol<F, MvPCS, UvPCS>,
    ) -> SnarkResult<(
        TrackedCol<F, MvPCS, UvPCS>,
        TrackedCol<F, MvPCS, UvPCS>,
        TrackedCol<F, MvPCS, UvPCS>,
        TrackedCol<F, MvPCS, UvPCS>,
    )> {
        let evaluations = col.data_tracked_poly().evaluations();
        let log_size = col.log_size();
        let mut chunk3_vals = Vec::with_capacity(evaluations.len());
        let mut chunk2_vals = Vec::with_capacity(evaluations.len());
        let mut chunk1_vals = Vec::with_capacity(evaluations.len());
        let mut chunk0_vals = Vec::with_capacity(evaluations.len());

        for eval in evaluations.iter() {
            let big = eval.into_bigint();
            let n = big.as_ref()[0] as i32;
            let [chunk3, chunk2, chunk1, chunk0] = Self::split_i32_into_u16s(n);
            chunk3_vals.push(F::from(chunk3 as u64));
            chunk2_vals.push(F::from(chunk2 as u64));
            chunk1_vals.push(F::from(chunk1 as u64));
            chunk0_vals.push(F::from(chunk0 as u64));
        }

        let chunk3_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, chunk3_vals))?;
        let chunk2_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, chunk2_vals))?;
        let chunk1_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, chunk1_vals))?;
        let chunk0_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, chunk0_vals))?;

        let recomposed = &(&(&(&chunk3_poly * F::from(1u64 << 48))
            + &(&chunk2_poly * F::from(1u64 << 32)))
            + &(&chunk1_poly * F::from(1u64 << 16)))
            + &chunk0_poly;

        let combined = &col.data_tracked_poly() - &recomposed;
        let zero_poly = match &col.activator_tracked_poly() {
            Some(activator) => &combined * activator,
            None => combined,
        };
        prover.add_mv_zerocheck_claim(zero_poly.id())?;

        Ok((
            TrackedCol::new(
                chunk3_poly,
                col.activator_tracked_poly(),
                col.field_ref().clone(),
            ),
            TrackedCol::new(
                chunk2_poly,
                col.activator_tracked_poly(),
                col.field_ref().clone(),
            ),
            TrackedCol::new(
                chunk1_poly,
                col.activator_tracked_poly(),
                col.field_ref().clone(),
            ),
            TrackedCol::new(
                chunk0_poly,
                col.activator_tracked_poly(),
                col.field_ref().clone(),
            ),
        ))
    }

    #[allow(clippy::complexity)]
    pub fn verify_non_neg_int32(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        tracked_col_oracle: &TrackedColOracle<F, MvPCS, UvPCS>,
    ) -> SnarkResult<(
        TrackedColOracle<F, MvPCS, UvPCS>,
        TrackedColOracle<F, MvPCS, UvPCS>,
        TrackedColOracle<F, MvPCS, UvPCS>,
        TrackedColOracle<F, MvPCS, UvPCS>,
    )> {
        let col_inner = tracked_col_oracle.data_tracked_oracle().clone();
        let col_activator = tracked_col_oracle.activator_tracked_oracle().clone();

        let chunk3_id = verifier.peek_next_id();
        let chunk3_poly = verifier.track_mv_com_by_id(chunk3_id)?;
        let chunk2_id = verifier.peek_next_id();
        let chunk2_poly = verifier.track_mv_com_by_id(chunk2_id)?;
        let chunk1_id = verifier.peek_next_id();
        let chunk1_poly = verifier.track_mv_com_by_id(chunk1_id)?;
        let chunk0_id = verifier.peek_next_id();
        let chunk0_poly = verifier.track_mv_com_by_id(chunk0_id)?;

        let recomposed = &(&(&(&chunk3_poly * F::from(1u64 << 48))
            + &(&chunk2_poly * F::from(1u64 << 32)))
            + &(&chunk1_poly * F::from(1u64 << 16)))
            + &chunk0_poly;

        let combined = &col_inner - &recomposed;
        let zero_poly = match &col_activator {
            Some(activator) => &combined * activator,
            None => combined,
        };
        verifier.add_zerocheck_claim(zero_poly.id());

        let chunk3_oracle = TrackedColOracle::new(
            chunk3_poly,
            col_activator.clone(),
            tracked_col_oracle.field_ref().clone(),
        );
        let chunk2_oracle = TrackedColOracle::new(
            chunk2_poly,
            col_activator.clone(),
            tracked_col_oracle.field_ref().clone(),
        );
        let chunk1_oracle = TrackedColOracle::new(
            chunk1_poly,
            col_activator.clone(),
            tracked_col_oracle.field_ref().clone(),
        );
        let chunk0_oracle = TrackedColOracle::new(
            chunk0_poly,
            col_activator,
            tracked_col_oracle.field_ref().clone(),
        );

        Ok((chunk3_oracle, chunk2_oracle, chunk1_oracle, chunk0_oracle))
    }

    #[allow(clippy::complexity)]
    pub fn prove_non_neg_uint64(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        col: &TrackedCol<F, MvPCS, UvPCS>,
    ) -> SnarkResult<(
        TrackedCol<F, MvPCS, UvPCS>,
        TrackedCol<F, MvPCS, UvPCS>,
        TrackedCol<F, MvPCS, UvPCS>,
        TrackedCol<F, MvPCS, UvPCS>,
    )> {
        let evaluations = col.data_tracked_poly().evaluations();
        let log_size = col.log_size();
        let mut chunk3_vals = Vec::with_capacity(evaluations.len());
        let mut chunk2_vals = Vec::with_capacity(evaluations.len());
        let mut chunk1_vals = Vec::with_capacity(evaluations.len());
        let mut chunk0_vals = Vec::with_capacity(evaluations.len());

        for eval in evaluations.iter() {
            let big = eval.into_bigint();
            let n = big.as_ref()[0] as u64;
            let [chunk3, chunk2, chunk1, chunk0] = Self::split_u64_into_u16s(n);
            chunk3_vals.push(F::from(chunk3 as u64));
            chunk2_vals.push(F::from(chunk2 as u64));
            chunk1_vals.push(F::from(chunk1 as u64));
            chunk0_vals.push(F::from(chunk0 as u64));
        }

        let chunk3_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, chunk3_vals))?;
        let chunk2_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, chunk2_vals))?;
        let chunk1_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, chunk1_vals))?;
        let chunk0_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, chunk0_vals))?;

        let recomposed = &(&(&(&chunk3_poly * F::from(1u64 << 48))
            + &(&chunk2_poly * F::from(1u64 << 32)))
            + &(&chunk1_poly * F::from(1u64 << 16)))
            + &chunk0_poly;

        let combined = &col.data_tracked_poly() - &recomposed;
        let zero_poly = match &col.activator_tracked_poly() {
            Some(activator) => &combined * activator,
            None => combined,
        };
        prover.add_mv_zerocheck_claim(zero_poly.id())?;

        Ok((
            TrackedCol::new(
                chunk3_poly,
                col.activator_tracked_poly(),
                col.field_ref().clone(),
            ),
            TrackedCol::new(
                chunk2_poly,
                col.activator_tracked_poly(),
                col.field_ref().clone(),
            ),
            TrackedCol::new(
                chunk1_poly,
                col.activator_tracked_poly(),
                col.field_ref().clone(),
            ),
            TrackedCol::new(
                chunk0_poly,
                col.activator_tracked_poly(),
                col.field_ref().clone(),
            ),
        ))
    }

    #[allow(clippy::complexity)]
    pub fn verify_non_neg_uint64(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        tracked_col_oracle: &TrackedColOracle<F, MvPCS, UvPCS>,
    ) -> SnarkResult<(
        TrackedColOracle<F, MvPCS, UvPCS>,
        TrackedColOracle<F, MvPCS, UvPCS>,
        TrackedColOracle<F, MvPCS, UvPCS>,
        TrackedColOracle<F, MvPCS, UvPCS>,
    )> {
        let col_inner = tracked_col_oracle.data_tracked_oracle().clone();
        let col_activator = tracked_col_oracle.activator_tracked_oracle().clone();

        let chunk3_id = verifier.peek_next_id();
        let chunk3_poly = verifier.track_mv_com_by_id(chunk3_id)?;
        let chunk2_id = verifier.peek_next_id();
        let chunk2_poly = verifier.track_mv_com_by_id(chunk2_id)?;
        let chunk1_id = verifier.peek_next_id();
        let chunk1_poly = verifier.track_mv_com_by_id(chunk1_id)?;
        let chunk0_id = verifier.peek_next_id();
        let chunk0_poly = verifier.track_mv_com_by_id(chunk0_id)?;

        let recomposed = &(&(&(&chunk3_poly * F::from(1u64 << 48))
            + &(&chunk2_poly * F::from(1u64 << 32)))
            + &(&chunk1_poly * F::from(1u64 << 16)))
            + &chunk0_poly;

        let combined = &col_inner - &recomposed;
        let zero_poly = match &col_activator {
            Some(activator) => &combined * activator,
            None => combined,
        };
        verifier.add_zerocheck_claim(zero_poly.id());

        let chunk3_oracle = TrackedColOracle::new(
            chunk3_poly,
            col_activator.clone(),
            tracked_col_oracle.field_ref().clone(),
        );
        let chunk2_oracle = TrackedColOracle::new(
            chunk2_poly,
            col_activator.clone(),
            tracked_col_oracle.field_ref().clone(),
        );
        let chunk1_oracle = TrackedColOracle::new(
            chunk1_poly,
            col_activator.clone(),
            tracked_col_oracle.field_ref().clone(),
        );
        let chunk0_oracle = TrackedColOracle::new(
            chunk0_poly,
            col_activator,
            tracked_col_oracle.field_ref().clone(),
        );

        Ok((chunk3_oracle, chunk2_oracle, chunk1_oracle, chunk0_oracle))
    }

    #[allow(clippy::complexity)]
    pub fn prove_non_neg_int64(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        col: &TrackedCol<F, MvPCS, UvPCS>,
    ) -> SnarkResult<(
        TrackedCol<F, MvPCS, UvPCS>,
        TrackedCol<F, MvPCS, UvPCS>,
        TrackedCol<F, MvPCS, UvPCS>,
        TrackedCol<F, MvPCS, UvPCS>,
    )> {
        let evaluations = col.data_tracked_poly().evaluations();
        let log_size = col.log_size();
        let mut chunk3_vals = Vec::with_capacity(evaluations.len());
        let mut chunk2_vals = Vec::with_capacity(evaluations.len());
        let mut chunk1_vals = Vec::with_capacity(evaluations.len());
        let mut chunk0_vals = Vec::with_capacity(evaluations.len());

        for eval in evaluations.iter() {
            let big = eval.into_bigint();
            let n = big.as_ref()[0] as i64;
            let [chunk3, chunk2, chunk1, chunk0] = Self::split_i64_into_u16s(n);
            chunk3_vals.push(F::from(chunk3 as u64));
            chunk2_vals.push(F::from(chunk2 as u64));
            chunk1_vals.push(F::from(chunk1 as u64));
            chunk0_vals.push(F::from(chunk0 as u64));
        }

        let chunk3_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, chunk3_vals))?;
        let chunk2_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, chunk2_vals))?;
        let chunk1_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, chunk1_vals))?;
        let chunk0_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, chunk0_vals))?;

        let recomposed = &(&(&(&chunk3_poly * F::from(1u64 << 48))
            + &(&chunk2_poly * F::from(1u64 << 32)))
            + &(&chunk1_poly * F::from(1u64 << 16)))
            + &chunk0_poly;

        let combined = &col.data_tracked_poly() - &recomposed;
        let zero_poly = match &col.activator_tracked_poly() {
            Some(activator) => &combined * activator,
            None => combined,
        };
        prover.add_mv_zerocheck_claim(zero_poly.id())?;

        Ok((
            TrackedCol::new(
                chunk3_poly,
                col.activator_tracked_poly(),
                col.field_ref().clone(),
            ),
            TrackedCol::new(
                chunk2_poly,
                col.activator_tracked_poly(),
                col.field_ref().clone(),
            ),
            TrackedCol::new(
                chunk1_poly,
                col.activator_tracked_poly(),
                col.field_ref().clone(),
            ),
            TrackedCol::new(
                chunk0_poly,
                col.activator_tracked_poly(),
                col.field_ref().clone(),
            ),
        ))
    }

    #[allow(clippy::complexity)]
    pub fn verify_non_neg_int64(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        tracked_col_oracle: &TrackedColOracle<F, MvPCS, UvPCS>,
    ) -> SnarkResult<(
        TrackedColOracle<F, MvPCS, UvPCS>,
        TrackedColOracle<F, MvPCS, UvPCS>,
        TrackedColOracle<F, MvPCS, UvPCS>,
        TrackedColOracle<F, MvPCS, UvPCS>,
    )> {
        let col_inner = tracked_col_oracle.data_tracked_oracle().clone();
        let col_activator = tracked_col_oracle.activator_tracked_oracle().clone();

        let chunk3_id = verifier.peek_next_id();
        let chunk3_poly = verifier.track_mv_com_by_id(chunk3_id)?;
        let chunk2_id = verifier.peek_next_id();
        let chunk2_poly = verifier.track_mv_com_by_id(chunk2_id)?;
        let chunk1_id = verifier.peek_next_id();
        let chunk1_poly = verifier.track_mv_com_by_id(chunk1_id)?;
        let chunk0_id = verifier.peek_next_id();
        let chunk0_poly = verifier.track_mv_com_by_id(chunk0_id)?;

        let recomposed = &(&(&(&chunk3_poly * F::from(1u64 << 48))
            + &(&chunk2_poly * F::from(1u64 << 32)))
            + &(&chunk1_poly * F::from(1u64 << 16)))
            + &chunk0_poly;

        let combined = &col_inner - &recomposed;
        let zero_poly = match &col_activator {
            Some(activator) => &combined * activator,
            None => combined,
        };
        verifier.add_zerocheck_claim(zero_poly.id());

        let chunk3_oracle = TrackedColOracle::new(
            chunk3_poly,
            col_activator.clone(),
            tracked_col_oracle.field_ref().clone(),
        );
        let chunk2_oracle = TrackedColOracle::new(
            chunk2_poly,
            col_activator.clone(),
            tracked_col_oracle.field_ref().clone(),
        );
        let chunk1_oracle = TrackedColOracle::new(
            chunk1_poly,
            col_activator.clone(),
            tracked_col_oracle.field_ref().clone(),
        );
        let chunk0_oracle = TrackedColOracle::new(
            chunk0_poly,
            col_activator,
            tracked_col_oracle.field_ref().clone(),
        );

        Ok((chunk3_oracle, chunk2_oracle, chunk1_oracle, chunk0_oracle))
    }

    fn split_u32_into_u16s(n: u32) -> [u16; 4] {
        let chunk0 = (n & 0xFFFF) as u16;
        let chunk1 = ((n >> 16) & 0xFFFF) as u16;
        let chunk2 = 0u16;
        let chunk3 = 0u16;
        [chunk3, chunk2, chunk1, chunk0]
    }

    fn split_i32_into_u16s(n: i32) -> [u16; 4] {
        let bits = n as u32;
        let chunk0 = (bits & 0xFFFF) as u16;
        let chunk1 = ((bits >> 16) & 0xFFFF) as u16;
        let sign_extension = if n < 0 { 0xFFFF } else { 0 };
        [sign_extension, sign_extension, chunk1, chunk0]
    }

    fn split_u64_into_u16s(n: u64) -> [u16; 4] {
        let chunk0 = (n & 0xFFFF) as u16;
        let chunk1 = ((n >> 16) & 0xFFFF) as u16;
        let chunk2 = ((n >> 32) & 0xFFFF) as u16;
        let chunk3 = ((n >> 48) & 0xFFFF) as u16;
        [chunk3, chunk2, chunk1, chunk0]
    }

    fn split_i64_into_u16s(n: i64) -> [u16; 4] {
        let bits = n as u64;
        let chunk0 = (bits & 0xFFFF) as u16;
        let chunk1 = ((bits >> 16) & 0xFFFF) as u16;
        let chunk2 = ((bits >> 32) & 0xFFFF) as u16;
        let chunk3 = ((bits >> 48) & 0xFFFF) as u16;
        [chunk3, chunk2, chunk1, chunk0]
    }
}
