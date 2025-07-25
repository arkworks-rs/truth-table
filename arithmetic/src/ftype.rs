use std::{
    any::Any,
    collections::{BTreeMap, HashMap},
    sync::OnceLock,
};

use ark_ec::bls12;
use ark_ff::PrimeField;
use ark_poly::{
    DenseMVPolynomial, Polynomial,
    multivariate::{SparseTerm, Term},
};
use ark_std::{end_timer, start_timer};
use datafusion::arrow::datatypes::DataType;
use rayon::vec;

use crate::{
    arithmetic::mle::mat::MLE, errors::{SnarkError, SnarkResult}, prover
};

pub trait FType<F: PrimeField> {
    fn max_value(&self) -> SnarkResult<F>;
    fn min_value(&self) -> SnarkResult<F>;
    fn gen_range_polys() -> BTreeMap<DataType, MLE<F>>;
}

impl<Fp: PrimeField> FType<Fp> for DataType {
    fn max_value(&self) -> SnarkResult<Fp> {
        match self {
            DataType::Int64 => Ok(Fp::from(i64::MAX)),
            DataType::UInt64 => Ok(Fp::from(u64::MAX)),
            DataType::Utf8 => Ok(Fp::from(u64::MAX)),
            _ => Err(SnarkError::DummyError),
        }
    }

    fn min_value(&self) -> SnarkResult<Fp> {
        match self {
            DataType::Int64 => Ok(Fp::from(i64::MIN)),
            DataType::UInt64 => Ok(Fp::from(0u64)),
            DataType::Utf8 => Ok(Fp::from(0u64)),
            _ => Err(SnarkError::DummyError),
        }
    }

    fn gen_range_polys() -> BTreeMap<DataType, MLE<Fp>> {
        let mut range_polys = BTreeMap::new();
        range_polys.insert(
            DataType::UInt8,
            MLE::from_evaluations_vec(
                8,
                (u8::MIN..=u8::MAX).map(|x| (Fp::from(x as u64))).collect(),
            ),
        );
        range_polys.insert(
            DataType::Int8,
            MLE::from_evaluations_vec(8, (0..=u8::MAX).map(|x| (Fp::from(x as u64))).collect()),
        );
        range_polys.insert(
            DataType::UInt16,
            MLE::from_evaluations_vec(
                16,
                (u16::MIN..=u16::MAX)
                    .map(|x| (Fp::from(x as u64)))
                    .collect(),
            ),
        );



        range_polys.insert(
            DataType::Int16,
            MLE::from_evaluations_vec(16, (0..=u16::MAX).map(|x| (Fp::from(x as u64))).collect()),
        );
        range_polys
    }
}
