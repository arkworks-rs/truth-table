use arithmetic::ark_ff::{Field, PrimeField};
use crypto::pcs::PolynomialCommitmentScheme;
use kit::derivative::Derivative;
use std::ops::Sub;

use super::prelude::{ProverTrackerRef, TrackedComm, TrackedPoly};

pub type ColInd = usize;

#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<F>"),
    PartialEq(bound = "PCS: PolynomialCommitmentScheme<F>")
)]

/// A column representation in dbSNARK
pub struct Col<F: PrimeField + PrimeField, PCS: PolynomialCommitmentScheme<F>>
where
    F: PrimeField,
{
    /// The polynomial representing the column. It is the
    /// extension of the column values. Depending on the activator
    /// polynomial, a value can be active or inactive
    pub inner_poly: TrackedPoly<F, PCS>,

    /// The activator polynomial, It evaluates to one at the indices of the
    /// active rows, and zero elsewhere
    pub actv_poly: TrackedPoly<F, PCS>,
}

impl<F: PrimeField, PCS: PolynomialCommitmentScheme<F>> Col<F, PCS>
where
    F: PrimeField,
{
    /// Creates a new column given a polynomial interpolating/extending the
    /// column and an activator polynomial
    pub fn new(inner_poly: TrackedPoly<F, PCS>, actv_poly: TrackedPoly<F, PCS>) -> Self {
        #[cfg(debug_assertions)]
        {
            assert_eq!(inner_poly.num_vars, actv_poly.num_vars);
            assert!(inner_poly.same_tracker(&actv_poly));
        }
        Self {
            inner_poly,
            actv_poly,
        }
    }

    /// Returns the number of variables of the column polynomial
    /// It is log_2 of the maximum capacity of the column
    pub fn num_vars(&self) -> usize {
        self.inner_poly.num_vars()
    }

    /// Returns a reference to the tracker of the column
    pub fn tracker_ref(&self) -> ProverTrackerRef<F, PCS> {
        ProverTrackerRef::new(self.inner_poly.tracker.clone())
    }

    /// Returns the effective polynomial of the column, which is the product of
    /// the activator and the column polynomial
    pub fn effective_poly(&self) -> TrackedPoly<F, PCS> {
        self.inner_poly.mul_poly(&self.actv_poly)
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<F>"),
    PartialEq(bound = "PCS: PolynomialCommitmentScheme<F>")
)]
pub struct ColComm<F: PrimeField, PCS: PolynomialCommitmentScheme<F>>
where
    F: PrimeField,
{
    pub poly: TrackedComm<F, PCS>,
    pub selector: TrackedComm<F, PCS>,
    num_vars: usize,
}
impl<F: PrimeField, PCS: PolynomialCommitmentScheme<F>> ColComm<F, PCS>
where
    F: PrimeField,
{
    pub fn new(poly: TrackedComm<F, PCS>, selector: TrackedComm<F, PCS>, num_vars: usize) -> Self {
        Self {
            poly,
            selector,
            num_vars,
        }
    }
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }
    /// Returns the effective polynomial of the column, which is the product of
    /// the activator and the column polynomial
    pub fn effective_poly(&self) -> TrackedComm<F, PCS> {
        self.poly.mul_comms(&self.selector)
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<F>"),
    PartialEq(bound = "PCS: PolynomialCommitmentScheme<F>")
)]
pub struct Table<F: PrimeField, PCS: PolynomialCommitmentScheme<F>>
where
    F: PrimeField,
{
    pub col_vals: Vec<TrackedPoly<F, PCS>>,
    pub actvtr: TrackedPoly<F, PCS>,
}

impl<F: PrimeField, PCS: PolynomialCommitmentScheme<F>> Table<F, PCS>
where
    F: PrimeField,
{
    pub fn new(col_vals: Vec<TrackedPoly<F, PCS>>, actvtr: TrackedPoly<F, PCS>) -> Self {
        #[cfg(debug_assertions)]
        {
            for poly in col_vals.iter() {
                assert_eq!(poly.num_vars, actvtr.num_vars);
                assert!(poly.same_tracker(&actvtr));
            }
        }
        Self { col_vals, actvtr }
    }

    pub fn num_vars(&self) -> usize {
        self.actvtr.num_vars
    }

    pub fn tracker_ref(&self) -> ProverTrackerRef<F, PCS> {
        ProverTrackerRef::new(self.actvtr.tracker.clone())
    }

    pub fn fold(&self, col_inds: &[usize], challs: &[F]) -> Col<F, PCS> {
        assert_eq!(col_inds.len(), challs.len());
        let mut folded: TrackedPoly<F, PCS> = self.col_vals[col_inds[0]].mul_scalar(challs[0]);
        for i in 1..col_inds.len() {
            folded = folded.add_poly(&self.col_vals[col_inds[i]].mul_scalar(challs[i]));
        }
        Col::new(folded, self.actvtr.clone())
    }
    pub fn col(&self, col_ind: usize) -> Col<F, PCS> {
        Col::new(self.col_vals[col_ind].clone(), self.actvtr.clone())
    }

    pub fn cols(&self, indice: &[usize]) -> Vec<Col<F, PCS>> {
        indice.iter().map(|&i| self.col(i)).collect()
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<F>"),
    PartialEq(bound = "PCS: PolynomialCommitmentScheme<F>")
)]
pub struct TableComm<F: PrimeField, PCS: PolynomialCommitmentScheme<F>>
where
    F: PrimeField,
{
    pub col_vals: Vec<TrackedComm<F, PCS>>,
    pub actvtr: TrackedComm<F, PCS>,
    pub num_vars: usize,
}

impl<F: PrimeField, PCS: PolynomialCommitmentScheme<F>> TableComm<F, PCS>
where
    F: PrimeField,
{
    pub fn new(
        col_vals: Vec<TrackedComm<F, PCS>>,
        actvtr: TrackedComm<F, PCS>,
        num_vars: usize,
    ) -> Self {
        Self {
            col_vals,
            actvtr,
            num_vars,
        }
    }
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    pub fn fold(&self, col_inds: &[usize], challs: &[F]) -> ColComm<F, PCS> {
        let mut folded: TrackedComm<F, PCS> = self.col_vals[col_inds[0]].mul_scalar(challs[0]);
        for i in 1..col_inds.len() {
            folded = folded.add_comms(&self.col_vals[col_inds[i]].mul_scalar(challs[i]));
        }
        ColComm::new(folded, self.actvtr.clone(), self.num_vars)
    }
    pub fn col(&self, col_ind: usize) -> ColComm<F, PCS> {
        ColComm::new(
            self.col_vals[col_ind].clone(),
            self.actvtr.clone(),
            self.num_vars,
        )
    }

    pub fn cols(&self, indice: &[usize]) -> Vec<ColComm<F, PCS>> {
        indice.iter().map(|&i| self.col(i)).collect()
    }
}
