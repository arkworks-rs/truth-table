use derivative::Derivative;
use crate::subroutines::PolynomialCommitmentScheme;
use ark_ec::pairing::Pairing;
use crate::tracker::prelude::*;

#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
    PartialEq(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct Bag<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub poly: TrackedPoly<E, PCS>,
    pub selector: TrackedPoly<E, PCS>,
}

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> Bag<E, PCS> {
    pub fn new(poly: TrackedPoly<E, PCS>, selector: TrackedPoly<E, PCS>) -> Self {
        #[cfg(debug_assertions)]
        {
            assert_eq!(poly.num_vars, selector.num_vars);
            assert!(poly.same_tracker(&selector));
        }
        Self {
            poly,
            selector,
        }
    }

    pub fn num_vars(&self) -> usize {
        self.poly.num_vars()
    }

    pub fn tracker_ref(&self) -> ProverTrackerRef<E, PCS> {
        ProverTrackerRef::new(self.poly.tracker.clone())
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
    PartialEq(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct BagComm<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub poly: TrackedComm<E, PCS>,
    pub selector: TrackedComm<E, PCS>,
    num_vars: usize,
}
impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> BagComm<E, PCS> {
    pub fn new(poly: TrackedComm<E, PCS>, selector: TrackedComm<E, PCS>, num_vars: usize) -> Self {
        Self {
            poly,
            selector,
            num_vars
        }
    }
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
    PartialEq(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct Table<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub col_vals: Vec<TrackedPoly<E, PCS>>,
    pub selector: TrackedPoly<E, PCS>,
}

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> Table<E, PCS> {
    pub fn new(col_vals: Vec<TrackedPoly<E, PCS>>, selector: TrackedPoly<E, PCS>) -> Self {
        #[cfg(debug_assertions)]
        {
            for poly in col_vals.iter() {
                assert_eq!(poly.num_vars, selector.num_vars);
                assert!(poly.same_tracker(&selector));
            }
        }
        Self {
            col_vals,
            selector,
        }
    }

    pub fn num_vars(&self) -> usize {
        self.selector.num_vars
    }

    pub fn tracker_ref(&self) -> ProverTrackerRef<E, PCS> {
        ProverTrackerRef::new(self.selector.tracker.clone())
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "PCS: PolynomialCommitmentScheme<E>"),
    PartialEq(bound = "PCS: PolynomialCommitmentScheme<E>"),
)]
pub struct TableComm<E: Pairing, PCS: PolynomialCommitmentScheme<E>> {
    pub col_vals: Vec<TrackedComm<E, PCS>>,
    pub selector: TrackedComm<E, PCS>,
    pub num_vars: usize,
}

impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> TableComm<E, PCS> {
    pub fn new(col_vals: Vec<TrackedComm<E, PCS>>, selector: TrackedComm<E, PCS>, num_vars: usize) -> Self {
        Self {
            col_vals,
            selector,
            num_vars
        }
    }
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }
}