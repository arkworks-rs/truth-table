use std::{collections::HashMap, sync::Arc};

use ark_ff::PrimeField;

use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    piop::DeepClone,
    prover::{structs::polynomial::TrackedPoly, Prover},
};

use datafusion::arrow::{
    array::RecordBatch,
    datatypes::{FieldRef, Schema},
};
use derivative::Derivative;

use crate::{
    col::ArithCol, ctx::ProverCtx, encoding::encode_arrow_array_to_field, errors::EncodeError,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[derive(Derivative)]
#[derivative(Clone(bound = "MvPCS: PCS<F>"), PartialEq(bound = "MvPCS: PCS<F>"))]
/// An abstraction of an arithmetized table in dbSNARK
/// An arithmetized table is represented by a set of polynomials representing
/// the data columns and a single activator polynomial If the activator
/// polynomial is None, all the rows are active
pub struct ArithTable<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// The schema of the table; i.e. the metadata about the table
    schema: Option<Schema>,
    /// The polynomials representing the data columns
    data_polys: HashMap<FieldRef, TrackedPoly<F, MvPCS, UvPCS>>,
    /// The polynomial representing the activator
    /// If it is None, all the rows are active
    actvtr_poly: Option<TrackedPoly<F, MvPCS, UvPCS>>,
    size: usize,
}

// Custom Debug impl to avoid requiring `MvPCS`/`UvPCS` to be Debug.
impl<F, MvPCS, UvPCS> core::fmt::Debug for ArithTable<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ArithTable")
            .field("num_cols", &self.num_cols())
            .field("log_size", &self.log_size())
            .field("has_actvtr", &self.actvtr_poly.is_some())
            .field("size", &self.size)
            .finish()
    }
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for ArithTable<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        let data_polys = self
            .data_polys
            .iter()
            .map(|(field, poly)| (field.clone(), poly.deep_clone(prover.clone())))
            .collect::<HashMap<FieldRef, TrackedPoly<F, MvPCS, UvPCS>>>();
        let actvtr_poly = self
            .actvtr_poly
            .as_ref()
            .map(|poly| poly.deep_clone(prover));
        Self::new(self.schema.clone(), data_polys, actvtr_poly, self.size)
    }
}

impl<F, MvPCS, UvPCS> ArithTable<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub fn new(
        schema: Option<Schema>,
        data_polys:  HashMap<FieldRef, TrackedPoly<F, MvPCS, UvPCS>>,
        actvtr_poly: Option<TrackedPoly<F, MvPCS, UvPCS>>,
        // TODO: See if we can remove this
        size: usize,
    ) -> Self {
        #[cfg(debug_assertions)]
        {
            if actvtr_poly.is_some() {
                let unwrapped_actvtr_poly = actvtr_poly.as_ref().unwrap();
                for poly in data_polys.values() {
                    assert_eq!(poly.log_size(), unwrapped_actvtr_poly.log_size());
                    assert!(poly.same_tracker(unwrapped_actvtr_poly));
                }
            }
        }
        Self {
            schema,
            data_polys,
            actvtr_poly,
            size,
        }
    }
    pub fn log_size(&self) -> usize {
        self.data_polys.values().next().unwrap().log_size()
    }

    pub fn prover(&self) -> Prover<F, MvPCS, UvPCS> {
        Prover::new_from_tracker_rc(self.data_polys.values().next().unwrap().tracker())
    }

    pub fn fold(&self, col_inds: &[usize], challs: &[F]) -> ArithCol<F, MvPCS, UvPCS> {
        assert_eq!(col_inds.len(), challs.len());
        let data_polys_values: Vec<_> = self.data_polys.values().collect();
        let mut folded: TrackedPoly<F, MvPCS, UvPCS> = &data_polys_values[col_inds[0]].clone() * challs[0];
        for i in 1..col_inds.len() {
            folded += &(data_polys_values[col_inds[i]] * challs[i]);
        }
        ArithCol::new(None, folded, self.actvtr_poly.clone())
    }

    pub fn fold_all(&self, challs: &[F]) -> ArithCol<F, MvPCS, UvPCS> {
        self.fold(&(0..self.num_cols()).collect::<Vec<usize>>(), challs)
    }

    pub fn col(&self, col_ind: usize) -> ArithCol<F, MvPCS, UvPCS> {
        ArithCol::new(
            self.schema.as_ref().map(|schema| {
                if col_ind >= schema.fields().len() {
                    panic!(
                        "Column index {} out of bounds (schema: {:?})",
                        col_ind, schema
                    );
                }
                schema.field(col_ind).clone().data_type().clone()
            }),
            self.data_polys.values().collect::<Vec<_>>()[col_ind].clone(),
            self.actvtr_poly.clone(),
        )
    }

    pub fn col_by_name(&self, name: &str) -> Option<ArithCol<F, MvPCS, UvPCS>> {
        let idx = self
            .schema
            .as_ref()
            .and_then(|schema| schema.index_of(name).ok())?;
        Some(self.col(idx))
    }

    pub fn data_polys(&self) -> Vec<TrackedPoly<F, MvPCS, UvPCS>> {
        self.data_polys.values().cloned().collect()
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn cols(&self, indice: &[usize]) -> Vec<ArithCol<F, MvPCS, UvPCS>> {
        indice.iter().map(|&i| self.col(i)).collect()
    }

    pub fn all_cols(&self) -> Vec<ArithCol<F, MvPCS, UvPCS>> {
        self.cols(&(0..self.num_cols()).collect::<Vec<usize>>())
    }

    pub fn num_cols(&self) -> usize {
        self.data_polys.len()
    }

    pub fn schema(&self) -> Option<Schema> {
        self.schema.clone()
    }

    pub fn actvtr_poly(&self) -> Option<TrackedPoly<F, MvPCS, UvPCS>> {
        self.actvtr_poly.clone()
    }
}
