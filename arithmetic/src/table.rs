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

use crate::{col::ArithCol, encoding::encode_arrow_array_to_field, errors::EncodeError};

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
    data_polys: Vec<TrackedPoly<F, MvPCS, UvPCS>>,
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
            .map(|poly| poly.deep_clone(prover.clone()))
            .collect();
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
    #[tracing::instrument(level = "debug", skip(record_batches, prover))]
    pub fn from_record_batches(
        record_batches: Vec<RecordBatch>,
        prover: &mut Prover<F, MvPCS, UvPCS>,
    ) -> Result<Self, EncodeError> {
        if record_batches.is_empty() {
            return Ok(Self::new(None, Vec::new(), None, 0));
        }

        let schema_ref = record_batches[0].schema();

        let activator_idx = schema_ref.index_of("activator").ok();
        let num_cols = schema_ref.fields().len();

        let total_rows: usize = record_batches.iter().map(|b| b.num_rows()).sum();
        assert!(total_rows.is_power_of_two());

        let max_log_vars = total_rows.trailing_zeros() as usize;

        let mut columns: Vec<Vec<F>> = vec![Vec::with_capacity(total_rows); num_cols];

        for batch in record_batches {
            for (col_idx, array) in batch.columns().iter().enumerate() {
                let mut encoded = encode_arrow_array_to_field::<F>(array)?;
                // TODO: The current version only supports single column encoding
                columns[col_idx].append(&mut encoded[0]);
            }
        }

        let mut column_polys: HashMap<FieldRef, Arc<MLE<F>>> = HashMap::with_capacity(num_cols);
        for (idx, values) in columns.into_iter().enumerate() {
            let mle = MLE::from_evaluations_slice(max_log_vars, &values);
            let field = schema_ref.field(idx).clone();
            column_polys.insert(Arc::new(field), Arc::new(mle));
        }

        let prover_param = prover.mv_pcs_prover_param();

        let mut column_commitments: HashMap<FieldRef, MvPCS::Commitment> =
            HashMap::with_capacity(column_polys.len());
        for (field_ref, poly) in &column_polys {
            let commitment = MvPCS::commit(prover_param.clone(), poly)
                .expect("failed to commit witness polynomial");
            column_commitments.insert(field_ref.clone(), commitment);
        }

        let mut data_polys: Vec<TrackedPoly<F, MvPCS, UvPCS>> = Vec::with_capacity(num_cols);
        let mut activator_poly: Option<TrackedPoly<F, MvPCS, UvPCS>> = None;

        for idx in 0..num_cols {
            let field_ref = Arc::new(schema_ref.field(idx).clone());
            let poly_arc = column_polys
                .get(&field_ref)
                .expect("polynomial for field not found")
                .clone();
            let commitment = column_commitments
                .get(&field_ref)
                .expect("commitment for field not found")
                .clone();

            let tracked = prover
                .track_mat_mv_poly_with_commitment(poly_arc.as_ref(), commitment)
                .expect("failed to commit witness polynomial");
            if Some(idx) == activator_idx {
                activator_poly = Some(tracked);
            } else {
                data_polys.push(tracked);
            }
        }

        let schema = Some(Schema::new(
            schema_ref
                .fields()
                .iter()
                .enumerate()
                .filter_map(|(idx, field)| {
                    if Some(idx) == activator_idx {
                        None
                    } else {
                        Some(field.clone())
                    }
                })
                .collect::<datafusion::arrow::datatypes::Fields>(),
        ));

        Ok(Self::new(schema, data_polys, activator_poly, total_rows))
    }

    pub fn new(
        schema: Option<Schema>,
        data_polys: Vec<TrackedPoly<F, MvPCS, UvPCS>>,
        actvtr_poly: Option<TrackedPoly<F, MvPCS, UvPCS>>,
        // TODO: See if we can remove this
        size: usize,
    ) -> Self {
        #[cfg(debug_assertions)]
        {
            if actvtr_poly.is_some() {
                let unwrapped_actvtr_poly = actvtr_poly.as_ref().unwrap();
                for poly in data_polys.iter() {
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
        self.data_polys[0].log_size()
    }

    pub fn prover(&self) -> Prover<F, MvPCS, UvPCS> {
        Prover::new_from_tracker_rc(self.data_polys[0].tracker())
    }

    pub fn fold(&self, col_inds: &[usize], challs: &[F]) -> ArithCol<F, MvPCS, UvPCS> {
        assert_eq!(col_inds.len(), challs.len());
        let mut folded: TrackedPoly<F, MvPCS, UvPCS> = &self.data_polys[col_inds[0]] * challs[0];
        for i in 1..col_inds.len() {
            folded += &(&self.data_polys[col_inds[i]] * challs[i]);
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
            self.data_polys[col_ind].clone(),
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
        self.data_polys.clone()
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
