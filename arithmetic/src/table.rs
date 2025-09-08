use std::iter::repeat_n;

use ark_ff::PrimeField;

use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    piop::DeepClone,
    prover::{structs::polynomial::TrackedPoly, Prover},
    verifier::{structs::oracle::TrackedOracle, Verifier},
};
use datafusion::{arrow::datatypes::Schema, prelude::DataFrame};
use derivative::Derivative;
use futures::StreamExt;

use crate::{
    col::{ArithCol, ColCom},
    downcast_and_encode,
    errors::EncodeError,
};

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
            .field("num_vars", &self.num_vars())
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
    pub fn num_vars(&self) -> usize {
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

#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Clone(bound = "UvPCS: PCS<F>"),
    PartialEq(bound = "UvPCS: PCS<F>")
)]
pub struct TableComm<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    schema: Option<Schema>,
    col_vals: Vec<TrackedOracle<F, MvPCS, UvPCS>>,
    actvtr: Option<TrackedOracle<F, MvPCS, UvPCS>>,
    num_vars: usize,
}

impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> TableComm<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub fn new(
        schema: Option<Schema>,
        col_vals: Vec<TrackedOracle<F, MvPCS, UvPCS>>,
        actvtr: Option<TrackedOracle<F, MvPCS, UvPCS>>,
        num_vars: usize,
    ) -> Self {
        Self {
            schema,
            col_vals,
            actvtr,
            num_vars,
        }
    }
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    pub fn fold(&self, col_inds: &[usize], challs: &[F]) -> ColCom<F, MvPCS, UvPCS> {
        let mut folded: TrackedOracle<F, MvPCS, UvPCS> = &self.col_vals[col_inds[0]] * challs[0];
        for i in 1..col_inds.len() {
            folded += &(&self.col_vals[col_inds[i]].clone() * challs[i]);
        }
        ColCom::new(None, folded, self.actvtr.clone(), self.num_vars)
    }

    pub fn fold_all(&self, challs: &[F]) -> ColCom<F, MvPCS, UvPCS> {
        self.fold(&(0..self.num_cols()).collect::<Vec<usize>>(), challs)
    }

    pub fn col(&self, col_ind: usize) -> ColCom<F, MvPCS, UvPCS> {
        ColCom::new(
            self.schema
                .as_ref()
                .map(|schema| schema.field(col_ind).clone().data_type().clone()),
            self.col_vals[col_ind].clone(),
            self.actvtr.clone(),
            self.num_vars,
        )
    }

    pub fn cols(&self, indice: &[usize]) -> Vec<ColCom<F, MvPCS, UvPCS>> {
        indice.iter().map(|&i| self.col(i)).collect()
    }
    pub fn all_cols(&self) -> Vec<ColCom<F, MvPCS, UvPCS>> {
        self.cols(&(0..self.num_cols()).collect::<Vec<usize>>())
    }
    pub fn num_cols(&self) -> usize {
        self.col_vals.len()
    }

    // TODO: Propagate error instead of unwraps
    pub fn from(
        table: ArithTable<F, MvPCS, UvPCS>,
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
    ) -> Self {
        let schema = table.schema.clone(); // Use the schema from the table, if available
        let data_comms: Vec<TrackedOracle<F, MvPCS, UvPCS>> = table
            .data_polys
            .iter()
            .map(|col| verifier.track_mv_com_by_id(col.id()).unwrap())
            .collect();
        match &table.actvtr_poly {
            Some(actvtr) => {
                let actvtr_comm = verifier.track_mv_com_by_id(actvtr.id()).unwrap();
                Self::new(schema, data_comms, Some(actvtr_comm), table.num_vars())
            },
            None => Self::new(schema, data_comms, None, table.num_vars()),
        }
    }
    pub fn col_vals(&self) -> Vec<TrackedOracle<F, MvPCS, UvPCS>> {
        self.col_vals.clone()
    }

    pub fn schema(&self) -> Option<Schema> {
        self.schema.clone()
    }
    pub fn actvtr_poly(&self) -> Option<TrackedOracle<F, MvPCS, UvPCS>> {
        self.actvtr.clone()
    }
}

pub async fn fieldify_df<F: PrimeField>(df: DataFrame) -> Result<Vec<Vec<F>>, EncodeError> {
    let mut field_vecs: Vec<Vec<F>> = vec![Vec::new(); df.schema().fields().len()];
    let partitioned_streams = df.execute_stream_partitioned().await.unwrap();

    for mut partition_stream in partitioned_streams {
        while let Some(batch) = partition_stream.next().await {
            for (i, array) in batch.unwrap().columns().iter().enumerate() {
                // One-liner using the macro
                // The following line will be expanded to the match block over the data types
                downcast_and_encode!(array, field_vecs[i], F);
            }
        }
    }
    Ok(field_vecs)
}

pub async fn arithmatize_df<F: PrimeField>(
    df: DataFrame,
    max_nv: usize,
) -> Result<(Vec<MLE<F>>, usize), EncodeError> {
    let mut field_vecs: Vec<Vec<F>> = fieldify_df::<F>(df).await?;
    let col_size = field_vecs[0].len();
    #[cfg(debug_assertions)]
    {
        field_vecs
            .iter()
            .for_each(|v| assert_eq!(v.len(), col_size));
    }

    // let nv: usize = log2(field_vecs.iter().map(|v| v.len()).max().unwrap()) as
    // usize;
    field_vecs.iter_mut().for_each(|v| {
        v.extend(repeat_n(F::zero(), (1 << max_nv) - v.len()));
    });
    let data_polys: Vec<MLE<F>> = field_vecs
        .iter()
        .map(|v| MLE::from_evaluations_slice(max_nv, v))
        .collect();
    Ok((data_polys, col_size))
}

pub async fn df_to_table<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    prover: &mut Prover<F, MvPCS, UvPCS>,
    df: DataFrame,
    max_nv: usize,
    compute_actvtr: bool,
) -> Result<ArithTable<F, MvPCS, UvPCS>, EncodeError> {
    let schema = df.schema();
    let (data_polys, col_size) = arithmatize_df(df.clone(), max_nv).await?;
    let data_tr_polys: Vec<TrackedPoly<F, MvPCS, UvPCS>> = data_polys
        .iter()
        .map(|p| prover.track_and_commit_mat_mv_poly(p).unwrap())
        .collect();
    let actv_opt = if compute_actvtr {
        let mut activator_evals: Vec<F> = vec![F::one(); col_size];
        activator_evals.extend(vec![F::zero(); 2_usize.pow(max_nv as u32) - col_size]);
        let activator_poly = MLE::from_evaluations_slice(max_nv, &activator_evals);
        let activator_tr_poly: TrackedPoly<F, MvPCS, UvPCS> = prover
            .track_and_commit_mat_mv_poly(&activator_poly)
            .unwrap();
        Some(activator_tr_poly)
    } else {
        None
    };

    let table = ArithTable::new(Some(schema.into()), data_tr_polys, actv_opt, col_size);
    Ok(table)
}
