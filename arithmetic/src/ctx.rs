use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::arrow::datatypes::Schema;
use derivative::Derivative;
use indexmap::IndexMap;

use crate::table_oracle::ArithTableOracle;
#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "MvPCS: PCS<F>"),
    Clone(bound = "UvPCS: PCS<F>"),
    PartialEq(bound = "UvPCS: PCS<F>"),
    Debug(bound = "UvPCS: PCS<F>")
)]
pub struct SharedCtx<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    table_oracles: IndexMap<Schema, ArithTableOracle<F, MvPCS, UvPCS>>,
}

impl<F, MvPCS, UvPCS> SharedCtx<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    pub fn new(table_oracles: IndexMap<Schema, ArithTableOracle<F, MvPCS, UvPCS>>) -> Self {
        Self { table_oracles }
    }

    pub fn table_oracle(&self, schema: &Schema) -> Option<&ArithTableOracle<F, MvPCS, UvPCS>> {
        self.table_oracles.get(schema)
    }

    pub fn table_oracles(&self) -> &IndexMap<Schema, ArithTableOracle<F, MvPCS, UvPCS>> {
        &self.table_oracles
    }
}

impl<F, MvPCS, UvPCS> Default for SharedCtx<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    fn default() -> Self {
        Self {
            table_oracles: IndexMap::new(),
        }
    }
}
