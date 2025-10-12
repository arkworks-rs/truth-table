use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::arrow::datatypes::Schema;
use indexmap::IndexMap;

use crate::table_oracle::ArithTableOracle;
#[derive(Clone)]
pub struct SharedCtx<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    table_oracles: IndexMap<Schema, ArithTableOracle<F, MvPCS, UvPCS>>,
}

impl<F, MvPCS, UvPCS> SharedCtx<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
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
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn default() -> Self {
        Self {
            table_oracles: IndexMap::new(),
        }
    }
}
