use std::{collections::HashMap, sync::Arc};

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::arrow::datatypes::Schema;

use crate::table_oracle::ArithTableOracle;
#[derive(Clone)]
pub struct ProverCtx<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    table_oracles: HashMap<Schema, ArithTableOracle<F, MvPCS, UvPCS>>,
    already_committed_polys: HashMap<Arc<MLE<F>>, MvPCS::Commitment>,
}

impl<F, MvPCS, UvPCS> ProverCtx<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub fn new(
        table_oracles: HashMap<Schema, ArithTableOracle<F, MvPCS, UvPCS>>,
        already_committed_polys: HashMap<Arc<MLE<F>>, MvPCS::Commitment>,
    ) -> Self {
        Self {
            table_oracles,
            already_committed_polys,
        }
    }

    pub fn table_oracle(
        &self,
        schema: &Schema,
    ) -> Option<&ArithTableOracle<F, MvPCS, UvPCS>> {
        self.table_oracles.get(schema)
    }

    pub fn table_oracles(&self) -> &HashMap<Schema, ArithTableOracle<F, MvPCS, UvPCS>> {
        &self.table_oracles
    }

    pub fn already_committed_polys(&self) -> &HashMap<Arc<MLE<F>>, MvPCS::Commitment> {
        &self.already_committed_polys
    }

    pub fn add_committed_poly(&mut self, poly: Arc<MLE<F>>, commitment: MvPCS::Commitment) {
        self.already_committed_polys.insert(poly, commitment);
    }

    pub fn already_committed_poly(&self, poly: &MLE<F>) -> Option<&MvPCS::Commitment> {
        self.already_committed_polys.get(poly)
    }
}

impl<F, MvPCS, UvPCS> Default for ProverCtx<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn default() -> Self {
        Self {
            table_oracles: HashMap::new(),
            already_committed_polys: HashMap::new(),
        }
    }
}
