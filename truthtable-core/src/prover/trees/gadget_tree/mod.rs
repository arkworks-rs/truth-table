pub mod display;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use indexmap::IndexMap;
use std::sync::Arc;

use crate::proof_nodes::{
    HintDF,
    prover::{ProverGadget, ProverPlanNode},
};
#[cfg(test)]
pub mod tests;

#[derive(Clone)]
pub struct GadgetForest<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    trees: Vec<Arc<GadgetTree<F, MvPCS, UvPCS>>>,
}

impl<F, MvPCS, UvPCS> GadgetForest<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    fn hints(&self) -> IndexMap<String, HintDF> {
        todo!()
    }
}

#[derive(Clone)]
pub struct GadgetTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    root: Arc<dyn ProverGadget<F, MvPCS, UvPCS>>,
}

impl<F, MvPCS, UvPCS> GadgetTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
{
    pub fn new(root: Arc<dyn ProverGadget<F, MvPCS, UvPCS>>) -> Self {
        Self { root }
    }

    pub fn root(&self) -> Arc<dyn ProverGadget<F, MvPCS, UvPCS>> {
        Arc::clone(&self.root)
    }
}
