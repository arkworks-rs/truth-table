use std::marker::PhantomData;

use crate::proof_nodes::{
    HintDF,
    gadgets::{ProverPermutationGadget, Sign, binary, col_eq, sign},
    prover::ProverGadget,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use indexmap::IndexMap;
use std::sync::Arc;

pub const NAME: &str = "Contigous_Sort_Round_Gadget";

#[derive(Clone)]
pub struct Prover<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    round: usize,
    _marker: PhantomData<(F, MvPCS, UvPCS)>,
}

impl<F, MvPCS, UvPCS> Prover<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    pub fn new_with_round(round: usize) -> Self {
        Self {
            round,
            _marker: PhantomData,
        }
    }
}

impl<F, MvPCS, UvPCS> ProverGadget<F, MvPCS, UvPCS> for Prover<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Send + Sync + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + Send + Sync + 'static,
{
    fn hints(&self, input: &IndexMap<String, HintDF>) -> IndexMap<String, HintDF> {
        todo!()
    }

    fn children(&self) -> Vec<Arc<dyn ProverGadget<F, MvPCS, UvPCS>>> {
        if self.round == 0 {
            vec![
                Arc::new(ProverPermutationGadget::new()) as Arc<dyn ProverGadget<F, MvPCS, UvPCS>>,
                Arc::new(sign::Prover::new(Sign::NoneNegative))
                    as Arc<dyn ProverGadget<F, MvPCS, UvPCS>>,
            ]
        } else {
            vec![
                Arc::new(binary::Prover::new()),
                Arc::new(col_eq::Prover::new()),
                Arc::new(sign::Prover::new(Sign::Nonezero)),
            ]
        }
    }

    fn name(&self) -> String {
        NAME.to_string()
    }
}
