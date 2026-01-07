use std::marker::PhantomData;

use ark_piop::SnarkBackend;

pub const NAME: &str = "TableScan_lp_Gadget";
#[derive(Clone)]
pub struct Prover<B>(PhantomData<B>);

impl<B> Prover<B>
where
    B: SnarkBackend,
{
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

// impl<B> ProverGadget<B> for Prover<B>
// where
//     F: PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
// {
//     fn children(&self) -> Vec<Arc<dyn ProverGadget<B>>> {
//         Vec::new()
//     }

//     fn name(&self) -> String {
//         NAME.to_string()
//     }

//     fn hints(
//         &self,
//         input: &IndexMap<String, crate::nodes::HintDF>,
//     ) -> IndexMap<String, crate::nodes::HintDF> {
//         IndexMap::new()
//     }
// }
