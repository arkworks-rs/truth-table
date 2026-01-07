use ark_piop::SnarkBackend;
use std::marker::PhantomData;

pub const NAME: &str = "Sort_lp_Gadget";
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
