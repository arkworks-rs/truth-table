use ark_piop::SnarkBackend;
use indexmap::IndexMap;
use std::{marker::PhantomData, sync::Arc};

use crate::irs::tree::Gadget;
pub const NAME: &str = "Sort_lp_Gadget";
#[derive(Clone)]
pub struct Prover<B>(PhantomData<(B)>);

impl<B> Prover<B>
where
    B: SnarkBackend,
{
    pub fn new() -> Self {
        Self(PhantomData)
    }
}
