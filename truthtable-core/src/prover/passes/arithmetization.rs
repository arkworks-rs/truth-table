use ark_ff::PrimeField;
use ark_piop::SnarkBackend;
use arithmetic::table::ArithTable;
use datafusion::arrow::datatypes::Schema;
use indexmap::IndexMap;
use std::sync::Arc;

use crate::{
    irs::{
        ir::LocalPass,
        nodes::{Node, NodeId},
    },
    prover::payloads::{ArithPayload, MaterializedPayload},
};

pub struct ArithmetizationPass<B> {
    // pub ctx: ExecCtx,
    _phantom: std::marker::PhantomData<(B)>,
}

impl<B> ArithmetizationPass<B> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<B> LocalPass<B, MaterializedPayload, ArithPayload<B::F>> for ArithmetizationPass<B>
where
    B: SnarkBackend,
{
    fn transform(
        &self,
        node: &Node<B>,
        id: NodeId,
        payload: &MaterializedPayload,
    ) -> ArithPayload<B::F> {
        match payload {
            MaterializedPayload::PlanPayload(mat) => {
                ArithPayload::PlanPayload(arithmetize_materialized_table(mat))
            }
            MaterializedPayload::GadgetPayload(map) => {
                let mut out = IndexMap::new();
                for (k, mat) in map {
                    out.insert(k.clone(), arithmetize_materialized_table(mat));
                }
                ArithPayload::GadgetPayload(out)
            }
        }
    }
}

fn arithmetize_materialized_table<F: PrimeField>(
    mat: &MaterializedTable,
) -> ArithTable<F> {
    let schema: Schema = mat.mem_table().schema().as_ref().clone();
    // TODO: real arithmetization; placeholder empty polynomials with log_size 0.
    ArithTable::new(Some(schema), IndexMap::new(), 0)
}
