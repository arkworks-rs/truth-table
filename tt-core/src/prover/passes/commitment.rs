use std::sync::Arc;

use arithmetic::table_oracle::ArithTableOracle;
use ark_piop::{SnarkBackend, pcs::PCS};
use indexmap::IndexMap;
use tracing::debug;

use crate::ctx_oracles::CtxOracles;
use crate::irs::ir::LocalPass;
use crate::irs::nodes::{IsNode, Node, NodeId};
use crate::prover::payloads::{ArithPayload, CommittedPayload};

/// A commitment pass that turns arithmetized tables into table oracles.
///
/// This pass commits to each arithmetized column and records only the resulting
/// commitments inside an `ArithTableOracle`, enabling parallel commitment.
pub struct CommitmentPass<B: SnarkBackend> {
    mv_pcs_param: Arc<<B::MvPCS as PCS<B::F>>::ProverParam>,
    ctx_oracles: CtxOracles<B>,
}

impl<B: SnarkBackend> CommitmentPass<B> {
    pub fn new(
        mv_pcs_param: Arc<<B::MvPCS as PCS<B::F>>::ProverParam>,
        ctx_oracles: CtxOracles<B>,
    ) -> Self {
        Self {
            mv_pcs_param,
            ctx_oracles,
        }
    }
}

impl<B> LocalPass<B, ArithPayload<B::F>, CommittedPayload<B>> for CommitmentPass<B>
where
    B: SnarkBackend,
{
    fn order(&self) -> crate::irs::ir::PassOrder {
        crate::irs::ir::PassOrder::PostOrder
    }

    fn transform(
        &self,
        node: &Node<B>,
        _id: NodeId,
        payload: Option<&ArithPayload<B::F>>,
    ) -> Option<CommittedPayload<B>> {
        match payload? {
            ArithPayload::PlanPayload(arith_table) => {
                if node.name() == "TableScan"
                    && let Some(schema) = arith_table.schema()
                    && let Some(oracle) = self.ctx_oracles.table_oracle(&schema)
                {
                    debug!("using ctx_oracle for table scan in commitment pass");
                    return Some(CommittedPayload::PlanPayload(oracle.clone()));
                }

                Some(CommittedPayload::PlanPayload(arith_to_oracle::<B>(
                    arith_table,
                    &self.mv_pcs_param,
                )))
            }
            ArithPayload::GadgetPayload(map) => {
                let mut out = IndexMap::new();
                for (key, arith_table) in map {
                    out.insert(
                        key.clone(),
                        arith_to_oracle::<B>(arith_table, &self.mv_pcs_param),
                    );
                }

                if out.is_empty() {
                    None
                } else {
                    Some(CommittedPayload::GadgetPayload(out))
                }
            }
        }
    }
}

fn arith_to_oracle<B: SnarkBackend>(
    arith_table: &arithmetic::table::ArithTable<B::F>,
    mv_pcs_param: &Arc<<B::MvPCS as PCS<B::F>>::ProverParam>,
) -> ArithTableOracle<B> {
    let mut commitments = IndexMap::with_capacity(arith_table.polynomials().len());
    for (field_ref, mle_arc) in arith_table.polynomials() {
        let commitment = B::MvPCS::commit(Arc::clone(mv_pcs_param), mle_arc)
            .expect("failed to commit arithmetized polynomial");
        commitments.insert(field_ref.clone(), commitment);
    }

    ArithTableOracle::new(arith_table.schema(), commitments, arith_table.log_size())
}
