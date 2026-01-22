use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use arithmetic::table_oracle::ArithTableOracle;
use ark_piop::{SnarkBackend, pcs::PCS};
use indexmap::IndexMap;
use tracing::{debug, info};

use crate::ctx_oracles::CtxOracles;
use crate::irs::ir::LocalPass;
use crate::irs::nodes::{IsNode, Node, NodeId};
use crate::prover::payloads::{ArithPayload, CommittedPayload};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// A commitment pass that turns arithmetized tables into table oracles.
///
/// This pass commits to each arithmetized column and records only the resulting
/// commitments inside an `ArithTableOracle`, enabling parallel commitment.
pub struct CommitmentPass<B: SnarkBackend> {
    mv_pcs_param: Arc<<B::MvPCS as PCS<B::F>>::ProverParam>,
    ctx_oracles: CtxOracles<B>,
    total_committed: AtomicUsize, // Count polynomials committed by this pass.
    total_ctx_loaded: AtomicUsize, // Count polynomials loaded from ctx oracles.
}

impl<B: SnarkBackend> CommitmentPass<B> {
    pub fn new(
        mv_pcs_param: Arc<<B::MvPCS as PCS<B::F>>::ProverParam>,
        ctx_oracles: CtxOracles<B>,
    ) -> Self {
        Self {
            mv_pcs_param,
            ctx_oracles,
            total_committed: AtomicUsize::new(0),
            total_ctx_loaded: AtomicUsize::new(0),
        }
    }
}

impl<B: SnarkBackend> Drop for CommitmentPass<B> {
    fn drop(&mut self) {
        info!(
            committed = self.total_committed.load(Ordering::Relaxed),
            "total committed polynomials after commitment pass"
        );
        info!(
            ctx_loaded = self.total_ctx_loaded.load(Ordering::Relaxed),
            "total ctx-oracle polynomials loaded after commitment pass"
        );
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
                    debug!( node = %node.name(), num=%oracle.comitments().len(), "commitment loaded");
                    self.total_ctx_loaded
                        .fetch_add(oracle.comitments().len(), Ordering::Relaxed);
                    return Some(CommittedPayload::PlanPayload(oracle.clone()));
                }
                let commited_payloadd = arith_to_oracle::<B>(arith_table, &self.mv_pcs_param);
                debug!( node = %node.name(), num=commited_payloadd.comitments().len(), "committed");
                self.total_committed
                    .fetch_add(commited_payloadd.comitments().len(), Ordering::Relaxed);

                Some(CommittedPayload::PlanPayload(commited_payloadd))
            }
            ArithPayload::GadgetPayload(map) => {
                let mut out = IndexMap::new();
                let mut num_committed = 0;
                for (key, arith_table) in map {
                    let commitment_payload = arith_to_oracle::<B>(arith_table, &self.mv_pcs_param);
                    num_committed += commitment_payload.comitments().len();
                    out.insert(key.clone(), commitment_payload);
                }
                debug!( node = %node.name(), num=num_committed, "committed");
                self.total_committed
                    .fetch_add(num_committed, Ordering::Relaxed);

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
    let entries: Vec<(usize, _, _)> = arith_table
        .polynomials()
        .iter()
        .enumerate()
        .map(|(idx, (field_ref, mle_arc))| (idx, field_ref.clone(), Arc::clone(mle_arc)))
        .collect();
    let mut commitments = IndexMap::with_capacity(entries.len());

    #[cfg(feature = "parallel")]
    {
        let mut committed: Vec<(usize, _, _)> = entries
            .par_iter()
            .map(|(idx, field_ref, mle_arc)| {
                let commitment = B::MvPCS::commit(Arc::clone(mv_pcs_param), mle_arc)
                    .expect("failed to commit arithmetized polynomial");
                (*idx, field_ref.clone(), commitment)
            })
            .collect();
        committed.sort_by_key(|(idx, _, _)| *idx);
        for (_idx, field_ref, commitment) in committed {
            commitments.insert(field_ref, commitment);
        }
    }

    #[cfg(not(feature = "parallel"))]
    {
        for (_idx, field_ref, mle_arc) in entries {
            let commitment = B::MvPCS::commit(Arc::clone(mv_pcs_param), &mle_arc)
                .expect("failed to commit arithmetized polynomial");
            commitments.insert(field_ref, commitment);
        }
    }

    ArithTableOracle::new(arith_table.schema(), commitments, arith_table.log_size())
}
