use arithmetic::{
    table::TrackedTable,
    table_oracle::{ArithTableOracle, TrackedTableOracle},
};
use ark_piop::{SnarkBackend, prover::ArgProver, setup::structs::SNARKPk, verifier::ArgVerifier};
use datafusion_common::DataFusionError;
use proof_planner::data_dependent_lp_optimizer::apply_optimization_hints;
use tracing::debug;
use tt_core::errors::TTResult;
#[cfg(feature = "honest-prover")]
use tt_core::prover::passes::honest_prover::HonestProverPass;
use tt_core::{
    irs::shared_ir::EmptyIr,
    irs::{nodes::IsNode, payloads::PayloadStructure},
    prover::{
        irs::TrackedIr,
        irs::{GadgetReadyIr as ProverGadgetReadyIr, VirtualizedIr as ProverVirtualizedIr},
        passes::{
            gadget_initialization::GadgetInitializationPass, proving::ProvingPass,
            virtualization::VirtualizationPass,
        },
    },
};

use crate::{shared::TTSharedConfig, structs::TTProof};

pub struct TTDataOwnerConfig<B: SnarkBackend> {
    /// Commit every string column's rank (TruthTable++ §3.2). A table
    /// committed without ranks cannot serve a query that sorts by a string.
    ranks: bool,
    phantom: std::marker::PhantomData<B>,
}

impl<B: SnarkBackend> TTDataOwnerConfig<B> {
    pub fn new() -> Self {
        Self {
            ranks: true,
            phantom: std::marker::PhantomData,
        }
    }

    pub fn with_ranks(mut self, ranks: bool) -> Self {
        self.ranks = ranks;
        self
    }
}

impl<B: SnarkBackend> Default for TTDataOwnerConfig<B> {
    fn default() -> Self {
        Self::new()
    }
}

/// Commits table-scan outputs into serializable oracles, so the verifier
/// never sees the raw table.
pub struct TTDataOwner<B: SnarkBackend> {
    data_owner_config: TTDataOwnerConfig<B>,
    shared_config: TTSharedConfig<B>,
    snark_pk: SNARKPk<B>,
}

impl<B: SnarkBackend> TTDataOwner<B> {
    pub fn new(
        data_owner_config: TTDataOwnerConfig<B>,
        shared_config: TTSharedConfig<B>,
        snark_pk: SNARKPk<B>,
    ) -> Self {
        Self {
            data_owner_config,
            shared_config,
            snark_pk,
        }
    }

    fn data_owner_config(&self) -> &TTDataOwnerConfig<B> {
        &self.data_owner_config
    }

    /// The tracked `TableScan` payload, which becomes the serializable oracle.
    fn table_scan_payload(&self, tracked_ir: &TrackedIr<B>) -> TTResult<TrackedTable<B>> {
        for (node_id, node) in tracked_ir.tree().arena() {
            if node.name() != "TableScan" {
                continue;
            }

            let payload = tracked_ir
                .payloads()
                .get(node_id)
                .and_then(|payload| payload.clone())
                .and_then(|payload| match payload {
                    PayloadStructure::PlanPayload(table) => Some(table),
                    _ => None,
                });

            if let Some(table) = payload {
                return Ok(table);
            }
        }

        Err(DataFusionError::Internal("table scan payload not found".to_string()).into())
    }

    /// The proof encodes NULL as 0 and has no other notion of it, so a NULL
    /// would join, group and compare as a 0. The data owner commits none in
    /// an active row; padding rows are inactive.
    async fn ensure_no_nulls(&self, lp: &datafusion_expr::LogicalPlan) -> TTResult<()> {
        use datafusion_expr::{Expr, col};
        let schema = lp.schema();
        let null_checks = schema
            .iter()
            .filter(|(_, field)| !arithmetic::is_system_column(field.name()))
            .map(|(qualifier, field)| {
                Expr::Column(datafusion_common::Column::new(
                    qualifier.cloned(),
                    field.name(),
                ))
                .is_null()
            })
            .reduce(Expr::or);
        let Some(any_null) = null_checks else {
            return Ok(());
        };
        let has_activator = schema
            .fields()
            .iter()
            .any(|field| field.name() == arithmetic::ACTIVATOR_COL_NAME);
        let predicate = if has_activator {
            col(arithmetic::ACTIVATOR_COL_NAME).and(any_null)
        } else {
            any_null
        };
        let rows_with_nulls = self
            .shared_config
            .session_ctx()
            .execute_logical_plan(lp.clone())
            .await?
            .filter(predicate)?
            .count()
            .await?;
        if rows_with_nulls > 0 {
            return Err(DataFusionError::Plan(format!(
                "NULL is not supported: {rows_with_nulls} active rows hold a NULL"
            ))
            .into());
        }
        Ok(())
    }

    /// Commits the table-scan output of `query` into a serializable oracle.
    pub async fn commit(&self, query: &str) -> TTResult<ArithTableOracle<B>> {
        let rank_columns = if self.data_owner_config().ranks {
            tt_core::prover::passes::arithmetization::RankColumns::All
        } else {
            tt_core::prover::passes::arithmetization::RankColumns::None
        };

        let initial_lp = self.shared_config.query_to_lp(query).await;
        self.ensure_no_nulls(&initial_lp).await?;
        debug!("Initial Logical plan{}", initial_lp.display_graphviz());
        let analyzed_lp = self.shared_config.analyze_lp(initial_lp).await;
        let analyzed_and_optimized_lp = self.shared_config.optimize_lp(analyzed_lp).await;

        // Apply the data-dependent hints so the committed oracle matches the
        // plan shape used by proving and verification.
        let optimization_hints = self
            .shared_config
            .data_dependent_optimizer()
            .collect_hints(self.shared_config.session_ctx(), &analyzed_and_optimized_lp)?;
        let analyzed_and_optimized_lp =
            apply_optimization_hints(analyzed_and_optimized_lp, &optimization_hints)?;
        debug!(
            "optimized and analyzed logical plan:\n{}",
            analyzed_and_optimized_lp.display_graphviz()
        );

        tt_core::irs::supported::ensure_supported(&analyzed_and_optimized_lp)?;
        let initial_ir = EmptyIr::<B>::from_logical_plan(&analyzed_and_optimized_lp);
        debug!("initial ir:\n{}", initial_ir.display_graphviz(true));

        // The prover-side IR passes up through tracking expose the table scan.
        let optimized_initial_ir = self.shared_config.pp_optimizer().optimize(initial_ir);
        debug!(
            "optimized initial ir:\n{}",
            optimized_initial_ir.display_graphviz(true)
        );
        let output_planned_ir = optimized_initial_ir.apply_local_pass_parallel(
            &tt_core::prover::passes::output_planning::OutputPlanningPass::new(),
        );
        debug!(
            "output planned ir:\n{}",
            output_planned_ir.display_graphviz(true)
        );
        let gadget_planned_ir = output_planned_ir.apply_local_pass_sequential(
            &tt_core::prover::passes::gadget_planning::GadgetPlanningPass::new(&output_planned_ir),
        );
        drop(output_planned_ir);
        debug!(
            "gadget planned ir:\n{}",
            gadget_planned_ir.display_graphviz(true)
        );
        let materialized_ir = gadget_planned_ir.apply_local_pass_parallel(
            &tt_core::prover::passes::materialization::MaterializationPass::new(),
        );
        drop(gadget_planned_ir);
        debug!(
            "materialized ir:\n{}",
            materialized_ir.display_graphviz(true)
        );
        let arithmetized_ir = materialized_ir.apply_local_pass_parallel(
            &tt_core::prover::passes::arithmetization::ArithmetizationPass::new(
                // The oracle carries every string column's char-level side
                // segments and fingerprint limbs, so any later query can
                // read the characters of, or pre-filter, any column.
                tt_core::prover::passes::arithmetization::SideColumns::All,
                tt_core::prover::passes::arithmetization::FingerprintColumns::All,
                rank_columns,
            ),
        );
        drop(materialized_ir);
        debug!(
            "arithmetized ir:\n{}",
            arithmetized_ir.display_graphviz(true)
        );
        let arg_prover = ArgProver::new_from_pk(self.snark_pk.clone());
        let committed_ir = arithmetized_ir.apply_local_pass_parallel(
            &tt_core::prover::passes::commitment::CommitmentPass::new(
                arg_prover.mv_pcs_prover_param(),
                self.shared_config.ctx_oracles().clone(),
                true,
            ),
        );
        debug!("committed ir:\n{}", committed_ir.display_graphviz(true));
        let tracked_ir = committed_ir.apply_local_pass_sequential(
            &tt_core::prover::passes::tracking::TrackingPass::new(
                arg_prover.clone(),
                arithmetized_ir.payloads(),
                None,
            ),
        );
        drop(arithmetized_ir);
        drop(committed_ir);
        debug!("tracked ir:\n{}", tracked_ir.display_graphviz(true));
        // Taken before virtualization, where the scan sets its ranks aside.
        let table_scan = self.table_scan_payload(&tracked_ir)?;

        // Finish the proving pipeline: the tracked-table oracle is derived
        // from a proof.
        let virtualization_pass = VirtualizationPass::<B>::new(&tracked_ir);
        let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);
        debug!("virtualized ir:\n{}", virtualized_ir.display_graphviz(true));
        let gadget_ir_view = ProverVirtualizedIr::new(
            virtualized_ir.tree().clone(),
            virtualized_ir.payloads().clone(),
        );
        let gadget_initialization_pass =
            GadgetInitializationPass::<B>::new(gadget_ir_view, arg_prover.clone());
        let gadget_ready_ir =
            virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);
        drop(virtualized_ir);
        debug!(
            "gadget ready ir:\n{}",
            gadget_ready_ir.display_graphviz(true)
        );
        let proving_ir_view = ProverGadgetReadyIr::new(
            gadget_ready_ir.tree().clone(),
            gadget_ready_ir.payloads().clone(),
        );
        #[cfg(feature = "honest-prover")]
        {
            let honest_ir_view = ProverGadgetReadyIr::new(
                gadget_ready_ir.tree().clone(),
                gadget_ready_ir.payloads().clone(),
            );
            let honest_prover_pass =
                HonestProverPass::<B>::new(arg_prover.deep_copy(), honest_ir_view);
            let _honest_ir = gadget_ready_ir.apply_local_pass_sequential(&honest_prover_pass);
            honest_prover_pass.take_result()?;
        }
        let proving_pass = ProvingPass::<B>::new(arg_prover.clone(), proving_ir_view);
        let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&proving_pass);
        drop(gadget_ready_ir);
        proving_pass.take_result()?;
        let mut arg_prover = arg_prover;
        let arg_proof = arg_prover.build_proof().unwrap();
        let tt_proof = TTProof::new(
            arg_proof,
            optimization_hints,
            tt_core::irs::string_order::string_order(),
            Vec::new(),
        )?;

        // Convert the tracked table into a serializable oracle using
        // verifier-side state.
        let mut verifier = ArgVerifier::new_from_vk(self.snark_pk.vk.clone());
        verifier.set_proof(tt_proof.snark_proof());

        let tracked_table_oracle =
            TrackedTableOracle::from_tracked_table(table_scan, &mut verifier)?;
        Ok(ArithTableOracle::from_tracked_table_oracle(
            &tracked_table_oracle,
        ))
    }
}
