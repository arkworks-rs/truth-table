use std::sync::Arc;
use std::collections::{HashMap, VecDeque};

use arithmetic::{
    table::{ArithTable, TrackedTable},
    ACTIVATOR_COL_NAME,
};
use ark_ff::Zero;
use ark_piop::{
    arithmetic::mat_poly::mle::MLE,
    pcs::PCS,
    prover::ArgProver,
    SnarkBackend,
};
use datafusion::{
    arrow::{
        array::{ArrayRef, BooleanArray},
        compute::{concat, concat_batches},
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    },
    datasource::{MemTable, TableProvider},
    prelude::SessionContext,
};
use datafusion_common::{DataFusionError, ScalarValue};
use indexmap::IndexMap;
use proof_planner::proof_plan_optimizer::{rules as proof_plan_rules, ProofPlanOptimizer};
use tracing::debug;
#[cfg(feature = "honest-prover")]
use tt_core::prover::passes::honest_prover::HonestProverPass;
use tt_core::{
    ctx_oracles::CtxOracles,
    errors::TTResult,
    irs::{
        nodes::{IsNode, NodeId},
        payloads::PayloadStructure,
        shared_ir::{EmptyIr, OutputPlannedIr},
        tree::Tree,
    },
    prover::{
        irs::{
            GadgetReadyIr as ProverGadgetReadyIr, VirtualizedIr as ProverVirtualizedIr,
        },
        passes::{
            arithmetization::{arithmetize_materialized_table, ArithmetizationPass}, commitment::CommitmentPass,
            gadget_initialization::GadgetInitializationPass,
            gadget_planning::GadgetPlanningPass as ProverGadgetPlanningPass,
            materialization::MaterializationPass,
            output_planning::OutputPlanningPass as ProverOutputPlanningPass, proving::ProvingPass,
            tracking::TrackingPass, virtualization::VirtualizationPass,
        },
        payloads::{ArithPayload, MaterializedTable},
    },
};

use crate::{shared::TTSharedConfig, structs::TTProof};

const RESULT_CHECK_SRC_POLY_ID_PREFIX: &str = "result_check_src_poly_id";

pub struct TTProverConfig<B: SnarkBackend> {
    allow_table_scan_commit_without_ctx: bool,
    phantom: std::marker::PhantomData<B>,
}
impl<B: SnarkBackend> TTProverConfig<B> {
    pub fn new() -> Self {
        Self {
            allow_table_scan_commit_without_ctx: false,
            phantom: std::marker::PhantomData,
        }
    }
    pub fn for_commit() -> Self {
        Self {
            allow_table_scan_commit_without_ctx: true,
            phantom: std::marker::PhantomData,
        }
    }
    pub fn output_planning_pass(&self) -> ProverOutputPlanningPass<B> {
        ProverOutputPlanningPass::new()
    }
    pub fn gadget_planning_pass(
        &self,
        planned_ir: &OutputPlannedIr<B>,
    ) -> ProverGadgetPlanningPass<B> {
        ProverGadgetPlanningPass::new(planned_ir)
    }
    pub fn materialization_pass(&self) -> MaterializationPass<B> {
        MaterializationPass::new()
    }
    pub fn arithmetization_pass(&self) -> ArithmetizationPass<B> {
        ArithmetizationPass::new()
    }
    pub fn commitment_pass(
        &self,
        mv_pcs_param: Arc<<B::MvPCS as PCS<B::F>>::ProverParam>,
        ctx_oracles: CtxOracles<B>,
    ) -> CommitmentPass<B> {
        CommitmentPass::new(
            mv_pcs_param,
            ctx_oracles,
            self.allow_table_scan_commit_without_ctx,
        )
    }
    pub fn tracking_pass<'a>(
        &self,
        arg_prover: ArgProver<B>,
        arith_payloads: &'a IndexMap<NodeId, Option<ArithPayload<B::F>>>,
    ) -> TrackingPass<'a, B> {
        TrackingPass::new(arg_prover, arith_payloads)
    }
}

impl<B: SnarkBackend> Default for TTProverConfig<B> {
    fn default() -> Self {
        Self::new()
    }
}

/// Prover configuration that bundles planner rules and context oracles.
pub struct TTProver<B: SnarkBackend> {
    prover_config: TTProverConfig<B>,
    shared_config: TTSharedConfig<B>,
    arg_prover: ArgProver<B>,
}

impl<B: SnarkBackend> TTProver<B> {
    pub fn new(
        prover_config: TTProverConfig<B>,
        shared_config: TTSharedConfig<B>,
        arg_prover: ArgProver<B>,
    ) -> Self {
        Self {
            prover_config,
            shared_config,
            arg_prover,
        }
    }

    pub fn prover_config(&self) -> &TTProverConfig<B> {
        &self.prover_config
    }
    pub fn shared_config(&self) -> &TTSharedConfig<B> {
        &self.shared_config
    }
    pub fn arg_prover(&self) -> &ArgProver<B> {
        &self.arg_prover
    }

    pub async fn prove(&self, query: &str) -> TTResult<(Arc<MemTable>, TTProof<B>)> {
        let (output_memtable, _table_scan, tt_proof) =
            self.prove_internal(query, true, false).await?;
        Ok((
            output_memtable.expect("output memtable should be present for prove()"),
            tt_proof,
        ))
    }

    pub async fn prove_with_table_scan(
        &self,
        query: &str,
    ) -> TTResult<(TrackedTable<B>, TTProof<B>)> {
        let (_output_memtable, table_scan, tt_proof) =
            self.prove_internal(query, false, true).await?;
        Ok((
            table_scan.expect("table scan payload should be present for commit proofs"),
            tt_proof,
        ))
    }

    async fn prove_internal(
        &self,
        query: &str,
        capture_output_memtable: bool,
        capture_table_scan: bool,
    ) -> TTResult<(Option<Arc<MemTable>>, Option<TrackedTable<B>>, TTProof<B>)> {
        let initial_lp = self.shared_config().query_to_lp(query).await;
        debug!("Initial Logical plan{}", initial_lp.display_graphviz());
        let analyzed_and_optimized_lp = self
            .shared_config()
            .analyze_and_optimize_lp(initial_lp)
            .await;

        debug!(
            "optimized and analyzed logical plan:\n{}",
            analyzed_and_optimized_lp.display_graphviz()
        );
        let tree: Tree<B> = Tree::from_logical_plan(&analyzed_and_optimized_lp);
        let initial_ir = EmptyIr::<B>::new_empty(tree);
        debug!("initial ir:\n{}", initial_ir.display_graphviz(true));
        let proof_plan_optimizer = ProofPlanOptimizer::new(proof_plan_rules());
        let optimized_initial_ir = proof_plan_optimizer.optimize(initial_ir);
        debug!(
            "optimized initial ir:\n{}",
            optimized_initial_ir.display_graphviz(true)
        );
        let optimized_tree = optimized_initial_ir.tree().clone();
        let output_planned_ir = optimized_initial_ir
            .apply_local_pass_parallel(&self.prover_config().output_planning_pass());
        debug!(
            "output planned ir:\n{}",
            output_planned_ir.display_graphviz(true)
        );
        let gadget_planned_ir = output_planned_ir.apply_local_pass_sequential(
            &self
                .prover_config()
                .gadget_planning_pass(&output_planned_ir),
        );
        drop(output_planned_ir);
        debug!(
            "gadget planned ir:\n{}",
            gadget_planned_ir.display_graphviz(true)
        );
        let materialized_ir = gadget_planned_ir
            .apply_local_pass_parallel(&self.prover_config().materialization_pass());
        drop(gadget_planned_ir);
        debug!(
            "materialized ir:\n{}",
            materialized_ir.display_graphviz(true)
        );

        let root_is_result_check = materialized_ir.tree().root().name() == "ResultCheck";
        let result_check_output = if root_is_result_check || capture_output_memtable {
            Some(self.extract_output_memtable(query).await?)
        } else {
            None
        };
        let result_check_src_positions = if root_is_result_check {
            Some(Self::result_check_src_positions_from_materialized(
                &materialized_ir,
                result_check_output
                    .as_ref()
                    .expect("ResultCheck output should be materialized"),
            )
            .await?)
        } else {
            None
        };
        let output_memtable = if capture_output_memtable {
            result_check_output.clone()
        } else {
            None
        };

        let arithmetized_ir =
            materialized_ir.apply_local_pass_parallel(&self.prover_config().arithmetization_pass());
        drop(materialized_ir);
        debug!(
            "arithmetized ir:\n{}",
            arithmetized_ir.display_graphviz(true)
        );

        let arg_prover = self.arg_prover().clone();
        let committed_ir =
            arithmetized_ir.apply_local_pass_parallel(&self.prover_config().commitment_pass(
                arg_prover.mv_pcs_prover_param(),
                self.shared_config().ctx_oracles().clone(),
            ));
        // debug!("committed ir:\n{}", committed_ir.display_graphviz(true));

        let mut tracked_ir = committed_ir.apply_local_pass_sequential(
            &self
                .prover_config()
                .tracking_pass(arg_prover.clone(), arithmetized_ir.payloads()),
        );
        drop(arithmetized_ir);
        drop(committed_ir);
        debug!("tracked ir:\n{}", tracked_ir.display_graphviz(true));

        self.track_query_output(
            &mut tracked_ir,
            result_check_output,
            result_check_src_positions,
            arg_prover.clone(),
        )
        .await?;

        let table_scan = if capture_table_scan {
            Some(Self::table_scan_payload(&tracked_ir)?)
        } else {
            None
        };

        let virtualization_pass = VirtualizationPass::<B>::new(&tracked_ir);
        let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);
        drop(tracked_ir);
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
            // Run the honest prover pass only when the feature is enabled.
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
        let optimized_ir = EmptyIr::<B>::new_empty(optimized_tree);
        let tt_proof = TTProof::new(arg_proof, optimized_ir);
        Ok((output_memtable, table_scan, tt_proof))
    }

    async fn extract_output_memtable(&self, query: &str) -> TTResult<Arc<MemTable>> {
        let df = self.shared_config().session_ctx().sql(query).await?;
        let base_schema = df.schema().as_arrow().clone();
        let batches = df.collect().await?;
        let (output_schema, output_batches) =
            Self::append_activator_and_pad_batches(&base_schema, batches)?;
        let mem_table = MemTable::try_new(Arc::new(output_schema), vec![output_batches])?;
        Ok(Arc::new(mem_table))
    }

    fn table_scan_payload(
        tracked_ir: &tt_core::prover::irs::TrackedIr<B>,
    ) -> TTResult<TrackedTable<B>> {
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

    async fn track_query_output(
        &self,
        tracked_ir: &mut tt_core::prover::irs::TrackedIr<B>,
        output_memtable: Option<Arc<MemTable>>,
        src_positions: Option<Vec<usize>>,
        mut arg_prover: ArgProver<B>,
    ) -> TTResult<()> {
        let Some(output_memtable) = output_memtable else {
            return Ok(());
        };
        let root = tracked_ir.tree().root();
        if root.name() != "ResultCheck" {
            return Ok(());
        }

        let input_table = Self::result_check_input_table(tracked_ir)?;
        let target_num_rows = 1usize << input_table.log_size();
        let target_schema = input_table
            .schema()
            .ok_or_else(|| {
                DataFusionError::Internal("ResultCheck input table schema is missing".to_string())
            })?;
        let support_positions = src_positions.ok_or_else(|| {
            DataFusionError::Internal("ResultCheck source positions are missing".to_string())
        })?;
        let src_poly = Self::build_result_check_src_poly(target_num_rows, &support_positions);
        let src_poly_id = arg_prover.track_and_send_mat_mv_poly(&src_poly)?.id();
        arg_prover.add_miscellaneous_field_element(
            Self::result_check_src_poly_key(root.id()),
            B::F::from(src_poly_id.to_int() as u64),
        )?;

        let materialized =
            Self::materialized_result_table_from_output(
                output_memtable,
                &target_schema,
                target_num_rows,
                &support_positions,
            )
            .await?;
        let arith_table = arithmetize_materialized_table::<B::F>(&materialized);
        let tracked_table =
            Self::track_arith_table_without_commitment(&arith_table, &mut arg_prover)?;
        tracked_ir.set_payload_for_node(
            root.id(),
            Some(PayloadStructure::PlanPayload(tracked_table)),
        );
        Ok(())
    }

    fn result_check_input_table(
        tracked_ir: &tt_core::prover::irs::TrackedIr<B>,
    ) -> TTResult<TrackedTable<B>> {
        let root = tracked_ir.tree().root();
        let input_id = root
            .children()
            .first()
            .map(|node| node.id())
            .ok_or_else(|| DataFusionError::Internal("ResultCheck input not found".to_string()))?;
        let input_table = tracked_ir
            .payload_for_node(&input_id)
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(table.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                DataFusionError::Internal("ResultCheck input payload not found".to_string())
            })?;
        Ok(input_table)
    }

    fn active_support_positions(evals: Vec<B::F>) -> Vec<usize> {
        evals.into_iter()
            .enumerate()
            .filter_map(|(idx, value)| (!value.is_zero()).then_some(idx))
            .collect()
    }

    fn build_result_check_src_poly(target_num_rows: usize, support_positions: &[usize]) -> MLE<B::F> {
        let mut evals = vec![B::F::zero(); target_num_rows];
        for (rank, &position) in support_positions.iter().enumerate() {
            evals[position] = B::F::from((rank + 1) as u64);
        }
        MLE::from_evaluations_vec(target_num_rows.trailing_zeros() as usize, evals)
    }

    async fn result_check_src_positions_from_materialized(
        materialized_ir: &tt_core::prover::irs::MaterializedIr<B>,
        output_memtable: &Arc<MemTable>,
    ) -> TTResult<Vec<usize>> {
        let root = materialized_ir.tree().root();
        let input_id = root
            .children()
            .first()
            .map(|node| node.id())
            .ok_or_else(|| DataFusionError::Internal("ResultCheck input not found".to_string()))?;
        let input_table = materialized_ir
            .payload_for_node(&input_id)
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(table.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                DataFusionError::Internal("ResultCheck input payload not found".to_string())
            })?;

        let sparse_batches = input_table.batches()?;
        let sparse_schema = input_table.mem_table().schema();
        let sparse_batch_refs: Vec<&RecordBatch> = sparse_batches.iter().collect();
        let sparse = concat_batches(&sparse_schema, sparse_batch_refs)
            .map_err(|e| DataFusionError::Execution(e.to_string()))?;

        let ctx = SessionContext::new();
        let compact_df = ctx.read_table(output_memtable.clone())?;
        let compact_batches = compact_df.collect().await?;
        let compact_schema = output_memtable.schema();
        let compact_batch_refs: Vec<&RecordBatch> = compact_batches.iter().collect();
        let compact = concat_batches(&compact_schema, compact_batch_refs)
            .map_err(|e| DataFusionError::Execution(e.to_string()))?;

        Self::match_compact_rows_to_sparse_positions(&sparse, &compact)
    }

    fn match_compact_rows_to_sparse_positions(
        sparse: &RecordBatch,
        compact: &RecordBatch,
    ) -> TTResult<Vec<usize>> {
        let sparse_activator_idx = sparse
            .schema()
            .index_of(ACTIVATOR_COL_NAME)
            .map_err(|e| DataFusionError::Execution(e.to_string()))?;
        let compact_activator_idx = compact
            .schema()
            .index_of(ACTIVATOR_COL_NAME)
            .map_err(|e| DataFusionError::Execution(e.to_string()))?;
        let sparse_activator = sparse
            .column(sparse_activator_idx)
            .as_any()
            .downcast_ref::<BooleanArray>()
            .ok_or_else(|| {
                DataFusionError::Internal("ResultCheck sparse activator is not boolean".to_string())
            })?;
        let compact_activator = compact
            .column(compact_activator_idx)
            .as_any()
            .downcast_ref::<BooleanArray>()
            .ok_or_else(|| {
                DataFusionError::Internal("ResultCheck compact activator is not boolean".to_string())
            })?;

        let sparse_schema = sparse.schema();
        let mut positions_by_key: HashMap<String, VecDeque<usize>> = HashMap::new();
        for row_idx in 0..sparse.num_rows() {
            if !sparse_activator.value(row_idx) {
                continue;
            }
            let key = Self::result_check_row_key(sparse, sparse_schema.as_ref(), row_idx)?;
            positions_by_key.entry(key).or_default().push_back(row_idx);
        }

        let compact_schema = compact.schema();
        let mut positions = Vec::new();
        for row_idx in 0..compact.num_rows() {
            if !compact_activator.value(row_idx) {
                continue;
            }
            let key = Self::result_check_row_key_casted(
                compact,
                compact_schema.as_ref(),
                row_idx,
                sparse_schema.as_ref(),
            )?;
            let position = positions_by_key
                .get_mut(&key)
                .and_then(VecDeque::pop_front)
                .ok_or_else(|| {
                    let sparse_examples = positions_by_key.keys().take(4).cloned().collect::<Vec<_>>();
                    let differing_columns = positions_by_key
                        .values()
                        .flat_map(|rows| rows.iter().copied())
                        .take(4)
                        .find_map(|sparse_row_idx| {
                            Self::describe_result_check_row_mismatch(
                                sparse,
                                compact,
                                sparse_row_idx,
                                row_idx,
                            )
                            .ok()
                            .filter(|s| !s.is_empty())
                        })
                        .unwrap_or_else(|| "unknown".to_string());
                    DataFusionError::Internal(format!(
                        "ResultCheck could not map compact row {} back to sparse input; compact_key={key}; sparse_examples={sparse_examples:?}; differing_columns={differing_columns}",
                        row_idx,
                    ))
                })?;
            positions.push(position);
        }
        Ok(positions)
    }

    fn describe_result_check_row_mismatch(
        sparse: &RecordBatch,
        compact: &RecordBatch,
        sparse_row_idx: usize,
        compact_row_idx: usize,
    ) -> TTResult<String> {
        let mut diffs = Vec::new();
        for sparse_field in sparse.schema().fields().iter() {
            if sparse_field.name() == ACTIVATOR_COL_NAME {
                continue;
            }
            let (sparse_col_idx, _) = sparse
                .schema()
                .column_with_name(sparse_field.name())
                .ok_or_else(|| DataFusionError::Internal("missing sparse column".to_string()))?;
            let (compact_col_idx, _) = compact
                .schema()
                .column_with_name(sparse_field.name())
                .ok_or_else(|| DataFusionError::Internal("missing compact column".to_string()))?;
            let sparse_value =
                ScalarValue::try_from_array(sparse.column(sparse_col_idx).as_ref(), sparse_row_idx)?;
            let compact_value = ScalarValue::try_from_array(
                compact.column(compact_col_idx).as_ref(),
                compact_row_idx,
            )?
            .cast_to(sparse_field.data_type())?;
            if sparse_value != compact_value {
                diffs.push(format!(
                    "{}: compact={:?}, sparse={:?}",
                    sparse_field.name(),
                    compact_value,
                    sparse_value
                ));
            }
        }
        Ok(diffs.join("; "))
    }

    fn result_check_row_key(
        batch: &RecordBatch,
        schema: &Schema,
        row_idx: usize,
    ) -> TTResult<String> {
        let mut parts = Vec::new();
        for (col_idx, field) in schema.fields().iter().enumerate() {
            if field.name() == ACTIVATOR_COL_NAME {
                continue;
            }
            let value = ScalarValue::try_from_array(batch.column(col_idx).as_ref(), row_idx)?;
            parts.push(format!("{:?}", value));
        }
        Ok(parts.join("|"))
    }

    fn result_check_row_key_casted(
        batch: &RecordBatch,
        source_schema: &Schema,
        row_idx: usize,
        target_schema: &Schema,
    ) -> TTResult<String> {
        let mut parts = Vec::new();
        for target_field in target_schema.fields().iter() {
            if target_field.name() == ACTIVATOR_COL_NAME {
                continue;
            }
            let source_idx = source_schema
                .fields()
                .iter()
                .position(|field| field.name() == target_field.name())
                .ok_or_else(|| {
                    DataFusionError::Internal(format!(
                        "ResultCheck output column {} not found",
                        target_field.name()
                    ))
                })?;
            let value = ScalarValue::try_from_array(batch.column(source_idx).as_ref(), row_idx)?
                .cast_to(target_field.data_type())?;
            parts.push(format!("{:?}", value));
        }
        Ok(parts.join("|"))
    }

    async fn materialized_result_table_from_output(
        output_memtable: Arc<MemTable>,
        target_schema: &Schema,
        target_num_rows: usize,
        support_positions: &[usize],
    ) -> TTResult<MaterializedTable> {
        let ctx = SessionContext::new();
        let df = ctx.read_table(output_memtable.clone())?;
        let compact_batches = df.collect().await?;
        let compact_schema = output_memtable.schema();
        let compact_row_count = compact_batches.iter().map(|batch| batch.num_rows()).sum::<usize>();

        let compact = if compact_row_count == 0 {
            None
        } else {
            let batch_refs: Vec<&RecordBatch> = compact_batches.iter().collect();
            Some(
                concat_batches(&compact_schema, batch_refs)
                    .map_err(|e| DataFusionError::Execution(e.to_string()))?,
            )
        };

        let compact_active_rows = compact
            .as_ref()
            .map_or(0, |batch| Self::count_active_rows(batch));
        if compact_active_rows != support_positions.len() {
            return Err(DataFusionError::Internal(format!(
                "ResultCheck output has {compact_active_rows} active rows but input support has {}",
                support_positions.len()
            ))
            .into());
        }

        let sparse_batch = Self::scatter_compact_output_to_support(
            target_schema,
            compact.as_ref(),
            target_num_rows,
            support_positions,
        )?;
        let rebuilt = MemTable::try_new(Arc::new(target_schema.clone()), vec![vec![sparse_batch.clone()]])?;
        Ok(MaterializedTable::new_with_batches(
            rebuilt,
            target_num_rows,
            vec![sparse_batch],
        ))
    }

    async fn materialized_table_from_memtable(
        mem_table: Arc<MemTable>,
        target_num_rows: Option<usize>,
    ) -> TTResult<MaterializedTable> {
        let ctx = SessionContext::new();
        let df = ctx.read_table(mem_table.clone())?;
        let mut batches = df.collect().await?;
        let schema = mem_table.schema();
        batches = Self::pad_memtable_batches_to_num_rows(schema.as_ref(), batches, target_num_rows)?;
        let row_count = batches.iter().map(|batch| batch.num_rows()).sum();
        let rebuilt = MemTable::try_new(mem_table.schema(), vec![batches.clone()])
            .expect("memtable rebuild from collected batches should succeed");
        Ok(MaterializedTable::new_with_batches(rebuilt, row_count, batches))
    }

    fn pad_memtable_batches_to_num_rows(
        schema: &Schema,
        batches: Vec<RecordBatch>,
        target_num_rows: Option<usize>,
    ) -> TTResult<Vec<RecordBatch>> {
        let row_count: usize = batches.iter().map(|batch| batch.num_rows()).sum();
        let Some(target_num_rows) = target_num_rows else {
            return Ok(batches);
        };
        if row_count > target_num_rows {
            return Err(DataFusionError::Internal(format!(
                "cannot pad output memtable from {} rows down to {} rows",
                row_count, target_num_rows
            ))
            .into());
        }
        if row_count == target_num_rows {
            return Ok(batches);
        }

        let schema_ref = Arc::new(schema.clone());
        let combined = if row_count == 0 || schema.fields().is_empty() {
            None
        } else {
            let batch_refs: Vec<&RecordBatch> = batches.iter().collect();
            Some(
                concat_batches(&schema_ref, batch_refs)
                    .map_err(|e| DataFusionError::Execution(e.to_string()))?,
            )
        };

        let pad = target_num_rows - row_count;
        let mut output_arrays = Vec::with_capacity(schema.fields().len());
        for (idx, field) in schema.fields().iter().enumerate() {
            let base = combined
                .as_ref()
                .map(|batch| batch.column(idx).clone())
                .unwrap_or_else(|| {
                    Self::inactive_padding_scalar(field.data_type())
                        .expect("padding scalar for schema field")
                        .to_array_of_size(0)
                        .expect("empty array for schema field")
                });
            let pad_arr = if field.name() == ACTIVATOR_COL_NAME {
                Arc::new(BooleanArray::from(vec![false; pad])) as ArrayRef
            } else {
                Self::inactive_padding_scalar(field.data_type())?.to_array_of_size(pad)?
            };
            output_arrays.push(
                concat(&[base.as_ref(), pad_arr.as_ref()])
                    .map_err(|e| DataFusionError::Execution(e.to_string()))?,
            );
        }

        let padded_batch = RecordBatch::try_new(schema_ref, output_arrays)
            .map_err(|e| DataFusionError::Execution(e.to_string()))?;
        Ok(vec![padded_batch])
    }

    fn track_arith_table_without_commitment(
        arith_table: &ArithTable<B::F>,
        arg_prover: &mut ArgProver<B>,
    ) -> TTResult<TrackedTable<B>> {
        let tracked_polys = arith_table
            .polynomials()
            .iter()
            .map(|(field_ref, mle)| {
                Ok((
                    field_ref.clone(),
                    arg_prover.track_and_send_mat_mv_poly(&mle)?,
                ))
            })
            .collect::<ark_piop::errors::SnarkResult<_>>()?;
        Ok(TrackedTable::new(
            arith_table.schema(),
            tracked_polys,
            arith_table.log_size(),
        ))
    }

    fn count_active_rows(batch: &RecordBatch) -> usize {
        batch
            .schema()
            .column_with_name(ACTIVATOR_COL_NAME)
            .and_then(|(idx, _)| batch.column(idx).as_any().downcast_ref::<BooleanArray>())
            .map(|activator| (0..activator.len()).filter(|&idx| activator.value(idx)).count())
            .unwrap_or_else(|| batch.num_rows())
    }

    fn scatter_compact_output_to_support(
        schema: &Schema,
        compact_batch: Option<&RecordBatch>,
        target_num_rows: usize,
        support_positions: &[usize],
    ) -> TTResult<RecordBatch> {
        let schema_ref = Arc::new(schema.clone());
        let mut output_arrays = Vec::with_capacity(schema.fields().len());

        for (col_idx, field) in schema.fields().iter().enumerate() {
            if field.name() == ACTIVATOR_COL_NAME {
                let mut activator = vec![false; target_num_rows];
                for &position in support_positions {
                    activator[position] = true;
                }
                output_arrays.push(Arc::new(BooleanArray::from(activator)) as ArrayRef);
                continue;
            }

            let inactive = Self::inactive_padding_scalar(field.data_type())?;
            let mut values = vec![inactive; target_num_rows];
            if let Some(batch) = compact_batch {
                let (source_idx, _) = batch
                    .schema()
                    .column_with_name(field.name())
                    .ok_or_else(|| {
                        DataFusionError::Internal(format!(
                            "ResultCheck output column {} not found",
                            field.name()
                        ))
                    })?;
                for (row_idx, &position) in support_positions.iter().enumerate() {
                    values[position] = ScalarValue::try_from_array(
                        batch.column(source_idx).as_ref(),
                        row_idx,
                    )?
                    .cast_to(field.data_type())?;
                }
            }
            output_arrays.push(ScalarValue::iter_to_array(values)?);
        }

        RecordBatch::try_new(schema_ref, output_arrays)
            .map_err(|e| DataFusionError::Execution(e.to_string()).into())
    }

    fn result_check_src_poly_key(id: NodeId) -> String {
        format!("{RESULT_CHECK_SRC_POLY_ID_PREFIX}_{id}")
    }

    fn append_activator_and_pad_batches(
        base_schema: &Schema,
        batches: Vec<RecordBatch>,
    ) -> TTResult<(Schema, Vec<RecordBatch>)> {
        let row_count: usize = batches.iter().map(|batch| batch.num_rows()).sum();
        let target = if row_count == 0 {
            2
        } else {
            row_count.next_power_of_two()
        };
        let output_schema = Self::schema_with_activator(base_schema);
        let output_schema_ref = Arc::new(output_schema.clone());
        let base_schema_ref = Arc::new(base_schema.clone());

        let combined = if row_count == 0 || base_schema.fields().is_empty() {
            None
        } else {
            let batch_refs: Vec<&RecordBatch> = batches.iter().collect();
            Some(
                concat_batches(&base_schema_ref, batch_refs)
                    .map_err(|e| DataFusionError::Execution(e.to_string()))?,
            )
        };

        let mut output_arrays = Vec::with_capacity(output_schema_ref.fields().len());
        for (idx, field) in base_schema.fields().iter().enumerate() {
            let array = if let Some(batch) = combined.as_ref() {
                let base = batch.column(idx).clone();
                let pad = target - row_count;
                if pad == 0 {
                    base
                } else {
                    let pad_arr =
                        Self::inactive_padding_scalar(field.data_type())?.to_array_of_size(pad)?;
                    concat(&[base.as_ref(), pad_arr.as_ref()])
                        .map_err(|e| DataFusionError::Execution(e.to_string()))?
                }
            } else {
                Self::inactive_padding_scalar(field.data_type())?.to_array_of_size(target)?
            };
            output_arrays.push(array);
        }

        let activator_values = std::iter::repeat_n(true, row_count)
            .chain(std::iter::repeat_n(false, target - row_count))
            .collect::<Vec<_>>();
        output_arrays.push(Arc::new(BooleanArray::from(activator_values)) as ArrayRef);

        let output_batch = RecordBatch::try_new(output_schema_ref, output_arrays)
            .map_err(|e| DataFusionError::Execution(e.to_string()))?;
        Ok((output_schema, vec![output_batch]))
    }

    fn schema_with_activator(base_schema: &Schema) -> Schema {
        let mut fields = base_schema
            .fields()
            .iter()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        fields.push(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false));
        Schema::new_with_metadata(fields, base_schema.metadata().clone())
    }

    fn inactive_padding_scalar(data_type: &DataType) -> TTResult<ScalarValue> {
        match ScalarValue::new_zero(data_type) {
            Ok(value) => Ok(value),
            Err(_) => match data_type {
                DataType::Utf8View => Ok(ScalarValue::Utf8View(Some(String::new()))),
                DataType::BinaryView => Ok(ScalarValue::BinaryView(Some(Vec::new()))),
                DataType::FixedSizeBinary(size) => {
                    Ok(ScalarValue::FixedSizeBinary(*size, Some(vec![0; *size as usize])))
                }
                _ => Err(DataFusionError::NotImplemented(format!(
                    "Can't create an inactive padding scalar from data_type \"{data_type}\""
                ))
                .into()),
            },
        }
    }
}
