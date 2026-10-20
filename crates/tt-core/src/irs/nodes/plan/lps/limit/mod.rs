use crate::irs::nodes::utils::{commit_with_tracker, field_to_usize, track_next_committed};
use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::{
    SnarkBackend,
    errors::{SnarkError, SnarkResult},
    verifier::{errors::VerifierError, structs::oracle::TrackedOracle},
};
mod hints;
use crate::{
    irs::{
        nodes::{
            IsLpNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
            hints::HintDF,
        },
        payloads::PayloadStructure,
        tree::Tree,
    },
    prover::irs::VirtualizedIr as ProverVirtualizedIr,
    verifier::irs::VirtualizedIr as VerifierVirtualizedIr,
};
use datafusion::arrow::datatypes::Schema;
use datafusion_expr::Limit;
use datafusion_expr::LogicalPlan;
pub struct LpNode<B>
where
    B: SnarkBackend,
{
    input: Arc<Node<B>>,
    limit: Limit,
}

impl<B: SnarkBackend> IsNode<B> for LpNode<B> {
    fn name(&self) -> String {
        "Limit".to_string()
    }

    fn display(&self) -> String {
        let skip = match self.limit.get_skip_type() {
            Ok(datafusion_expr::SkipType::Literal(val)) => val.to_string(),
            Ok(datafusion_expr::SkipType::UnsupportedExpr) => "<expr>".to_string(),
            Err(err) => format!("err:{err}"),
        };
        let fetch = match self.limit.get_fetch_type() {
            Ok(datafusion_expr::FetchType::Literal(Some(val))) => val.to_string(),
            Ok(datafusion_expr::FetchType::Literal(None)) => "none".to_string(),
            Ok(datafusion_expr::FetchType::UnsupportedExpr) => "<expr>".to_string(),
            Err(err) => format!("err:{err}"),
        };
        format!(
            "Limit\nInput: {}, skip: {}, fetch: {}",
            self.input.name(),
            skip,
            fetch
        )
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.input.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for LpNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        assert_no_skip(&self.limit);
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        let current_table = virtualized_ir
            .payload_for_node(&id)
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(table.clone()),
                _ => None,
            })
            .unwrap_or_default();

        let mut merged_polys = current_table.tracked_polys();
        debug_assert!(
            !merged_polys.is_empty(),
            "Limit payload should already contain the activator column"
        );

        for (field, poly) in input_table.tracked_polys_iter() {
            if field.name() == ACTIVATOR_COL_NAME {
                continue;
            }
            merged_polys
                .entry(field.clone())
                .or_insert_with(|| poly.clone());
        }

        let metadata = current_table
            .schema_ref()
            .map(|s| s.metadata().clone())
            .or_else(|| input_table.schema_ref().map(|s| s.metadata().clone()))
            .unwrap_or_default();

        let fields = merged_polys
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        let schema = Some(Schema::new_with_metadata(fields, metadata));

        let log_size = match (current_table.log_size(), input_table.log_size()) {
            (0, other) => other,
            (current, 0) => current,
            (current, input) => {
                debug_assert_eq!(current, input, "Limit log sizes should match input");
                current
            }
        };

        // Paper PIOP 15: the output activator is the virtual `Î.a · C_{µ,j}`,
        // where the prefix `j` holds the first `fetch` active rows, and a
        // sumcheck proves it has `c` ones. `j` and `c` are committed, so they
        // are in the transcript, and the verifier checks `c` against `fetch`.
        if let Some(input_act) = input_table.activator_tracked_poly() {
            let fetch = fetch_limit_literal(&self.limit);
            let input_evals = input_act.evaluations();
            let j = contig_s_from_fetch(&input_evals, fetch, input_table.size());
            let c = input_evals[..j].iter().copied().sum::<B::F>();
            // Committed before anything else is tracked, in the order the
            // verifier reads them.
            let tracker_rc = input_act.tracker();
            commit_with_tracker(&tracker_rc, 0, vec![B::F::from(j as u64)])?;
            commit_with_tracker(&tracker_rc, 0, vec![c])?;
            let contig = tracker_rc
                .borrow_mut()
                .get_or_build_contig_one_poly(log_size, j)?;
            let output_act = &input_act * &contig;
            tracker_rc
                .borrow_mut()
                .add_mv_sumcheck_claim(output_act.id(), c)?;
            let activator_field = merged_polys
                .keys()
                .find(|field| field.name() == ACTIVATOR_COL_NAME)
                .cloned()
                .unwrap_or_else(|| arithmetic::ACTIVATOR_FIELD.clone());
            merged_polys.insert(activator_field, output_act);
        }

        let updated_table = TrackedTable::new(schema, merged_polys, log_size);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for LpNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        assert_no_skip(&self.limit);
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        let current_table = virtualized_ir
            .payload_for_node(&id)
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(table.clone()),
                _ => None,
            })
            .unwrap_or_default();

        let mut merged_polys = current_table.tracked_oracles();
        debug_assert!(
            !merged_polys.is_empty(),
            "Limit payload should already contain the activator column"
        );

        for (field, poly) in input_table.tracked_oracles_iter() {
            if field.name() == ACTIVATOR_COL_NAME {
                continue;
            }
            merged_polys
                .entry(field.clone())
                .or_insert_with(|| poly.clone());
        }

        let metadata = current_table
            .schema_ref()
            .map(|s| s.metadata().clone())
            .or_else(|| input_table.schema_ref().map(|s| s.metadata().clone()))
            .unwrap_or_default();

        let fields = merged_polys
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        let schema = Some(Schema::new_with_metadata(fields, metadata));

        let log_size = match (current_table.log_size(), input_table.log_size()) {
            (0, other) => other,
            (current, 0) => current,
            (current, input) => {
                debug_assert_eq!(current, input, "Limit log sizes should match input");
                current
            }
        };

        if let Some(input_act) = input_table.activator_tracked_poly() {
            let tracker_rc = input_act.tracker();
            let j = committed_count(track_next_committed(&tracker_rc)?, "prefix length")?;
            let c = committed_count(track_next_committed(&tracker_rc)?, "row count")?;
            // Exactly `fetch` rows, or every active row when there are fewer:
            // then the prefix is the whole table.
            let whole_table = j == 1 << log_size;
            let count_ok = match fetch_limit_literal(&self.limit) {
                Some(fetch) => c == fetch || (whole_table && c < fetch),
                None => whole_table,
            };
            if !count_ok {
                return Err(SnarkError::VerifierError(
                    VerifierError::VerifierCheckFailed(format!(
                        "LIMIT output has {c} rows over a prefix of {j}"
                    )),
                ));
            }
            let contig = tracker_rc
                .borrow_mut()
                .get_or_build_contig_one_poly(log_size, j)?;
            let output_act = &input_act * &contig;
            tracker_rc
                .borrow_mut()
                .add_mv_sumcheck_claim(output_act.id(), B::F::from(c as u64));
            let activator_field = merged_polys
                .keys()
                .find(|field| field.name() == ACTIVATOR_COL_NAME)
                .cloned()
                .unwrap_or_else(|| arithmetic::ACTIVATOR_FIELD.clone());
            merged_polys.insert(activator_field, output_act);
        }

        let updated_table = TrackedTableOracle::new(schema, merged_polys, log_size);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }
    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for LpNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        None
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsProverPlanNode<B> for LpNode<B> {
    fn output(&self) -> HintDF {
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsProverPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Limit input cannot be a gadget node"),
        };

        let output_df = hints::build_output_dataframe(input_hint_df.data_frame(), &self.limit);
        let output_df = crate::irs::nodes::hints::sort_by_row_id_if_present(output_df)
            .expect("limit output row-id sort should succeed");
        HintDF::new_virtual(output_df)
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for LpNode<B> {
    fn output(&self) -> HintDF {
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Limit input cannot be a gadget node"),
        };
        // Verifier planning only needs schema; LIMIT preserves schema.
        input_hint_df.as_virtual_view()
    }
}

fn committed_count<B: SnarkBackend>(count: TrackedOracle<B>, what: &str) -> SnarkResult<usize> {
    match count.as_constant() {
        Some(value) if count.log_size() == 0 => field_to_usize(value, what),
        _ => Err(SnarkError::VerifierError(
            VerifierError::VerifierCheckFailed(format!(
                "the LIMIT {what} is not a committed scalar"
            )),
        )),
    }
}

fn fetch_limit_literal(limit: &Limit) -> Option<usize> {
    match limit.get_fetch_type() {
        Ok(datafusion_expr::FetchType::Literal(Some(val))) => Some(val),
        _ => None,
    }
}

fn contig_s_from_fetch<F: PrimeField>(
    activator: &[F],
    fetch: Option<usize>,
    table_size: usize,
) -> usize {
    match fetch {
        None => table_size,
        Some(0) => 0,
        Some(limit) => {
            let mut seen = 0usize;
            for (idx, val) in activator.iter().enumerate() {
                if *val == F::one() {
                    seen += 1;
                    if seen == limit {
                        return idx + 1;
                    }
                }
            }
            table_size
        }
    }
}

fn assert_no_skip(limit: &Limit) {
    match limit.get_skip_type() {
        Ok(datafusion_expr::SkipType::Literal(0)) => {}
        Ok(datafusion_expr::SkipType::Literal(val)) => {
            panic!("Limit skip is not supported (skip={val})");
        }
        Ok(datafusion_expr::SkipType::UnsupportedExpr) => {
            panic!("Limit skip expression is not supported");
        }
        Err(err) => {
            panic!("Limit skip parsing error: {err}");
        }
    }
}

impl<B: SnarkBackend> IsLpNode<B> for LpNode<B> {
    fn from_lp(_plan: LogicalPlan, _self_ref: std::sync::Weak<Node<B>>) -> Self
    where
        Self: Sized,
    {
        let limit = match _plan {
            LogicalPlan::Limit(limit) => limit,
            _ => panic!("Expected LogicalPlan::Limit"),
        };

        let input = Tree::<B>::from_logical_plan(&limit.input).root().clone();

        Self { input, limit }
    }

    fn lp(&self) -> LogicalPlan {
        LogicalPlan::Limit(self.limit.clone())
    }
}
