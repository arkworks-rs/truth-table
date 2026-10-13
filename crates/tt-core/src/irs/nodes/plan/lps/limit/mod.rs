use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::{SnarkBackend, arithmetic::mat_poly::mle::MLE, errors::SnarkError};
use either::Either;
pub mod gadget;
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
use ark_ff::BigInteger;
use datafusion::arrow::datatypes::Schema;
use datafusion_expr::Limit;
use datafusion_expr::LogicalPlan;
use indexmap::IndexMap;
/// LIMIT preserves physical rows and selects a prefix of the input activator.
pub struct LpNode<B>
where
    B: SnarkBackend,
{
    input: Arc<Node<B>>,
    gadget: Arc<Node<B>>,
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
        vec![self.input.clone(), self.gadget.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for LpNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        ensure_no_skip(&self.limit)?;
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        // LIMIT preserves every raw data column. Reuse the input polynomial
        // handles structurally and replace only the activator; never retain a
        // prover-selected output column with the same field name.
        let mut merged_polys = input_table.tracked_polys();
        let schema = input_table.schema();
        let log_size = input_table.log_size();

        // Compute the contiguous mask size `s` and set output activator to
        // input_activator * contig_one(log_size, s).
        if let Some(input_act) = input_table.activator_tracked_poly() {
            let capacity = checked_capacity::<B::F>(log_size)?;
            let fetch = fetch_limit_literal(&self.limit);
            let s = contig_s_from_fetch(&input_act.evaluations(), fetch, capacity);
            let tracker_rc = input_act.tracker();
            let s_u64 = u64::try_from(s)
                .map_err(|_| limit_check_error("LIMIT prefix does not fit into u64"))?;
            let s_field = B::F::from(s_u64);
            let s_mle = MLE::from_evaluations_vec(0, vec![s_field]);
            match tracker_rc
                .borrow_mut()
                .track_and_commit_mat_mv_p(&s_mle, false)?
            {
                Either::Right((_id, committed)) if committed == s_field => {}
                _ => {
                    return Err(limit_check_error("LIMIT prefix must be a committed scalar"));
                }
            }
            let contig = tracker_rc
                .borrow_mut()
                .get_or_build_contig_one_poly(log_size, s)?;
            let output_act = &input_act * &contig;
            let activator_field = merged_polys
                .keys()
                .find(|field| field.name() == ACTIVATOR_COL_NAME)
                .cloned()
                .unwrap_or_else(|| arithmetic::ACTIVATOR_FIELD.clone());
            merged_polys.insert(activator_field, output_act.clone());
        }

        let updated_table = TrackedTable::new(schema, merged_polys, log_size);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }

    /// Supply both activators so the gadget can authenticate the output count
    /// and check that an undersized result retained every input row.
    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => Some(table.clone()),
            _ => None,
        };
        let output_table =
            virtualized_ir
                .payload_for_node(&_id)
                .and_then(|payload| match payload {
                    PayloadStructure::PlanPayload(table) => Some(table.clone()),
                    _ => None,
                });

        let activator_only = |table: &TrackedTable<B>, col_name: &str| {
            let idx = table
                .tracked_polys()
                .keys()
                .position(|field| field.name() == ACTIVATOR_COL_NAME)
                .expect("table should include activator column");
            let mut output = table.tracked_subtable_by_indices(&[idx]);
            output.rename_col(0, col_name);
            output
        };

        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        if let Some(input) = input_table.as_ref() {
            gadget_payload.insert(
                gadget::INPUT_ACTIVATOR_LABEL.to_string(),
                activator_only(input, "input_activator"),
            );
        }
        if let Some(output) = output_table.as_ref() {
            gadget_payload.insert(
                gadget::OUTPUT_ACTIVATOR_LABEL.to_string(),
                activator_only(output, "output_activator"),
            );
        }

        if !gadget_payload.is_empty() {
            virtualized_ir.set_payload_for_node(
                self.gadget.id(),
                Some(PayloadStructure::GadgetPayload(gadget_payload)),
            );
        }
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
        ensure_no_skip(&self.limit)?;
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };

        // Mirror the prover's structural reuse of input data columns.
        let mut merged_polys = input_table.tracked_oracles();
        let schema = input_table.schema();
        let log_size = input_table.log_size();

        // Mirror the prover: read `s` and apply contiguous mask to activator.
        if let Some(input_act) = input_table.activator_tracked_poly() {
            let tracker_rc = input_act.tracker();
            let s_id = tracker_rc.borrow_mut().peek_next_id();
            let s_field = tracker_rc
                .borrow()
                .proof_mv_constant(s_id)
                .ok_or_else(|| limit_check_error("LIMIT prefix is not a committed scalar"))?;
            let (s_num_vars, _tracked_id) = tracker_rc.borrow_mut().track_mv_com_by_id(s_id)?;
            if s_num_vars != 0 {
                return Err(limit_check_error(
                    "LIMIT prefix committed scalar has variables",
                ));
            }
            let s = field_to_usize::<B::F>(s_field)?;
            let capacity = checked_capacity::<B::F>(log_size)?;
            if s > capacity {
                return Err(limit_check_error("LIMIT prefix exceeds the input capacity"));
            }
            let contig = tracker_rc
                .borrow_mut()
                .get_or_build_contig_one_poly(log_size, s)?;
            let output_act = &input_act * &contig;
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
        id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => Some(table.clone()),
            _ => None,
        };
        let output_table = virtualized_ir
            .payload_for_node(&id)
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(table.clone()),
                _ => None,
            });

        let activator_only = |table: &TrackedTableOracle<B>, col_name: &str| {
            let (field_ref, activator_oracle) = table
                .tracked_oracles_iter()
                .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
                .expect("table should include activator column");
            let renamed_field = Arc::new(datafusion::arrow::datatypes::Field::new(
                col_name,
                field_ref.data_type().clone(),
                field_ref.is_nullable(),
            ));
            let mut oracles = IndexMap::new();
            oracles.insert(renamed_field.clone(), activator_oracle.clone());
            let schema = table.schema_ref().map(|schema| {
                Schema::new_with_metadata(
                    vec![renamed_field.as_ref().clone()],
                    schema.metadata().clone(),
                )
            });
            TrackedTableOracle::new(schema, oracles, table.log_size())
        };

        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        if let Some(input) = input_table.as_ref() {
            gadget_payload.insert(
                gadget::INPUT_ACTIVATOR_LABEL.to_string(),
                activator_only(input, "input_activator"),
            );
        }
        if let Some(output) = output_table.as_ref() {
            gadget_payload.insert(
                gadget::OUTPUT_ACTIVATOR_LABEL.to_string(),
                activator_only(output, "output_activator"),
            );
        }

        if !gadget_payload.is_empty() {
            virtualized_ir.set_payload_for_node(
                self.gadget.id(),
                Some(PayloadStructure::GadgetPayload(gadget_payload)),
            );
        }
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
        Some(self.gadget.as_ref().clone())
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

fn fetch_limit_literal(limit: &Limit) -> Option<usize> {
    match limit.get_fetch_type() {
        Ok(datafusion_expr::FetchType::Literal(Some(val))) => Some(val),
        _ => None,
    }
}

fn limit_check_error(message: &str) -> SnarkError {
    SnarkError::VerifierError(
        ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(message.to_string()),
    )
}

/// A Boolean activator's sum is an integer count only below the field modulus.
fn checked_capacity<F: PrimeField>(log_size: usize) -> ark_piop::errors::SnarkResult<usize> {
    let capacity = u32::try_from(log_size)
        .ok()
        .and_then(|bits| 1usize.checked_shl(bits))
        .ok_or_else(|| limit_check_error("LIMIT input capacity does not fit into usize"))?;
    let capacity_u64 = u64::try_from(capacity)
        .map_err(|_| limit_check_error("LIMIT input capacity does not fit into u64"))?;
    if F::BigInt::from(capacity_u64) >= F::MODULUS {
        return Err(limit_check_error(
            "LIMIT input capacity must be below the field modulus",
        ));
    }
    Ok(capacity)
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

fn field_to_usize<F: PrimeField>(value: F) -> ark_piop::errors::SnarkResult<usize> {
    let big = value.into_bigint();
    let bytes = big.to_bytes_le();
    let mut out: usize = 0;
    let max = std::mem::size_of::<usize>();
    for (i, byte) in bytes.iter().enumerate() {
        if i >= max {
            if *byte != 0 {
                return Err(SnarkError::VerifierError(
                    ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(
                        "LIMIT count or prefix does not fit into usize".to_string(),
                    ),
                ));
            }
            continue;
        }
        out |= (*byte as usize) << (8 * i);
    }
    Ok(out)
}

/// Accept only the zero-offset LIMIT fragment implemented by this protocol.
fn ensure_no_skip(limit: &Limit) -> ark_piop::errors::SnarkResult<()> {
    match limit.get_skip_type() {
        Ok(datafusion_expr::SkipType::Literal(0)) => Ok(()),
        Ok(datafusion_expr::SkipType::Literal(val)) => Err(limit_check_error(&format!(
            "LIMIT offset is unsupported (skip={val})"
        ))),
        Ok(datafusion_expr::SkipType::UnsupportedExpr) => Err(limit_check_error(
            "LIMIT offset must be a nonnegative literal",
        )),
        Err(err) => Err(limit_check_error(&format!(
            "LIMIT offset could not be parsed: {err}"
        ))),
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

        // Recurse into the input subtree and fetch the logical plan that feeds this
        // limit.
        let input = Tree::<B>::from_logical_plan(&limit.input).root().clone();

        let gadget = Arc::new(Node::<B>::Gadget(Arc::new(gadget::GadgetNode::new(
            limit.clone(),
        ))));

        Self {
            input,
            limit,
            gadget,
        }
    }

    fn lp(&self) -> LogicalPlan {
        LogicalPlan::Limit(self.limit.clone())
    }
}
