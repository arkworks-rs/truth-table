use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::{One, PrimeField};
use ark_piop::{SnarkBackend, errors::SnarkError};
mod hints;
use crate::{
    irs::{
        nodes::{
            IsLpNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
            gadget::lps::limit, hints::HintDF,
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
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
/// The implementation of a filter node in the prover proof tree.
pub struct LpNode<B>
where
    B: SnarkBackend,
{
    input: Arc<Node<B>>,
    gadget: Arc<Node<B>>,
    limit: Limit,
}

const LIMIT_CONTIG_S_PREFIX: &str = "limit_contig_s";
const LIMIT_CONTIG_SUM_PREFIX: &str = "limit_contig_sum";

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

        // Compute the contiguous mask size `s` and set output activator to
        // input_activator * contig_one(log_size, s).
        if let Some(input_act) = input_table.activator_tracked_poly() {
            let fetch = fetch_limit_literal(&self.limit);
            let s = contig_s_from_fetch(&input_act.evaluations(), fetch, input_table.size());
            let tracker_rc = input_act.tracker();
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

            let key = format!("{LIMIT_CONTIG_S_PREFIX}_{}", limit_key(&self.limit));
            tracker_rc
                .borrow_mut()
                .insert_miscellaneous_field(key, B::F::from(s as u64));
            // Store the actual sum of the output activator for the sumcheck claim.
            let sum_key = format!("{LIMIT_CONTIG_SUM_PREFIX}_{}", limit_key(&self.limit));
            let output_sum = output_act.evaluations().iter().copied().sum::<B::F>();
            tracker_rc
                .borrow_mut()
                .insert_miscellaneous_field(sum_key, output_sum);
        }

        let updated_table = TrackedTable::new(schema, merged_polys, log_size);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }

    /// The gadget for the filter node only takes in 1. the input activator column, 2. the output activator column and 3. the binary output of the predicate column.
    /// Then the gadget proves to you that the output activator column is correctly computed from the input activator column and the predicate column.
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
                limit::INPUT_ACTIVATOR_LABEL.to_string(),
                activator_only(input, "input_activator"),
            );
        }
        if let Some(output) = output_table.as_ref() {
            gadget_payload.insert(
                limit::OUTPUT_ACTIVATOR_LABEL.to_string(),
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

        // Mirror the prover: read `s` and apply contiguous mask to activator.
        if let Some(input_act) = input_table.activator_tracked_poly() {
            let tracker_rc = input_act.tracker();
            let key = format!("{LIMIT_CONTIG_S_PREFIX}_{}", limit_key(&self.limit));
            let s_field = tracker_rc.borrow().miscellaneous_field_element(&key)?;
            let s = field_to_usize::<B::F>(s_field)?;
            let contig = tracker_rc
                .borrow_mut()
                .get_or_build_contig_one_oracle(log_size, s)?;
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
                limit::INPUT_ACTIVATOR_LABEL.to_string(),
                activator_only(input, "input_activator"),
            );
        }
        if let Some(output) = output_table.as_ref() {
            gadget_payload.insert(
                limit::OUTPUT_ACTIVATOR_LABEL.to_string(),
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
        Ok(datafusion_expr::FetchType::Literal(Some(val))) => Some(val as usize),
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
                        "limit contig s does not fit into usize".to_string(),
                    ),
                ));
            }
            continue;
        }
        out |= (*byte as usize) << (8 * i);
    }
    Ok(out)
}

fn limit_key(limit: &Limit) -> u64 {
    let skip = match limit.get_skip_type() {
        Ok(datafusion_expr::SkipType::Literal(val)) => Some(val),
        _ => None,
    };
    let fetch = match limit.get_fetch_type() {
        Ok(datafusion_expr::FetchType::Literal(val)) => val,
        _ => None,
    };
    let mut hasher = DefaultHasher::new();
    (skip, fetch).hash(&mut hasher);
    hasher.finish()
}

fn assert_no_skip(limit: &Limit) {
    match limit.get_skip_type() {
        Ok(datafusion_expr::SkipType::Literal(val)) if val == 0 => {}
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

        // Recurse into the input subtree and fetch the logical plan that feeds this
        // limit.
        let input = Tree::<B>::from_logical_plan(&limit.input).root().clone();

        let gadget = Arc::new(Node::<B>::Gadget(Arc::new(limit::GadgetNode::new(
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
