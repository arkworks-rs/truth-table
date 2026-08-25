use std::sync::Arc;

use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::One;
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{DataType, Field};
use datafusion_expr::{Aggregate, Expr};
use indexmap::IndexMap;

use crate::irs::nodes::utils::{bool, supp};
use crate::irs::nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps};
use crate::irs::payloads::PayloadStructure;
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;

pub const INPUT_LABEL: &str = "__input__";
pub const OUTPUT_LABEL: &str = "__output__";
const PREDICATE_COL_NAME: &str = "predicate";

pub struct GadgetNode<B: SnarkBackend> {
    supp_gadget: Option<Arc<Node<B>>>,
    bool_gadget: Option<Arc<Node<B>>>,
    aggregate: Aggregate,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Aggregate".to_string()
    }

    fn display(&self) -> String {
        let name = self.name();
        crate::irs::nodes::display_with_inputs(&name, &self.children())
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        let mut children = Vec::with_capacity(2);
        children.extend(self.supp_gadget.iter().cloned());
        children.extend(self.bool_gadget.iter().cloned());
        children
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        if !self.has_groups() {
            return Ok(());
        }
        let aggregate_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };

        let input_hint = match aggregate_payload.get(INPUT_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };
        let output_hint = match aggregate_payload.get(OUTPUT_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };

        let mut supp_payload =
            match planned_ir.payload_for_node(&self.supp_gadget.as_ref().unwrap().id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };

        supp_payload.insert(supp::ORIG_LABEL.to_string(), input_hint);
        supp_payload.insert(supp::SUPER_LABEL.to_string(), output_hint);

        planned_ir.set_payload_for_node(
            self.supp_gadget.as_ref().unwrap().id(),
            Some(PayloadStructure::GadgetPayload(supp_payload)),
        );
        Ok(())
    }

    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        if !self.has_groups() && !self.needs_ungrouped_extremum_check() {
            return Ok(());
        }
        let gadget_payload = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => panic!("Expected gadget payload for aggregate node"),
        };

        let output_table = gadget_payload
            .get(OUTPUT_LABEL)
            .cloned()
            .expect("Expected aggregate output table");

        if let Some(supp_gadget) = &self.supp_gadget {
            let input_table = gadget_payload
                .get(INPUT_LABEL)
                .cloned()
                .expect("Expected grouped aggregate input table");
            let mut supp_payload = match virtualized_ir.payload_for_node(&supp_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };

            supp_payload.insert(supp::ORIG_LABEL.to_string(), input_table);
            supp_payload.insert(supp::SUPER_LABEL.to_string(), output_table.clone());
            virtualized_ir.set_payload_for_node(
                supp_gadget.id(),
                Some(PayloadStructure::GadgetPayload(supp_payload)),
            );
        }

        if let Some(bool_gadget) = &self.bool_gadget {
            let bool_table = bool_table_from_output_prover(&output_table);
            let mut bool_payload = match virtualized_ir.payload_for_node(&bool_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            bool_payload.insert(bool::TABLE_LABEL.to_string(), bool_table);
            virtualized_ir.set_payload_for_node(
                bool_gadget.id(),
                Some(PayloadStructure::GadgetPayload(bool_payload)),
            );
        }
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        if !self.has_groups() {
            return Ok(());
        }
        let aggregate_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };

        let input_hint = match aggregate_payload.get(INPUT_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };
        let output_hint = match aggregate_payload.get(OUTPUT_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };

        let mut supp_payload =
            match planned_ir.payload_for_node(&self.supp_gadget.as_ref().unwrap().id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };

        supp_payload.insert(supp::ORIG_LABEL.to_string(), input_hint);
        supp_payload.insert(supp::SUPER_LABEL.to_string(), output_hint);

        planned_ir.set_payload_for_node(
            self.supp_gadget.as_ref().unwrap().id(),
            Some(PayloadStructure::GadgetPayload(supp_payload)),
        );
        Ok(())
    }

    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        if !self.has_groups() && !self.needs_ungrouped_extremum_check() {
            return Ok(());
        }
        let gadget_payload = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => panic!("Expected gadget payload for aggregate node"),
        };

        let output_table = gadget_payload
            .get(OUTPUT_LABEL)
            .cloned()
            .expect("Expected aggregate output table");

        if let Some(supp_gadget) = &self.supp_gadget {
            let input_table = gadget_payload
                .get(INPUT_LABEL)
                .cloned()
                .expect("Expected grouped aggregate input table");
            let mut supp_payload = match virtualized_ir.payload_for_node(&supp_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };

            supp_payload.insert(supp::ORIG_LABEL.to_string(), input_table);
            supp_payload.insert(supp::SUPER_LABEL.to_string(), output_table.clone());
            virtualized_ir.set_payload_for_node(
                supp_gadget.id(),
                Some(PayloadStructure::GadgetPayload(supp_payload)),
            );
        }

        if let Some(bool_gadget) = &self.bool_gadget {
            let bool_table = bool_table_from_output_verifier(&output_table);
            let mut bool_payload = match virtualized_ir.payload_for_node(&bool_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            bool_payload.insert(bool::TABLE_LABEL.to_string(), bool_table);
            virtualized_ir.set_payload_for_node(
                bool_gadget.id(),
                Some(PayloadStructure::GadgetPayload(bool_payload)),
            );
        }
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        if !self.needs_ungrouped_extremum_check() {
            return Ok(());
        }
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for ungrouped extremum aggregate");
        };
        let output = payload
            .get(OUTPUT_LABEL)
            .expect("Ungrouped extremum aggregate missing output table");
        let output_activator = output
            .activator_tracked_poly()
            .expect("Ungrouped extremum aggregate output must carry an activator");
        prover.add_mv_sumcheck_claim(output_activator.id(), B::F::one())?;
        Ok(())
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        if !self.needs_ungrouped_extremum_check() {
            return Ok(());
        }
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for ungrouped extremum aggregate");
        };
        let output = payload
            .get(OUTPUT_LABEL)
            .expect("Ungrouped extremum aggregate missing output table");
        let output_activator = output
            .activator_tracked_poly()
            .expect("Ungrouped extremum aggregate output must carry an activator");
        verifier.add_mv_sumcheck_claim(output_activator.id(), B::F::one());
        Ok(())
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}
impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(aggregate: Aggregate) -> Self {
        let has_groups = !aggregate.group_expr.is_empty();
        let needs_ungrouped_extremum_check =
            !has_groups && aggregate.aggr_expr.iter().any(is_extremum_expr);
        let supp_gadget = has_groups.then(|| {
            Arc::new(Node::<B>::Gadget(Arc::new(
                crate::irs::nodes::utils::supp::GadgetNode::new(),
            )))
        });
        // Grouped aggregates already need a Boolean output activator for Support/NoDup.
        // Ungrouped MAX/MIN need it as part of their exact-one representative check.
        let bool_gadget = (has_groups || needs_ungrouped_extremum_check).then(|| {
            Arc::new(Node::<B>::Gadget(Arc::new(
                crate::irs::nodes::utils::bool::GadgetNode::<B>::new(),
            )))
        });
        Self {
            supp_gadget,
            aggregate,
            bool_gadget,
        }
    }

    fn has_groups(&self) -> bool {
        !self.aggregate.group_expr.is_empty()
    }

    /// Ungrouped extrema require exactly one active output representative.
    ///
    /// Grouped aggregates obtain output-key uniqueness from Support/NoDup. Without
    /// `GROUP BY`, those gadgets are absent, so Booleanity plus a sum of one closes
    /// the otherwise-unconstrained output-cardinality case for MAX/MIN.
    ///
    /// This follows the current non-NULL aggregate model. SQL's one-NULL-row result
    /// for an empty input requires separate NULL semantics and is not handled here.
    fn needs_ungrouped_extremum_check(&self) -> bool {
        !self.has_groups() && self.aggregate.aggr_expr.iter().any(is_extremum_expr)
    }
}

fn is_extremum_expr(expr: &Expr) -> bool {
    match expr {
        Expr::Alias(alias) => is_extremum_expr(&alias.expr),
        Expr::AggregateFunction(function) => matches!(function.func.name(), "max" | "min"),
        _ => false,
    }
}

fn bool_table_from_output_prover<B: SnarkBackend>(output: &TrackedTable<B>) -> TrackedTable<B> {
    let predicate_poly = output
        .activator_tracked_poly()
        .expect("Aggregate output should carry an activator column");
    let predicate_field = Arc::new(Field::new(PREDICATE_COL_NAME, DataType::Boolean, false));
    TrackedTable::single_column_with_activator(predicate_field, predicate_poly, None)
}

fn bool_table_from_output_verifier<B: SnarkBackend>(
    output: &TrackedTableOracle<B>,
) -> TrackedTableOracle<B> {
    let predicate_oracle = output
        .activator_tracked_poly()
        .expect("Aggregate output should carry an activator column");
    let predicate_field = Arc::new(Field::new(PREDICATE_COL_NAME, DataType::Boolean, false));
    TrackedTableOracle::single_column_with_activator(predicate_field, predicate_oracle, None)
}
