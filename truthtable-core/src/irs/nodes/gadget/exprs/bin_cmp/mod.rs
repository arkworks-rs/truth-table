use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, table::TrackedTable};
use ark_ff::One;
use ark_piop::SnarkBackend;
use ark_piop::prover::structs::polynomial::TrackedPoly;
use datafusion::arrow::datatypes::Schema;
use indexmap::IndexMap;

use crate::irs::nodes::{
    IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps, gadget::utils::sign,
};
use crate::irs::payloads::PayloadStructure;
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;

#[cfg(test)]
mod tests;

pub const LEFT_INPUT_LABEL: &str = "left_input";
pub const RIGHT_INPUT_LABEL: &str = "right_input";
pub const OUTPUT_LABEL: &str = "output";

#[derive(Clone, Copy, Debug)]
pub enum BinCmpOp {
    Geq,
    Leq,
    Gt,
    Lt,
}

pub struct BinCmpNode<B: SnarkBackend> {
    op: BinCmpOp,
    true_sign: Arc<Node<B>>,
    false_sign: Arc<Node<B>>,
}

impl<B: SnarkBackend> BinCmpNode<B> {
    pub fn new(op: BinCmpOp) -> Self {
        let (true_sign, false_sign) = Self::sign_pair(op);
        let true_sign_gadget = Arc::new(Node::<B>::Gadget(Arc::new(sign::SignNode::new(
            true_sign,
        ))));
        let false_sign_gadget = Arc::new(Node::<B>::Gadget(Arc::new(sign::SignNode::new(
            false_sign,
        ))));
        Self {
            op,
            true_sign: true_sign_gadget,
            false_sign: false_sign_gadget,
        }
    }

    pub fn geq() -> Self {
        Self::new(BinCmpOp::Geq)
    }

    pub fn leq() -> Self {
        Self::new(BinCmpOp::Leq)
    }

    pub fn gt() -> Self {
        Self::new(BinCmpOp::Gt)
    }

    pub fn lt() -> Self {
        Self::new(BinCmpOp::Lt)
    }

    fn sign_pair(op: BinCmpOp) -> (sign::Sign, sign::Sign) {
        match op {
            BinCmpOp::Geq => (sign::Sign::NonNegative, sign::Sign::Negative),
            BinCmpOp::Leq => (sign::Sign::NonPositive, sign::Sign::Positive),
            BinCmpOp::Gt => (sign::Sign::Positive, sign::Sign::NonPositive),
            BinCmpOp::Lt => (sign::Sign::Negative, sign::Sign::NonNegative),
        }
    }

    fn name_for_op(op: BinCmpOp) -> &'static str {
        match op {
            BinCmpOp::Geq => "Binary GEQ",
            BinCmpOp::Leq => "Binary LEQ",
            BinCmpOp::Gt => "Binary GT",
            BinCmpOp::Lt => "Binary LT",
        }
    }
}

impl<B: SnarkBackend> IsNode<B> for BinCmpNode<B> {
    fn name(&self) -> String {
        Self::name_for_op(self.op).to_string()
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.true_sign.clone(), self.false_sign.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for BinCmpNode<B> {
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
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Fetch the payload for this gadget node.
        let gadget_payload = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        // Extract the left, right, and output tracked tables from the payload.
        let (left_input, right_input, output) = match (
            gadget_payload.get(LEFT_INPUT_LABEL),
            gadget_payload.get(RIGHT_INPUT_LABEL),
            gadget_payload.get(OUTPUT_LABEL),
        ) {
            (Some(left), Some(right), Some(output)) => {
                (left.clone(), right.clone(), output.clone())
            }
            _ => panic!("Expected left, right, and output tables for binary compare gadget"),
        };

        // Ensure that the left and right inputs and output share the same activator polynomial.
        debug_assert_eq!(
            left_input.activator_tracked_poly(),
            right_input.activator_tracked_poly(),
            "Left and right inputs must share the same activator polynomial"
        );

        debug_assert_eq!(
            left_input.activator_tracked_poly(),
            output.activator_tracked_poly(),
            "Left input and output must share the same activator polynomial"
        );

        // Now that we are sure that the left and right inputs share the same activator polynomial, we get this activator.
        let shared_activator = left_input.activator_tracked_poly();

        let output_ind = output.data_tracked_polys_indices()[0];
        let output_poly = output.tracked_col_by_ind(output_ind).data_tracked_poly();

        let build_table_with_activator = |table: &TrackedTable<B>, activator: &TrackedPoly<B>| {
            let mut polys = IndexMap::new();
            for (field, poly) in table.tracked_polys_iter() {
                if field.name() == ACTIVATOR_COL_NAME {
                    continue;
                }
                polys.insert(field.clone(), poly.clone());
            }
            polys.insert(ACTIVATOR_FIELD.clone(), activator.clone());

            let metadata = table
                .schema_ref()
                .map(|s| s.metadata().clone())
                .unwrap_or_default();
            let fields = polys.keys().map(|f| f.as_ref().clone()).collect::<Vec<_>>();
            let schema = Some(Schema::new_with_metadata(fields, metadata));

            TrackedTable::new(schema, polys, table.log_size())
        };

        // Compute the activator for the true branch.
        let true_activator = match &shared_activator {
            Some(poly) => poly * &output_poly,
            None => output_poly.clone(),
        };
        let true_input = build_table_with_activator(&left_input, &true_activator.clone());
        let true_payload = IndexMap::from([(sign::INPUT_LABEL.to_string(), true_input)]);
        virtualized_ir.set_payload_for_node(
            self.true_sign.id(),
            Some(PayloadStructure::GadgetPayload(true_payload)),
        );

        // Compute the activator for the false branch.
        let neg_output_activator = output_poly
            .mul_scalar_poly(-B::F::one())
            .add_scalar_poly(B::F::one());
        let false_activator = match &shared_activator {
            Some(poly) => poly * &neg_output_activator,
            None => neg_output_activator.clone(),
        };
        let false_input = build_table_with_activator(&left_input, &false_activator.clone());
        let false_payload = IndexMap::from([(sign::INPUT_LABEL.to_string(), false_input)]);
        virtualized_ir.set_payload_for_node(
            self.false_sign.id(),
            Some(PayloadStructure::GadgetPayload(false_payload)),
        );
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for BinCmpNode<B> {
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
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Fetch the payload for this gadget node.
        let gadget_payload = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        // Extract the left, right, and output tracked tables from the payload.
        let (left_input, right_input, output) = match (
            gadget_payload.get(LEFT_INPUT_LABEL),
            gadget_payload.get(RIGHT_INPUT_LABEL),
            gadget_payload.get(OUTPUT_LABEL),
        ) {
            (Some(left), Some(right), Some(output)) => {
                (left.clone(), right.clone(), output.clone())
            }
            _ => panic!("Expected left, right, and output tables for binary compare gadget"),
        };

        // Ensure that the left and right inputs and output share the same activator oracle.
        debug_assert_eq!(
            left_input.activator_tracked_poly(),
            right_input.activator_tracked_poly(),
            "Left and right inputs must share the same activator oracle"
        );
        debug_assert_eq!(
            left_input.activator_tracked_poly(),
            output.activator_tracked_poly(),
            "Left input and output must share the same activator oracle"
        );

        // Now that we are sure that the left and right inputs share the same activator oracle, we get this activator.
        let shared_activator = left_input.activator_tracked_poly();

        let output_ind = output.data_tracked_oracles_indices()[0];
        let output_oracle = output
            .tracked_col_oracle_by_ind(output_ind)
            .data_tracked_oracle();

        let build_table_with_activator =
            |table: &arithmetic::table_oracle::TrackedTableOracle<B>,
             activator: &ark_piop::verifier::structs::oracle::TrackedOracle<B>| {
                let mut oracles = IndexMap::new();
                for (field, oracle) in table.tracked_oracles_iter() {
                    if field.name() == ACTIVATOR_COL_NAME {
                        continue;
                    }
                    oracles.insert(field.clone(), oracle.clone());
                }
                oracles.insert(ACTIVATOR_FIELD.clone(), activator.clone());

                let metadata = table
                    .schema_ref()
                    .map(|s| s.metadata().clone())
                    .unwrap_or_default();
                let fields = oracles
                    .keys()
                    .map(|f| f.as_ref().clone())
                    .collect::<Vec<_>>();
                let schema = Some(Schema::new_with_metadata(fields, metadata));

                let table_log_size = table.log_size();
                let activator_log_size = activator.log_size();
                let log_size = if table_log_size == 0 {
                    activator_log_size
                } else {
                    debug_assert_eq!(
                        table_log_size, activator_log_size,
                        "BinCmp gadget activator log size should match table log size"
                    );
                    table_log_size
                };
                arithmetic::table_oracle::TrackedTableOracle::new(schema, oracles, log_size)
            };

        // Build the true-branch gadget inputs.
        let true_activator = match &shared_activator {
            Some(oracle) => oracle * &output_oracle,
            None => output_oracle.clone(),
        };
        let true_input = build_table_with_activator(&left_input, &true_activator);
        let true_payload = IndexMap::from([(sign::INPUT_LABEL.to_string(), true_input)]);
        virtualized_ir.set_payload_for_node(
            self.true_sign.id(),
            Some(PayloadStructure::GadgetPayload(true_payload)),
        );

        // Build the false-branch gadget inputs.
        let neg_output_activator = output_oracle
            .mul_scalar_oracle(-B::F::one())
            .add_scalar_oracle(B::F::one());
        let false_activator = match &shared_activator {
            Some(oracle) => oracle * &neg_output_activator,
            None => neg_output_activator.clone(),
        };
        let false_input = build_table_with_activator(&left_input, &false_activator);
        let false_payload = IndexMap::from([(sign::INPUT_LABEL.to_string(), false_input)]);
        virtualized_ir.set_payload_for_node(
            self.false_sign.id(),
            Some(PayloadStructure::GadgetPayload(false_payload)),
        );
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for BinCmpNode<B> {
    fn prove(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        // TODO: implement gadget proof
        Ok(())
    }

    fn verify(
        &self,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}
