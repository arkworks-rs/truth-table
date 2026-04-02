use std::sync::Arc;

use arithmetic::{ACTIVATOR_FIELD, is_system_column, table::TrackedTable};
use ark_ff::One;
use ark_piop::SnarkBackend;
use ark_piop::prover::structs::polynomial::TrackedPoly;
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use indexmap::IndexMap;

use crate::irs::nodes::NodeId;
use crate::irs::nodes::cost::ProvingCost;
use crate::irs::nodes::hints::HintDF;
use crate::irs::nodes::{
    IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps,
    gadget::utils::{bool, sign},
};
use crate::irs::payloads::PayloadStructure;
use crate::prover::irs::GadgetReadyIr;
use crate::prover::irs::{
    GadgetReadyIr as ProverGadgetReadyIr, VirtualizedIr as ProverVirtualizedIr,
};
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
    bool_check: Arc<Node<B>>,
}

impl<B: SnarkBackend> BinCmpNode<B> {
    pub fn new(op: BinCmpOp) -> Self {
        let (true_sign, false_sign) = Self::sign_pair(op);
        let true_sign_gadget = Arc::new(Node::<B>::Gadget(Arc::new(sign::SignNode::new(
            sign::SignConfig::Uniform(true_sign),
        ))));
        let false_sign_gadget = Arc::new(Node::<B>::Gadget(Arc::new(sign::SignNode::new(
            sign::SignConfig::Uniform(false_sign),
        ))));
        let bool_check_gadget = Arc::new(Node::<B>::Gadget(Arc::new(bool::GadgetNode::<B>::new())));
        Self {
            op,
            true_sign: true_sign_gadget,
            false_sign: false_sign_gadget,
            bool_check: bool_check_gadget,
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

    fn integer_width_and_signed(data_type: &DataType) -> Option<(u8, bool)> {
        match data_type {
            DataType::UInt8 => Some((8, false)),
            DataType::UInt16 => Some((16, false)),
            DataType::UInt32 => Some((32, false)),
            DataType::UInt64 => Some((64, false)),
            DataType::Int8 => Some((8, true)),
            DataType::Int16 => Some((16, true)),
            DataType::Int32 | DataType::Date32 => Some((32, true)),
            DataType::Int64 => Some((64, true)),
            _ => None,
        }
    }

    fn merged_sign_data_type(left: &DataType, right: &DataType) -> DataType {
        if left == right {
            return left.clone();
        }

        match (left, right) {
            (DataType::Decimal128(lp, ls), DataType::Decimal128(rp, rs)) => {
                DataType::Decimal128((*lp).max(*rp), (*ls).max(*rs))
            }
            (DataType::Decimal128(lp, ls), _) => DataType::Decimal128(*lp, *ls),
            (_, DataType::Decimal128(rp, rs)) => DataType::Decimal128(*rp, *rs),
            _ => {
                if let (Some((lb, lsigned)), Some((rb, rsigned))) = (
                    Self::integer_width_and_signed(left),
                    Self::integer_width_and_signed(right),
                ) {
                    let width = lb.max(rb);
                    let signed = lsigned || rsigned;
                    match (width, signed) {
                        (8, false) => DataType::UInt8,
                        (16, false) => DataType::UInt16,
                        (32, false) => DataType::UInt32,
                        (_, false) => DataType::UInt64,
                        (8, true) => DataType::Int8,
                        (16, true) => DataType::Int16,
                        (32, true) => DataType::Int32,
                        _ => DataType::Int64,
                    }
                } else {
                    left.clone()
                }
            }
        }
    }

    fn merged_sign_field(left_field: &FieldRef, right_field: &FieldRef) -> FieldRef {
        let merged_dtype =
            Self::merged_sign_data_type(left_field.data_type(), right_field.data_type());
        Arc::new(Field::new(
            left_field.name(),
            merged_dtype,
            left_field.is_nullable() || right_field.is_nullable(),
        ))
    }

    fn decimal_scale(data_type: &DataType) -> Option<i8> {
        match data_type {
            DataType::Decimal128(_, scale) => Some(*scale),
            _ => None,
        }
    }

    fn pow10(exp: u32) -> B::F {
        let mut out = B::F::one();
        let ten = B::F::from(10u64);
        for _ in 0..exp {
            out *= ten;
        }
        out
    }

    fn aligned_decimal_diff_polys(
        left_data_poly: &TrackedPoly<B>,
        left_type: &DataType,
        right_data_poly: &TrackedPoly<B>,
        right_type: &DataType,
    ) -> (TrackedPoly<B>, TrackedPoly<B>) {
        match (
            Self::decimal_scale(left_type),
            Self::decimal_scale(right_type),
        ) {
            (Some(left_scale), Some(right_scale)) => {
                let target = left_scale.max(right_scale);
                let left_aligned = if left_scale < target {
                    left_data_poly.mul_scalar_poly(Self::pow10((target - left_scale) as u32))
                } else {
                    left_data_poly.clone()
                };
                let right_aligned = if right_scale < target {
                    right_data_poly.mul_scalar_poly(Self::pow10((target - right_scale) as u32))
                } else {
                    right_data_poly.clone()
                };
                (left_aligned, right_aligned)
            }
            _ => (left_data_poly.clone(), right_data_poly.clone()),
        }
    }

    fn aligned_decimal_diff_oracles(
        left_data_oracle: &ark_piop::verifier::structs::oracle::TrackedOracle<B>,
        left_type: &DataType,
        right_data_oracle: &ark_piop::verifier::structs::oracle::TrackedOracle<B>,
        right_type: &DataType,
    ) -> (
        ark_piop::verifier::structs::oracle::TrackedOracle<B>,
        ark_piop::verifier::structs::oracle::TrackedOracle<B>,
    ) {
        match (
            Self::decimal_scale(left_type),
            Self::decimal_scale(right_type),
        ) {
            (Some(left_scale), Some(right_scale)) => {
                let target = left_scale.max(right_scale);
                let left_aligned = if left_scale < target {
                    left_data_oracle.mul_scalar_oracle(Self::pow10((target - left_scale) as u32))
                } else {
                    left_data_oracle.clone()
                };
                let right_aligned = if right_scale < target {
                    right_data_oracle.mul_scalar_oracle(Self::pow10((target - right_scale) as u32))
                } else {
                    right_data_oracle.clone()
                };
                (left_aligned, right_aligned)
            }
            _ => (left_data_oracle.clone(), right_data_oracle.clone()),
        }
    }
}

impl<B: SnarkBackend> IsNode<B> for BinCmpNode<B> {
    fn name(&self) -> String {
        Self::name_for_op(self.op).to_string()
    }

    fn display(&self) -> String {
        let name = self.name();
        crate::irs::nodes::display_with_inputs(&name, &self.children())
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![
            self.bool_check.clone(),
            self.true_sign.clone(),
            self.false_sign.clone(),
        ]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for BinCmpNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
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

        let left_data_ind = left_input.data_tracked_polys_indices()[0];
        let left_data_poly = left_input
            .tracked_col_by_ind(left_data_ind)
            .data_tracked_poly();
        let right_data_ind = right_input.data_tracked_polys_indices()[0];
        let right_data_poly = right_input
            .tracked_col_by_ind(right_data_ind)
            .data_tracked_poly();

        let left_data_field = left_input
            .tracked_polys()
            .keys()
            .find(|field| !is_system_column(field.name()))
            .cloned()
            .expect("BinCmp left input should include a data column");
        let right_data_field = right_input
            .tracked_polys()
            .keys()
            .find(|field| !is_system_column(field.name()))
            .cloned()
            .expect("BinCmp right input should include a data column");
        let (left_data_poly, right_data_poly) = Self::aligned_decimal_diff_polys(
            &left_data_poly,
            left_data_field.data_type(),
            &right_data_poly,
            right_data_field.data_type(),
        );

        let diff_data_poly = &left_data_poly - &right_data_poly;
        // Now that we are sure that the left and right inputs share the same activator polynomial, we get this activator.
        let shared_activator = left_input.activator_tracked_poly();

        let output_ind = output.data_tracked_polys_indices()[0];
        let output_poly = output.tracked_col_by_ind(output_ind).data_tracked_poly();

        let data_field = Self::merged_sign_field(&left_data_field, &right_data_field);
        let metadata = left_input
            .schema_ref()
            .map(|s| s.metadata().clone())
            .unwrap_or_default();

        let build_table_with_activator =
            |data_poly: &TrackedPoly<B>, activator: &TrackedPoly<B>| {
                let mut polys = IndexMap::new();
                polys.insert(data_field.clone(), data_poly.clone());
                polys.insert(ACTIVATOR_FIELD.clone(), activator.clone());

                let fields = polys.keys().map(|f| f.as_ref().clone()).collect::<Vec<_>>();
                let schema = Some(Schema::new_with_metadata(fields, metadata.clone()));

                let data_log_size = data_poly.log_size();
                debug_assert_eq!(
                    data_log_size,
                    activator.log_size(),
                    "BinCmp gadget activator log size should match data log size"
                );
                TrackedTable::new(schema, polys, data_log_size)
            };

        let true_activator = output_poly.clone();
        let true_input = build_table_with_activator(&diff_data_poly, &true_activator.clone());
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
            Some(poly) => poly - &output_poly,
            None => neg_output_activator.clone(),
        };
        let false_input = build_table_with_activator(&diff_data_poly, &false_activator.clone());
        let false_payload = IndexMap::from([(sign::INPUT_LABEL.to_string(), false_input)]);
        virtualized_ir.set_payload_for_node(
            self.false_sign.id(),
            Some(PayloadStructure::GadgetPayload(false_payload)),
        );

        let mut bool_payload = match virtualized_ir.payload_for_node(&self.bool_check.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        bool_payload.insert(bool::TABLE_LABEL.to_string(), output);
        virtualized_ir.set_payload_for_node(
            self.bool_check.id(),
            Some(PayloadStructure::GadgetPayload(bool_payload)),
        );
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
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let (true_input, false_input, output) = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => match (
                map.get(LEFT_INPUT_LABEL),
                map.get(RIGHT_INPUT_LABEL),
                map.get(OUTPUT_LABEL),
            ) {
                (Some(left_input), Some(right_input), Some(output)) => {
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

                    let left_data_ind = left_input.data_tracked_oracles_indices()[0];
                    let left_data_oracle = left_input
                        .tracked_col_oracle_by_ind(left_data_ind)
                        .data_tracked_oracle();
                    let right_data_ind = right_input.data_tracked_oracles_indices()[0];
                    let right_data_oracle = right_input
                        .tracked_col_oracle_by_ind(right_data_ind)
                        .data_tracked_oracle();

                    let output_ind = output.data_tracked_oracles_indices()[0];
                    let output_oracle = output
                        .tracked_col_oracle_by_ind(output_ind)
                        .data_tracked_oracle();

                    let left_data_field = left_input
                        .tracked_oracles()
                        .keys()
                        .find(|field| !is_system_column(field.name()))
                        .cloned()
                        .expect("BinCmp left input should include a data column");
                    let right_data_field = right_input
                        .tracked_oracles()
                        .keys()
                        .find(|field| !is_system_column(field.name()))
                        .cloned()
                        .expect("BinCmp right input should include a data column");
                    let (left_data_oracle, right_data_oracle) = Self::aligned_decimal_diff_oracles(
                        &left_data_oracle,
                        left_data_field.data_type(),
                        &right_data_oracle,
                        right_data_field.data_type(),
                    );
                    let diff_data_oracle = &left_data_oracle - &right_data_oracle;
                    let data_field = Self::merged_sign_field(&left_data_field, &right_data_field);
                    let metadata = left_input
                        .schema_ref()
                        .map(|s| s.metadata().clone())
                        .unwrap_or_default();

                    let build_table_with_activator =
                        |data_oracle: &ark_piop::verifier::structs::oracle::TrackedOracle<B>,
                         activator: &ark_piop::verifier::structs::oracle::TrackedOracle<B>| {
                            let mut oracles = IndexMap::new();
                            oracles.insert(data_field.clone(), data_oracle.clone());
                            oracles.insert(ACTIVATOR_FIELD.clone(), activator.clone());

                            let fields = oracles
                                .keys()
                                .map(|f| f.as_ref().clone())
                                .collect::<Vec<_>>();
                            let schema = Some(Schema::new_with_metadata(fields, metadata.clone()));

                            let data_log_size = data_oracle.log_size();
                            debug_assert_eq!(
                                data_log_size,
                                activator.log_size(),
                                "BinCmp gadget activator log size should match data log size"
                            );
                            arithmetic::table_oracle::TrackedTableOracle::new(
                                schema,
                                oracles,
                                data_log_size,
                            )
                        };

                    let true_activator = output_oracle.clone();
                    let true_input = build_table_with_activator(&diff_data_oracle, &true_activator);

                    // Build the false-branch gadget inputs.
                    let neg_output_activator = output_oracle
                        .mul_scalar_oracle(-B::F::one())
                        .add_scalar_oracle(B::F::one());
                    let false_activator = match &shared_activator {
                        Some(oracle) => oracle - &output_oracle,
                        None => neg_output_activator.clone(),
                    };
                    let false_input =
                        build_table_with_activator(&diff_data_oracle, &false_activator);

                    (true_input, false_input, output.clone())
                }
                _ => panic!("Expected left, right, and output tables for binary compare gadget"),
            },
            _ => panic!("Expected left, right, and output tables for binary compare gadget"),
        };

        let true_payload = IndexMap::from([(sign::INPUT_LABEL.to_string(), true_input)]);
        virtualized_ir.set_payload_for_node(
            self.true_sign.id(),
            Some(PayloadStructure::GadgetPayload(true_payload)),
        );

        let false_payload = IndexMap::from([(sign::INPUT_LABEL.to_string(), false_input)]);
        virtualized_ir.set_payload_for_node(
            self.false_sign.id(),
            Some(PayloadStructure::GadgetPayload(false_payload)),
        );

        let mut bool_payload = match virtualized_ir.payload_for_node(&self.bool_check.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        bool_payload.insert(bool::TABLE_LABEL.to_string(), output);
        virtualized_ir.set_payload_for_node(
            self.bool_check.id(),
            Some(PayloadStructure::GadgetPayload(bool_payload)),
        );
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

impl<B: SnarkBackend> IsGadgetNode<B> for BinCmpNode<B> {
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut ProverGadgetReadyIr<B>,
        id: NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Fetch the payload for this gadget node.
        let gadget_payload = match gadget_ready_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map,
            _ => return Ok(()),
        };
        // Extract the left, right, and output tracked tables from the payload.
        let (left_input, right_input, output) = match (
            gadget_payload.get(LEFT_INPUT_LABEL),
            gadget_payload.get(RIGHT_INPUT_LABEL),
            gadget_payload.get(OUTPUT_LABEL),
        ) {
            (Some(left), Some(right), Some(output)) => (left, right, output),
            _ => panic!("Expected left, right, and output tables for binary equality gadget"),
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
        let output_ind = output.data_tracked_polys_indices()[0];
        let output_poly = output.tracked_col_by_ind(output_ind).data_tracked_poly();

        if let Some(activator) = shared_activator {
            let zero_poly = &(activator.sub_scalar_poly(B::F::one())) * &output_poly;
            prover.add_mv_zerocheck_claim(zero_poly.id())?;
        };
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
        id: NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Fetch the payload for this gadget node.
        let gadget_payload = match gadget_ready_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map,
            _ => return Ok(()),
        };
        // Extract the left, right, and output tracked tables from the payload.
        let (left_input, right_input, output) = match (
            gadget_payload.get(LEFT_INPUT_LABEL),
            gadget_payload.get(RIGHT_INPUT_LABEL),
            gadget_payload.get(OUTPUT_LABEL),
        ) {
            (Some(left), Some(right), Some(output)) => (left, right, output),
            _ => panic!("Expected left, right, and output tables for binary equality gadget"),
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
        let output_poly = output
            .tracked_col_oracle_by_ind(output_ind)
            .data_tracked_oracle();

        if let Some(activator) = shared_activator {
            let zero_poly = &(activator.sub_scalar_oracle(B::F::one())) * &output_poly;
            verifier.add_zerocheck_claim(zero_poly.id());
        };

        Ok(())
    }

    fn prover_hints(&self) -> IndexMap<String, HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}
