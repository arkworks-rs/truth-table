use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_FIELD, col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::{One, PrimeField, Zero};
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::SnarkResult,
    piop::PIOP,
    prover::ArgProver,
    prover::structs::polynomial::TrackedPoly,
    verifier::{
        ArgVerifier,
        structs::oracle::{Oracle, TrackedOracle},
    },
};
use ark_poly::{
    DenseMVPolynomial, Polynomial,
    multivariate::{SparsePolynomial, SparseTerm, Term},
};
use col_toolbox::lookup::{LookupPIOP, LookupProverInput, LookupVerifierInput};
use datafusion::arrow::datatypes::DataType;
use either::Either;
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps, gadget::utils::neq},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub const INPUT_LABEL: &str = "__input__";
#[cfg(test)]
mod tests;
#[derive(Debug, Clone, Copy)]
pub enum Sign {
    NonNegative,
    Negative,
    NonPositive,
    Positive,
}
pub struct SignNode<B: SnarkBackend> {
    sign: Sign,
    neq_zero_gadget: Option<Arc<Node<B>>>,
}

impl<B: SnarkBackend> IsNode<B> for SignNode<B> {
    fn name(&self) -> String {
        "Sign".to_string()
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

    fn initialize_gadget_plans(
        &self,
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        self.neq_zero_gadget
            .as_ref()
            .map(|node| vec![node.clone()])
            .unwrap_or_default()
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for SignNode<B> {
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
        let Some(neq_gadget) = self.neq_zero_gadget.as_ref() else {
            return Ok(());
        };

        let gadget_payload = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        let input = gadget_payload
            .get(INPUT_LABEL)
            .cloned()
            .expect("Expected input for Sign gadget initialization");

        let data_indices = input.data_tracked_polys_indices();
        debug_assert!(
            !data_indices.is_empty(),
            "Sign gadget expects at least one data column in its input"
        );
        let mut left_cols = IndexMap::new();
        let mut right_cols = IndexMap::new();
        for data_ind in data_indices {
            let input_col = input.tracked_col_by_ind(data_ind);
            let data_field = input_col
                .field_ref()
                .expect("Expected field ref for Sign gadget input");
            let data_poly = input_col.data_tracked_poly();
            let zero_poly = TrackedPoly::new(
                Either::Right(B::F::zero()),
                data_poly.log_size(),
                data_poly.tracker(),
            );
            left_cols.insert(data_field.clone(), data_poly);
            right_cols.insert(data_field, zero_poly);
        }
        if let Some(activator) = input.activator_tracked_poly() {
            left_cols.insert(ACTIVATOR_FIELD.clone(), activator.clone());
            right_cols.insert(ACTIVATOR_FIELD.clone(), activator);
        }
        let left_table = TrackedTable::new(None, left_cols, input.log_size());
        let right_table = TrackedTable::new(None, right_cols, input.log_size());

        let mut neq_payload = match virtualized_ir.payload_for_node(&neq_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        neq_payload.insert(neq::LEFT_LABEL.to_string(), left_table);
        neq_payload.insert(neq::RIGHT_LABEL.to_string(), right_table);
        virtualized_ir.set_payload_for_node(
            neq_gadget.id(),
            Some(PayloadStructure::GadgetPayload(neq_payload)),
        );
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for SignNode<B> {
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
        let Some(neq_gadget) = self.neq_zero_gadget.as_ref() else {
            return Ok(());
        };

        let gadget_payload = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        let input = gadget_payload
            .get(INPUT_LABEL)
            .cloned()
            .expect("Expected input for Sign gadget initialization");

        let data_indices = input.data_tracked_oracles_indices();
        debug_assert!(
            !data_indices.is_empty(),
            "Sign gadget expects at least one data column in its input"
        );
        let mut left_cols = IndexMap::new();
        let mut right_cols = IndexMap::new();
        for data_ind in data_indices {
            let input_col = input.tracked_col_oracle_by_ind(data_ind);
            let data_field = input_col
                .field_ref()
                .expect("Expected field ref for Sign gadget input");
            let data_oracle = input_col.data_tracked_oracle();
            let zero_oracle = TrackedOracle::new(
                Either::Right(B::F::zero()),
                data_oracle.tracker(),
                data_oracle.log_size(),
            );
            left_cols.insert(data_field.clone(), data_oracle);
            right_cols.insert(data_field, zero_oracle);
        }
        if let Some(activator) = input.activator_tracked_poly() {
            left_cols.insert(ACTIVATOR_FIELD.clone(), activator.clone());
            right_cols.insert(ACTIVATOR_FIELD.clone(), activator);
        }
        let left_table = TrackedTableOracle::new(None, left_cols, input.log_size());
        let right_table = TrackedTableOracle::new(None, right_cols, input.log_size());

        let mut neq_payload = match virtualized_ir.payload_for_node(&neq_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        neq_payload.insert(neq::LEFT_LABEL.to_string(), left_table);
        neq_payload.insert(neq::RIGHT_LABEL.to_string(), right_table);
        virtualized_ir.set_payload_for_node(
            neq_gadget.id(),
            Some(PayloadStructure::GadgetPayload(neq_payload)),
        );
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for SignNode<B> {
    fn prove(
        &self,
        prover: &mut ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        // First fetch the payloads prepared for this gadget to consume
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for Sign gadget node");
        };
        // Then inside that payload, fetch the input
        let Some(input) = payload.get(INPUT_LABEL).cloned() else {
            panic!("Expected input for Sign gadget");
        };
        let data_inds = input.data_tracked_polys_indices();
        debug_assert!(
            !data_inds.is_empty(),
            "Sign gadget supports at least one data column per input."
        );
        for data_ind in data_inds {
            let input_col = input.tracked_col_by_ind(data_ind);
            match self.sign {
                Sign::NonNegative => {
                    Self::prove_sign_inner(prover, &input_col, Sign::NonNegative)?;
                }
                Sign::NonPositive => {
                    let negated_col = Self::negated_col(&input_col);
                    Self::prove_sign_inner(prover, &negated_col, Sign::NonNegative)?;
                }
                Sign::Positive => {
                    Self::prove_sign_inner(prover, &input_col, Sign::Positive)?;
                }
                Sign::Negative => {
                    let negated_col = Self::negated_col(&input_col);
                    Self::prove_sign_inner(prover, &negated_col, Sign::Positive)?;
                }
            }
        }
        Ok(())
    }

    fn honest_prover_check(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let _ = prover;
        // Validate activated rows against the expected sign semantics.
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let input = payload
            .get(INPUT_LABEL)
            .cloned()
            .expect("Expected input for Sign gadget");
        let data_inds = input.data_tracked_polys_indices();
        debug_assert!(
            !data_inds.is_empty(),
            "Sign gadget supports at least one data column per input."
        );
        let activator = input.activator_tracked_poly().map(|poly| poly.evaluations());
        for data_ind in data_inds {
            let input_col = input.tracked_col_by_ind(data_ind);
            let field_ref = input_col
                .field_ref()
                .expect("Expected field ref for Sign gadget");
            let data_type = field_ref.data_type();
            let evals = input_col.data_tracked_poly().evaluations();
            for (idx, eval) in evals.iter().enumerate() {
                if let Some(act) = activator.as_ref() {
                    if act[idx] != B::F::one() {
                        continue;
                    }
                }
                let (check_val, check_sign) = match self.sign {
                    Sign::NonNegative => (*eval, Sign::NonNegative),
                    Sign::Positive => (*eval, Sign::Positive),
                    Sign::NonPositive => (-*eval, Sign::NonNegative),
                    Sign::Negative => (-*eval, Sign::Positive),
                };
                if !Self::eval_matches_sign(data_type, check_sign, check_val) {
                    let (signed_val, unsigned_val, bit_width) =
                        Self::eval_debug_values(data_type, check_val);
                    tracing::error!(
                        target: "tt_core::prover::passes::honest_prover",
                        gadget = "Sign",
                        row = idx,
                        data_type = %data_type,
                        sign = ?self.sign,
                        effective_sign = ?check_sign,
                        bits = ?bit_width,
                        signed_val = ?signed_val,
                        unsigned_val = ?unsigned_val,
                        "honest prover sign check failed"
                    );
                    return Err(ark_piop::errors::SnarkError::ProverError(
                        ark_piop::prover::errors::ProverError::HonestProverError(
                            ark_piop::prover::errors::HonestProverError::FalseClaim,
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    fn verify(
        &self,
        verifier: &mut ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        // First fetch the payloads prepared for this gadget to consume
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for Sign gadget node");
        };
        // Then inside that payload, fetch the input
        let Some(input) = payload.get(INPUT_LABEL).cloned() else {
            panic!("Expected input for Sign gadget");
        };
        let data_inds = input.data_tracked_oracles_indices();
        debug_assert!(
            !data_inds.is_empty(),
            "Sign gadget supports at least one data column per input."
        );
        for data_ind in data_inds {
            let input_col = input.tracked_col_oracle_by_ind(data_ind);
            match self.sign {
                Sign::NonNegative => {
                    Self::verify_sign_inner(verifier, &input_col, Sign::NonNegative)?;
                }
                Sign::NonPositive => {
                    let negated_col = Self::negated_col_oracle(&input_col);
                    Self::verify_sign_inner(verifier, &negated_col, Sign::NonNegative)?;
                }
                Sign::Positive => {
                    Self::verify_sign_inner(verifier, &input_col, Sign::Positive)?;
                }
                Sign::Negative => {
                    let negated_col = Self::negated_col_oracle(&input_col);
                    Self::verify_sign_inner(verifier, &negated_col, Sign::Positive)?;
                }
            }
        }
        Ok(())
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> SignNode<B> {
    pub fn new(sign: Sign) -> Self {
        let has_zero = match sign {
            Sign::NonNegative | Sign::NonPositive => true,
            Sign::Positive | Sign::Negative => false,
        };
        let neq_zero_gadget = if !has_zero {
            Some(Arc::new(Node::<B>::Gadget(
                Arc::new(neq::GadgetNode::new()),
            )))
        } else {
            None
        };
        Self {
            sign,
            neq_zero_gadget,
        }
    }

    fn sparse_range_poly_by_nv(nv: usize) -> SnarkResult<SparsePolynomial<B::F, SparseTerm>> {
        let terms = (0..nv)
            .map(|i| {
                (
                    B::F::from(u64::pow(2, i as u32)),
                    SparseTerm::new(vec![(i, 1)]),
                )
            })
            .collect::<Vec<_>>();
        Ok(SparsePolynomial::from_coefficients_vec(nv, terms))
    }

    fn dense_range_poly_by_nv(nv: usize) -> MLE<B::F> {
        let evals = (0..2_usize.pow(nv as u32))
            .map(|x| B::F::from(x as u64))
            .collect::<Vec<_>>();
        MLE::from_evaluations_vec(nv, evals)
    }

    fn add_range_inclusion(
        prover: &mut ArgProver<B>,
        col: &TrackedCol<B>,
        nv: usize,
    ) -> SnarkResult<()> {
        let range_poly = prover.track_mat_mv_poly(Self::dense_range_poly_by_nv(nv));
        let super_col = TrackedCol::new(range_poly, None, None);
        let input = LookupProverInput {
            included_cols: vec![col.clone()],
            super_col,
        };
        LookupPIOP::<B>::prove(prover, input)?;
        Ok(())
    }

    fn negated_col(col: &TrackedCol<B>) -> TrackedCol<B> {
        TrackedCol::new(
            col.data_tracked_poly() * (-B::F::one()),
            col.activator_tracked_poly(),
            col.field_ref(),
        )
    }

    fn negated_col_oracle(col: &TrackedColOracle<B>) -> TrackedColOracle<B> {
        TrackedColOracle::new(
            col.data_tracked_oracle() * (-B::F::one()),
            col.activator_tracked_oracle(),
            col.field_ref(),
        )
    }

    fn range_oracle(nv: usize) -> Oracle<B::F> {
        Oracle::new_multivariate(nv, move |x| {
            Ok(Self::sparse_range_poly_by_nv(nv)?.evaluate(&x))
        })
    }

    fn add_range_inclusion_oracle(
        verifier: &mut ArgVerifier<B>,
        col: &TrackedColOracle<B>,
        nv: usize,
    ) -> SnarkResult<()> {
        let range_oracle = verifier.track_oracle(Self::range_oracle(nv));
        let super_col = TrackedColOracle::new(range_oracle, None, None);
        let input = LookupVerifierInput {
            included_tracked_col_oracles: vec![col.clone()],
            super_tracked_col_oracle: super_col,
        };
        LookupPIOP::<B>::verify(verifier, input)?;
        Ok(())
    }

    fn prove_sign_inner(
        prover: &mut ArgProver<B>,
        col: &TrackedCol<B>,
        _sign: Sign,
    ) -> SnarkResult<()> {
        let field_ref = col.field_ref().expect("Expected field ref for Sign gadget");
        let data_type = field_ref.data_type();
        match data_type {
            DataType::UInt8 => {
                Self::add_range_inclusion(prover, col, 8)?;
            }
            DataType::Int8 => {
                Self::add_range_inclusion(prover, col, 7)?;
            }
            DataType::UInt16 => {
                Self::add_range_inclusion(prover, col, 16)?;
            }
            DataType::Int16 => {
                Self::add_range_inclusion(prover, col, 15)?;
            }
            DataType::UInt32 => {
                let (chunk3, chunk2, chunk1, chunk0) = Self::prove_non_neg_uint32(prover, col)?;
                for segment in [chunk3, chunk2, chunk1, chunk0] {
                    Self::add_range_inclusion(prover, &segment, 16)?;
                }
            }
            DataType::Int32 | DataType::Date32 => {
                let (chunk3, chunk2, chunk1, chunk0) = Self::prove_non_neg_int32(prover, col)?;
                Self::add_range_inclusion(prover, &chunk3, 15)?;
                for segment in [chunk2, chunk1, chunk0] {
                    Self::add_range_inclusion(prover, &segment, 16)?;
                }
            }
            DataType::UInt64 => {
                let (chunk3, chunk2, chunk1, chunk0) = Self::prove_non_neg_uint64(prover, col)?;
                for segment in [chunk3, chunk2, chunk1, chunk0] {
                    Self::add_range_inclusion(prover, &segment, 16)?;
                }
            }
            DataType::Int64 => {
                let (chunk3, chunk2, chunk1, chunk0) = Self::prove_non_neg_int64(prover, col)?;
                Self::add_range_inclusion(prover, &chunk3, 15)?;
                for segment in [chunk2, chunk1, chunk0] {
                    Self::add_range_inclusion(prover, &segment, 16)?;
                }
            }
            DataType::Decimal128(..) => {
                let chunks = Self::prove_non_neg_int128(prover, col)?;
                let (top, rest) = chunks
                    .split_first()
                    .expect("chunked integer representation must be non-empty");
                Self::add_range_inclusion(prover, top, 15)?;
                for segment in rest {
                    Self::add_range_inclusion(prover, segment, 16)?;
                }
            }
            DataType::Utf8View => {
                let segments = Self::prove_non_neg_uint256(prover, col)?;
                for segment in segments {
                    Self::add_range_inclusion(prover, &segment, 16)?;
                }
            }
            _ => {
                return Err(ark_piop::errors::SnarkError::DataTypeError(
                    ark_piop::arithmetic::errors::DataTypeError::NotSupported(
                        data_type.to_string(),
                    ),
                ));
            }
        }
        Ok(())
    }

    fn verify_sign_inner(
        verifier: &mut ArgVerifier<B>,
        col: &TrackedColOracle<B>,
        _sign: Sign,
    ) -> SnarkResult<()> {
        let field_ref = col.field_ref().expect("Expected field ref for Sign gadget");
        let data_type = field_ref.data_type();
        match data_type {
            DataType::UInt8 => {
                Self::add_range_inclusion_oracle(verifier, col, 8)?;
            }
            DataType::Int8 => {
                Self::add_range_inclusion_oracle(verifier, col, 7)?;
            }
            DataType::UInt16 => {
                Self::add_range_inclusion_oracle(verifier, col, 16)?;
            }
            DataType::Int16 => {
                Self::add_range_inclusion_oracle(verifier, col, 15)?;
            }
            DataType::UInt32 => {
                let (chunk3, chunk2, chunk1, chunk0) = Self::verify_non_neg_uint32(verifier, col)?;
                for segment in [chunk3, chunk2, chunk1, chunk0] {
                    Self::add_range_inclusion_oracle(verifier, &segment, 16)?;
                }
            }
            DataType::Int32 | DataType::Date32 => {
                let (chunk3, chunk2, chunk1, chunk0) = Self::verify_non_neg_int32(verifier, col)?;
                Self::add_range_inclusion_oracle(verifier, &chunk3, 15)?;
                for segment in [chunk2, chunk1, chunk0] {
                    Self::add_range_inclusion_oracle(verifier, &segment, 16)?;
                }
            }
            DataType::UInt64 => {
                let (chunk3, chunk2, chunk1, chunk0) = Self::verify_non_neg_uint64(verifier, col)?;
                for segment in [chunk3, chunk2, chunk1, chunk0] {
                    Self::add_range_inclusion_oracle(verifier, &segment, 16)?;
                }
            }
            DataType::Int64 => {
                let (chunk3, chunk2, chunk1, chunk0) = Self::verify_non_neg_int64(verifier, col)?;
                Self::add_range_inclusion_oracle(verifier, &chunk3, 15)?;
                for segment in [chunk2, chunk1, chunk0] {
                    Self::add_range_inclusion_oracle(verifier, &segment, 16)?;
                }
            }
            DataType::Decimal128(..) => {
                let segments = Self::verify_non_neg_int128(verifier, col)?;
                let (top, rest) = segments
                    .split_first()
                    .expect("chunked integer representation must be non-empty");
                Self::add_range_inclusion_oracle(verifier, top, 15)?;
                for segment in rest {
                    Self::add_range_inclusion_oracle(verifier, segment, 16)?;
                }
            }
            DataType::Utf8View => {
                let segments = Self::verify_non_neg_uint256(verifier, col)?;
                for segment in segments {
                    Self::add_range_inclusion_oracle(verifier, &segment, 16)?;
                }
            }
            _ => {
                return Err(ark_piop::errors::SnarkError::DataTypeError(
                    ark_piop::arithmetic::errors::DataTypeError::NotSupported(
                        data_type.to_string(),
                    ),
                ));
            }
        }
        Ok(())
    }

    #[allow(clippy::complexity)]
    fn prove_non_neg_uint32(
        prover: &mut ArgProver<B>,
        col: &TrackedCol<B>,
    ) -> SnarkResult<(TrackedCol<B>, TrackedCol<B>, TrackedCol<B>, TrackedCol<B>)> {
        Self::prove_non_neg_u16_chunks_4(prover, col, |eval| {
            let n = Self::field_low_bits_unsigned(eval, 32) as u32;
            Self::split_u32_into_u16s(n)
        })
    }

    #[allow(clippy::complexity)]
    fn verify_non_neg_uint32(
        verifier: &mut ArgVerifier<B>,
        tracked_col_oracle: &TrackedColOracle<B>,
    ) -> SnarkResult<(
        TrackedColOracle<B>,
        TrackedColOracle<B>,
        TrackedColOracle<B>,
        TrackedColOracle<B>,
    )> {
        Self::verify_non_neg_u16_chunks_4(verifier, tracked_col_oracle)
    }

    #[allow(clippy::complexity)]
    fn prove_non_neg_int32(
        prover: &mut ArgProver<B>,
        col: &TrackedCol<B>,
    ) -> SnarkResult<(TrackedCol<B>, TrackedCol<B>, TrackedCol<B>, TrackedCol<B>)> {
        Self::prove_non_neg_u16_chunks_4(prover, col, |eval| {
            let n = Self::field_low_bits_signed(eval, 32) as i32;
            Self::split_i32_into_u16s(n)
        })
    }

    #[allow(clippy::complexity)]
    fn verify_non_neg_int32(
        verifier: &mut ArgVerifier<B>,
        tracked_col_oracle: &TrackedColOracle<B>,
    ) -> SnarkResult<(
        TrackedColOracle<B>,
        TrackedColOracle<B>,
        TrackedColOracle<B>,
        TrackedColOracle<B>,
    )> {
        Self::verify_non_neg_u16_chunks_4(verifier, tracked_col_oracle)
    }

    #[allow(clippy::complexity)]
    fn prove_non_neg_uint64(
        prover: &mut ArgProver<B>,
        col: &TrackedCol<B>,
    ) -> SnarkResult<(TrackedCol<B>, TrackedCol<B>, TrackedCol<B>, TrackedCol<B>)> {
        Self::prove_non_neg_u16_chunks_4(prover, col, |eval| {
            let n = Self::field_low_bits_unsigned(eval, 64) as u64;
            Self::split_u64_into_u16s(n)
        })
    }

    #[allow(clippy::complexity)]
    fn verify_non_neg_uint64(
        verifier: &mut ArgVerifier<B>,
        tracked_col_oracle: &TrackedColOracle<B>,
    ) -> SnarkResult<(
        TrackedColOracle<B>,
        TrackedColOracle<B>,
        TrackedColOracle<B>,
        TrackedColOracle<B>,
    )> {
        Self::verify_non_neg_u16_chunks_4(verifier, tracked_col_oracle)
    }

    #[allow(clippy::complexity)]
    fn prove_non_neg_int64(
        prover: &mut ArgProver<B>,
        col: &TrackedCol<B>,
    ) -> SnarkResult<(TrackedCol<B>, TrackedCol<B>, TrackedCol<B>, TrackedCol<B>)> {
        Self::prove_non_neg_u16_chunks_4(prover, col, |eval| {
            let n = Self::field_low_bits_signed(eval, 64) as i64;
            Self::split_i64_into_u16s(n)
        })
    }

    #[allow(clippy::complexity)]
    fn verify_non_neg_int64(
        verifier: &mut ArgVerifier<B>,
        tracked_col_oracle: &TrackedColOracle<B>,
    ) -> SnarkResult<(
        TrackedColOracle<B>,
        TrackedColOracle<B>,
        TrackedColOracle<B>,
        TrackedColOracle<B>,
    )> {
        Self::verify_non_neg_u16_chunks_4(verifier, tracked_col_oracle)
    }

    #[allow(clippy::complexity)]
    fn prove_non_neg_u16_chunks_4(
        prover: &mut ArgProver<B>,
        col: &TrackedCol<B>,
        mut eval_to_chunks: impl FnMut(B::F) -> [u16; 4],
    ) -> SnarkResult<(TrackedCol<B>, TrackedCol<B>, TrackedCol<B>, TrackedCol<B>)> {
        let evaluations = col.data_tracked_poly().evaluations();
        let log_size = col.log_size();
        let mut chunk3_vals = Vec::with_capacity(evaluations.len());
        let mut chunk2_vals = Vec::with_capacity(evaluations.len());
        let mut chunk1_vals = Vec::with_capacity(evaluations.len());
        let mut chunk0_vals = Vec::with_capacity(evaluations.len());

        for &eval in evaluations.iter() {
            let [chunk3, chunk2, chunk1, chunk0] = eval_to_chunks(eval);
            chunk3_vals.push(B::F::from(chunk3 as u64));
            chunk2_vals.push(B::F::from(chunk2 as u64));
            chunk1_vals.push(B::F::from(chunk1 as u64));
            chunk0_vals.push(B::F::from(chunk0 as u64));
        }

        let chunk3_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, chunk3_vals))?;
        let chunk2_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, chunk2_vals))?;
        let chunk1_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, chunk1_vals))?;
        let chunk0_poly = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, chunk0_vals))?;

        let recomposed = Self::recompose_tracked_polys(&[
            chunk3_poly.clone(),
            chunk2_poly.clone(),
            chunk1_poly.clone(),
            chunk0_poly.clone(),
        ]);

        let combined = &col.data_tracked_poly() - &recomposed;
        let zero_poly = match &col.activator_tracked_poly() {
            Some(activator) => &combined * activator,
            None => combined,
        };
        prover.add_mv_zerocheck_claim(zero_poly.id())?;

        let activator = col.activator_tracked_poly();
        let field_ref = col.field_ref().clone();

        Ok((
            TrackedCol::new(chunk3_poly, activator.clone(), field_ref.clone()),
            TrackedCol::new(chunk2_poly, activator.clone(), field_ref.clone()),
            TrackedCol::new(chunk1_poly, activator.clone(), field_ref.clone()),
            TrackedCol::new(chunk0_poly, activator, field_ref),
        ))
    }

    #[allow(clippy::complexity)]
    fn verify_non_neg_u16_chunks_4(
        verifier: &mut ArgVerifier<B>,
        tracked_col_oracle: &TrackedColOracle<B>,
    ) -> SnarkResult<(
        TrackedColOracle<B>,
        TrackedColOracle<B>,
        TrackedColOracle<B>,
        TrackedColOracle<B>,
    )> {
        let col_inner = tracked_col_oracle.data_tracked_oracle().clone();
        let col_activator = tracked_col_oracle.activator_tracked_oracle().clone();

        let chunk3_id = verifier.peek_next_id();
        let chunk3_poly = verifier.track_mv_com_by_id(chunk3_id)?;
        let chunk2_id = verifier.peek_next_id();
        let chunk2_poly = verifier.track_mv_com_by_id(chunk2_id)?;
        let chunk1_id = verifier.peek_next_id();
        let chunk1_poly = verifier.track_mv_com_by_id(chunk1_id)?;
        let chunk0_id = verifier.peek_next_id();
        let chunk0_poly = verifier.track_mv_com_by_id(chunk0_id)?;

        let recomposed = Self::recompose_tracked_oracles(&[
            chunk3_poly.clone(),
            chunk2_poly.clone(),
            chunk1_poly.clone(),
            chunk0_poly.clone(),
        ]);

        let combined = &col_inner - &recomposed;
        let zero_poly = match &col_activator {
            Some(activator) => &combined * activator,
            None => combined,
        };
        verifier.add_zerocheck_claim(zero_poly.id());

        let field_ref = tracked_col_oracle.field_ref().clone();

        Ok((
            TrackedColOracle::new(chunk3_poly, col_activator.clone(), field_ref.clone()),
            TrackedColOracle::new(chunk2_poly, col_activator.clone(), field_ref.clone()),
            TrackedColOracle::new(chunk1_poly, col_activator.clone(), field_ref.clone()),
            TrackedColOracle::new(chunk0_poly, col_activator, field_ref),
        ))
    }

    #[allow(clippy::complexity)]
    fn prove_non_neg_int128(
        prover: &mut ArgProver<B>,
        col: &TrackedCol<B>,
    ) -> SnarkResult<Vec<TrackedCol<B>>> {
        let evaluations = col.data_tracked_poly().evaluations();
        let log_size = col.log_size();
        let mut chunk_values: Vec<Vec<B::F>> = (0..8)
            .map(|_| Vec::with_capacity(evaluations.len()))
            .collect();

        for &eval in evaluations.iter() {
            let n = Self::field_low_bits_signed(eval, 128);
            for (target, chunk) in chunk_values
                .iter_mut()
                .zip(Self::split_i128_into_u16s(n).into_iter())
            {
                target.push(B::F::from(chunk as u64));
            }
        }

        let mut chunk_polys = Vec::with_capacity(8);
        for values in chunk_values {
            let poly = prover
                .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, values))?;
            chunk_polys.push(poly);
        }

        let recomposed = Self::recompose_tracked_polys(&chunk_polys);
        let combined = &col.data_tracked_poly() - &recomposed;
        let zero_poly = match &col.activator_tracked_poly() {
            Some(activator) => &combined * activator,
            None => combined,
        };
        prover.add_mv_zerocheck_claim(zero_poly.id())?;

        let activator = col.activator_tracked_poly();
        let field_ref = col.field_ref().clone();
        let tracked_cols = chunk_polys
            .into_iter()
            .map(|poly| TrackedCol::new(poly, activator.clone(), field_ref.clone()))
            .collect();

        Ok(tracked_cols)
    }

    #[allow(clippy::complexity)]
    fn verify_non_neg_int128(
        verifier: &mut ArgVerifier<B>,
        tracked_col_oracle: &TrackedColOracle<B>,
    ) -> SnarkResult<Vec<TrackedColOracle<B>>> {
        let col_inner = tracked_col_oracle.data_tracked_oracle().clone();
        let col_activator = tracked_col_oracle.activator_tracked_oracle().clone();

        let mut chunk_polys = Vec::with_capacity(8);
        for _ in 0..8 {
            let chunk_id = verifier.peek_next_id();
            let chunk_poly = verifier.track_mv_com_by_id(chunk_id)?;
            chunk_polys.push(chunk_poly);
        }

        let recomposed = Self::recompose_tracked_oracles(&chunk_polys);
        let combined = &col_inner - &recomposed;
        let zero_poly = match &col_activator {
            Some(activator) => &combined * activator,
            None => combined,
        };
        verifier.add_zerocheck_claim(zero_poly.id());

        let field_ref = tracked_col_oracle.field_ref().clone();
        let tracked_cols = chunk_polys
            .into_iter()
            .map(|poly| TrackedColOracle::new(poly, col_activator.clone(), field_ref.clone()))
            .collect();

        Ok(tracked_cols)
    }

    #[allow(clippy::complexity)]
    fn prove_non_neg_uint256(
        prover: &mut ArgProver<B>,
        col: &TrackedCol<B>,
    ) -> SnarkResult<Vec<TrackedCol<B>>> {
        let evaluations = col.data_tracked_poly().evaluations();
        let log_size = col.log_size();
        let mut chunk_values: Vec<Vec<B::F>> = (0..16)
            .map(|_| Vec::with_capacity(evaluations.len()))
            .collect();

        for &eval in evaluations.iter() {
            let chunks = Self::split_field_into_u16_limbs::<16>(eval);
            for (target, chunk) in chunk_values.iter_mut().zip(chunks.iter()) {
                target.push(B::F::from(*chunk as u64));
            }
        }

        let mut chunk_polys = Vec::with_capacity(16);
        for values in chunk_values {
            let poly = prover
                .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(log_size, values))?;
            chunk_polys.push(poly);
        }

        let recomposed = Self::recompose_tracked_polys(&chunk_polys);
        let combined = &col.data_tracked_poly() - &recomposed;
        let zero_poly = match &col.activator_tracked_poly() {
            Some(activator) => &combined * activator,
            None => combined,
        };
        prover.add_mv_zerocheck_claim(zero_poly.id())?;

        let activator = col.activator_tracked_poly();
        let field_ref = col.field_ref().clone();
        let tracked_cols = chunk_polys
            .into_iter()
            .map(|poly| TrackedCol::new(poly, activator.clone(), field_ref.clone()))
            .collect();

        Ok(tracked_cols)
    }

    #[allow(clippy::complexity)]
    fn verify_non_neg_uint256(
        verifier: &mut ArgVerifier<B>,
        tracked_col_oracle: &TrackedColOracle<B>,
    ) -> SnarkResult<Vec<TrackedColOracle<B>>> {
        let col_inner = tracked_col_oracle.data_tracked_oracle().clone();
        let col_activator = tracked_col_oracle.activator_tracked_oracle().clone();

        let mut chunk_polys = Vec::with_capacity(16);
        for _ in 0..16 {
            let chunk_id = verifier.peek_next_id();
            let chunk_poly = verifier.track_mv_com_by_id(chunk_id)?;
            chunk_polys.push(chunk_poly);
        }

        let recomposed = Self::recompose_tracked_oracles(&chunk_polys);
        let combined = &col_inner - &recomposed;
        let zero_poly = match &col_activator {
            Some(activator) => &combined * activator,
            None => combined,
        };
        verifier.add_zerocheck_claim(zero_poly.id());

        let field_ref = tracked_col_oracle.field_ref().clone();
        let tracked_cols = chunk_polys
            .into_iter()
            .map(|poly| TrackedColOracle::new(poly, col_activator.clone(), field_ref.clone()))
            .collect();

        Ok(tracked_cols)
    }

    fn recompose_tracked_polys(chunks: &[TrackedPoly<B>]) -> TrackedPoly<B> {
        debug_assert!(!chunks.is_empty());
        let base = B::F::from(1u64 << 16);
        let mut iter = chunks.iter();
        let mut acc = iter
            .next()
            .expect("chunked integer representation must be non-empty")
            .clone();
        for chunk in iter {
            let scaled = acc.clone() * base;
            acc = &scaled + chunk;
        }
        acc
    }

    fn recompose_tracked_oracles(chunks: &[TrackedOracle<B>]) -> TrackedOracle<B> {
        debug_assert!(!chunks.is_empty());
        let base = B::F::from(1u64 << 16);
        let mut iter = chunks.iter();
        let mut acc = iter
            .next()
            .expect("chunked integer representation must be non-empty")
            .clone();
        for chunk in iter {
            let scaled = acc.clone() * base;
            acc = &scaled + chunk;
        }
        acc
    }

    fn split_u32_into_u16s(n: u32) -> [u16; 4] {
        let chunk0 = (n & 0xFFFF) as u16;
        let chunk1 = ((n >> 16) & 0xFFFF) as u16;
        let chunk2 = 0u16;
        let chunk3 = 0u16;
        [chunk3, chunk2, chunk1, chunk0]
    }

    fn split_i32_into_u16s(n: i32) -> [u16; 4] {
        let bits = n as u32;
        let chunk0 = (bits & 0xFFFF) as u16;
        let chunk1 = ((bits >> 16) & 0xFFFF) as u16;
        let sign_extension = if n < 0 { 0xFFFF } else { 0 };
        [sign_extension, sign_extension, chunk1, chunk0]
    }

    fn split_u64_into_u16s(n: u64) -> [u16; 4] {
        let chunk0 = (n & 0xFFFF) as u16;
        let chunk1 = ((n >> 16) & 0xFFFF) as u16;
        let chunk2 = ((n >> 32) & 0xFFFF) as u16;
        let chunk3 = ((n >> 48) & 0xFFFF) as u16;
        [chunk3, chunk2, chunk1, chunk0]
    }

    fn split_i64_into_u16s(n: i64) -> [u16; 4] {
        let bits = n as u64;
        let chunk0 = (bits & 0xFFFF) as u16;
        let chunk1 = ((bits >> 16) & 0xFFFF) as u16;
        let chunk2 = ((bits >> 32) & 0xFFFF) as u16;
        let chunk3 = ((bits >> 48) & 0xFFFF) as u16;
        [chunk3, chunk2, chunk1, chunk0]
    }

    fn split_u128_into_u16s(n: u128) -> [u16; 8] {
        [
            ((n >> 112) & 0xFFFF) as u16,
            ((n >> 96) & 0xFFFF) as u16,
            ((n >> 80) & 0xFFFF) as u16,
            ((n >> 64) & 0xFFFF) as u16,
            ((n >> 48) & 0xFFFF) as u16,
            ((n >> 32) & 0xFFFF) as u16,
            ((n >> 16) & 0xFFFF) as u16,
            (n & 0xFFFF) as u16,
        ]
    }

    fn split_i128_into_u16s(n: i128) -> [u16; 8] {
        let bits = n as u128;
        Self::split_u128_into_u16s(bits)
    }

    fn split_field_into_u16_limbs<const N: usize>(value: B::F) -> [u16; N] {
        let bigint = value.into_bigint();
        let limbs = bigint.as_ref();
        let mut little_endian_chunks = Vec::with_capacity(N);
        let mut limb_index = 0usize;
        let mut shift = 0usize;

        while little_endian_chunks.len() < N {
            if limb_index >= limbs.len() {
                little_endian_chunks.push(0u16);
            } else {
                let limb = limbs[limb_index];
                let chunk = ((limb >> shift) & 0xFFFF) as u16;
                little_endian_chunks.push(chunk);
                shift += 16;
                if shift >= 64 {
                    shift -= 64;
                    limb_index += 1;
                }
            }
        }

        let mut big_endian_chunks = vec![0u16; N];
        for (idx, val) in little_endian_chunks.into_iter().enumerate() {
            big_endian_chunks[N - 1 - idx] = val;
        }
        big_endian_chunks
            .try_into()
            .expect("chunk count must match the specified output size")
    }

    fn field_low_bits_unsigned(value: B::F, bits: usize) -> u128 {
        debug_assert!(bits <= 128);
        if bits == 0 {
            return 0;
        }
        let bigint = value.into_bigint();
        let limbs = bigint.as_ref();
        let mut acc: u128 = 0;
        let mut shift = 0;
        let mut remaining = bits;
        for limb in limbs {
            if remaining == 0 {
                break;
            }
            let take = remaining.min(64);
            let mask = if take == 64 {
                u64::MAX
            } else {
                (1u64 << take) - 1
            };
            let part = (*limb & mask) as u128;
            acc |= part << shift;
            remaining -= take;
            shift += 64;
        }
        acc
    }

    fn field_low_bits_signed(value: B::F, bits: usize) -> i128 {
        debug_assert!(bits <= 128);
        if bits == 0 {
            return 0;
        }
        let unsigned = Self::field_low_bits_unsigned(value, bits);
        let sign_bit = 1u128 << (bits - 1);
        if unsigned & sign_bit != 0 {
            (unsigned as i128) - (1i128 << bits)
        } else {
            unsigned as i128
        }
    }

    // Interpret the field element using the column's bit-width/signing rules.
    fn eval_matches_sign(data_type: &DataType, sign: Sign, value: B::F) -> bool {
        match data_type {
            DataType::UInt8 => Self::eval_unsigned_sign(value, 8, sign),
            DataType::UInt16 => Self::eval_unsigned_sign(value, 16, sign),
            DataType::UInt32 => Self::eval_unsigned_sign(value, 32, sign),
            DataType::UInt64 => Self::eval_unsigned_sign(value, 64, sign),
            DataType::Int8 => Self::eval_signed_sign(value, 8, sign),
            DataType::Int16 => Self::eval_signed_sign(value, 16, sign),
            DataType::Int32 | DataType::Date32 => Self::eval_signed_sign(value, 32, sign),
            DataType::Int64 => Self::eval_signed_sign(value, 64, sign),
            DataType::Decimal128(..) => Self::eval_signed_sign(value, 128, sign),
            DataType::Utf8View => match sign {
                Sign::NonNegative => true,
                Sign::Positive => !value.is_zero(),
                Sign::NonPositive => value.is_zero(),
                Sign::Negative => false,
            },
            _ => false,
        }
    }

    fn eval_unsigned_sign(value: B::F, bits: usize, sign: Sign) -> bool {
        let val = Self::field_low_bits_unsigned(value, bits);
        match sign {
            Sign::NonNegative => true,
            Sign::Positive => val > 0,
            Sign::NonPositive => val == 0,
            Sign::Negative => false,
        }
    }

    fn eval_signed_sign(value: B::F, bits: usize, sign: Sign) -> bool {
        let val = Self::field_low_bits_signed(value, bits);
        match sign {
            Sign::NonNegative => val >= 0,
            Sign::Positive => val > 0,
            Sign::NonPositive => val <= 0,
            Sign::Negative => val < 0,
        }
    }

    fn eval_debug_values(data_type: &DataType, value: B::F) -> (Option<i128>, Option<u128>, Option<usize>) {
        match data_type {
            DataType::UInt8 => (None, Some(Self::field_low_bits_unsigned(value, 8)), Some(8)),
            DataType::UInt16 => (None, Some(Self::field_low_bits_unsigned(value, 16)), Some(16)),
            DataType::UInt32 => (None, Some(Self::field_low_bits_unsigned(value, 32)), Some(32)),
            DataType::UInt64 => (None, Some(Self::field_low_bits_unsigned(value, 64)), Some(64)),
            DataType::Int8 => (Some(Self::field_low_bits_signed(value, 8)), None, Some(8)),
            DataType::Int16 => (Some(Self::field_low_bits_signed(value, 16)), None, Some(16)),
            DataType::Int32 | DataType::Date32 => (Some(Self::field_low_bits_signed(value, 32)), None, Some(32)),
            DataType::Int64 => (Some(Self::field_low_bits_signed(value, 64)), None, Some(64)),
            DataType::Decimal128(..) => (Some(Self::field_low_bits_signed(value, 128)), None, Some(128)),
            DataType::Utf8View => (None, Some(Self::field_low_bits_unsigned(value, 128)), Some(128)),
            _ => (None, None, None),
        }
    }

}
