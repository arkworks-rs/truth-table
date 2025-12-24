use std::marker::PhantomData;

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::{One, Zero};
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::SnarkResult,
    prover::ArgProver,
    verifier::{ArgVerifier, structs::oracle::Oracle},
};
use col_toolbox::sign_check::SignCheckPIOP;
use datafusion::arrow::datatypes::DataType;
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub const INPUT_LABEL: &str = "input";
#[cfg(test)]
mod tests;
pub enum Sign {
    NonNegative,
    Negative,
    NonPositive,
    Positive,
}
pub struct SignNode<B: SnarkBackend> {
    sign: Sign,
    phantom: PhantomData<B>,
}

impl<B: SnarkBackend> IsNode<B> for SignNode<B> {
    fn name(&self) -> String {
        "Sign".to_string()
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![]
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
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
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
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
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
        // The input should have exactly one data tracked polynomial.
        debug_assert_eq!(
            input.data_tracked_polys_indices().len(),
            1,
            "Sign gadget supports one tracked polynomial per input."
        );
        // Extract the indices corresponding to the input data tracked polynomial.
        let data_ind = input.data_tracked_polys_indices()[0];
        // Fetch the tracked columns corresponding to those indices
        let input_col = input.tracked_col_by_ind(data_ind);
        match self.sign {
            Sign::NonNegative => Self::prove_sign_inner(prover, &input_col, Sign::NonNegative),
            Sign::NonPositive => {
                let negated_col = Self::negated_col(&input_col);
                Self::prove_sign_inner(prover, &negated_col, Sign::NonNegative)
            }
            Sign::Positive => {
                Self::prove_sign_inner(prover, &input_col, Sign::Positive)?;
                Ok(())
            }
            Sign::Negative => {
                let negated_col = Self::negated_col(&input_col);
                Self::prove_sign_inner(prover, &negated_col, Sign::Positive)?;
                Ok(())
            }
        }
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
        // The input should have exactly one data tracked oracle.
        debug_assert_eq!(
            input.data_tracked_oracles_indices().len(),
            1,
            "Sign gadget supports one tracked oracle per input."
        );
        // Extract the indices corresponding to the input data tracked oracle.
        let data_ind = input.data_tracked_oracles_indices()[0];
        // Fetch the tracked column oracle corresponding to that index.
        let input_col = input.tracked_col_oracle_by_ind(data_ind);
        match self.sign {
            Sign::NonNegative => Self::verify_sign_inner(verifier, &input_col, Sign::NonNegative),
            Sign::NonPositive => {
                let negated_col = Self::negated_col_oracle(&input_col);
                Self::verify_sign_inner(verifier, &negated_col, Sign::NonNegative)
            }
            Sign::Positive => Self::verify_sign_inner(verifier, &input_col, Sign::Positive),
            Sign::Negative => {
                let negated_col = Self::negated_col_oracle(&input_col);
                Self::verify_sign_inner(verifier, &negated_col, Sign::Positive)
            }
        }
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> SignNode<B> {
    pub fn new(sign: Sign) -> Self {
        Self {
            sign,
            phantom: PhantomData,
        }
    }

    fn dense_range_poly_by_nv(nv: usize, has_zero: bool) -> MLE<B::F> {
        let mut evals = (0..2_usize.pow(nv as u32))
            .map(|x| B::F::from(x as u64))
            .collect::<Vec<_>>();
        if !has_zero {
            evals[0] = B::F::one();
        }
        MLE::from_evaluations_vec(nv, evals)
    }

    fn add_range_lookup(
        prover: &mut ArgProver<B>,
        col: &TrackedCol<B>,
        nv: usize,
        has_zero: bool,
    ) -> SnarkResult<()> {
        let range_poly = prover.track_mat_mv_poly(Self::dense_range_poly_by_nv(nv, has_zero));
        let activated_poly = col.activated_data_tracked_poly();
        prover.add_mv_lookup_claim(range_poly.id(), activated_poly.id())
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

    fn range_oracle(nv: usize, has_zero: bool) -> Oracle<B::F> {
        Oracle::new_multivariate(nv, move |x| {
            let mut acc = B::F::zero();
            for (i, value) in x.iter().enumerate() {
                acc += *value * B::F::from(1u64 << i);
            }
            if !has_zero {
                let mut acc_eq_zero = B::F::one();
                for value in x.iter() {
                    acc_eq_zero *= B::F::one() - *value;
                }
                acc += acc_eq_zero;
            }
            Ok(acc)
        })
    }

    fn add_range_lookup_oracle(
        verifier: &mut ArgVerifier<B>,
        col: &TrackedColOracle<B>,
        nv: usize,
        has_zero: bool,
    ) -> SnarkResult<()> {
        let range_oracle = verifier.track_oracle(Self::range_oracle(nv, has_zero));
        let activated_oracle = col.activated_data_tracked_oracle();
        verifier.add_mv_lookup_claim(range_oracle.id(), activated_oracle.id())
    }

    fn prove_sign_inner(
        prover: &mut ArgProver<B>,
        col: &TrackedCol<B>,
        sign: Sign,
    ) -> SnarkResult<()> {
        let has_zero = match sign {
            Sign::NonNegative => true,
            Sign::Positive => false,
            _ => unreachable!(),
        };
        let field_ref = col.field_ref().expect("Expected field ref for Sign gadget");
        let data_type = field_ref.data_type();
        match data_type {
            DataType::UInt8 => {
                Self::add_range_lookup(prover, col, 8, has_zero)?;
            }
            DataType::Int8 => {
                Self::add_range_lookup(prover, col, 7, has_zero)?;
            }
            DataType::UInt16 => {
                Self::add_range_lookup(prover, col, 16, has_zero)?;
            }
            DataType::Int16 => {
                Self::add_range_lookup(prover, col, 15, has_zero)?;
            }
            DataType::UInt32 => {
                let (chunk3, chunk2, chunk1, chunk0) =
                    SignCheckPIOP::<B>::prove_non_neg_uint32(prover, col)?;
                for segment in [chunk3, chunk2, chunk1, chunk0] {
                    Self::add_range_lookup(prover, &segment, 16, has_zero)?;
                }
            }
            DataType::Int32 | DataType::Date32 => {
                let (chunk3, chunk2, chunk1, chunk0) =
                    SignCheckPIOP::<B>::prove_non_neg_int32(prover, col)?;
                Self::add_range_lookup(prover, &chunk3, 15, has_zero)?;
                for segment in [chunk2, chunk1, chunk0] {
                    Self::add_range_lookup(prover, &segment, 16, has_zero)?;
                }
            }
            DataType::UInt64 => {
                let (chunk3, chunk2, chunk1, chunk0) =
                    SignCheckPIOP::<B>::prove_non_neg_uint64(prover, col)?;
                for segment in [chunk3, chunk2, chunk1, chunk0] {
                    Self::add_range_lookup(prover, &segment, 16, has_zero)?;
                }
            }
            DataType::Int64 => {
                let (chunk3, chunk2, chunk1, chunk0) =
                    SignCheckPIOP::<B>::prove_non_neg_int64(prover, col)?;
                Self::add_range_lookup(prover, &chunk3, 15, has_zero)?;
                for segment in [chunk2, chunk1, chunk0] {
                    Self::add_range_lookup(prover, &segment, 16, has_zero)?;
                }
            }
            DataType::Decimal128(..) => {
                let chunks = SignCheckPIOP::<B>::prove_non_neg_int128(prover, col)?;
                let (top, rest) = chunks
                    .split_first()
                    .expect("chunked integer representation must be non-empty");
                Self::add_range_lookup(prover, top, 15, has_zero)?;
                for segment in rest {
                    Self::add_range_lookup(prover, segment, 16, has_zero)?;
                }
            }
            DataType::Utf8View => {
                let segments = SignCheckPIOP::<B>::prove_non_neg_uint256(prover, col)?;
                for segment in segments {
                    Self::add_range_lookup(prover, &segment, 16, has_zero)?;
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
        sign: Sign,
    ) -> SnarkResult<()> {
        let has_zero = match sign {
            Sign::NonNegative => true,
            Sign::Positive => false,
            _ => unreachable!(),
        };
        let field_ref = col.field_ref().expect("Expected field ref for Sign gadget");
        let data_type = field_ref.data_type();
        match data_type {
            DataType::UInt8 => {
                Self::add_range_lookup_oracle(verifier, col, 8, has_zero)?;
            }
            DataType::Int8 => {
                Self::add_range_lookup_oracle(verifier, col, 7, has_zero)?;
            }
            DataType::UInt16 => {
                Self::add_range_lookup_oracle(verifier, col, 16, has_zero)?;
            }
            DataType::Int16 => {
                Self::add_range_lookup_oracle(verifier, col, 15, has_zero)?;
            }
            DataType::UInt32 => {
                let (chunk3, chunk2, chunk1, chunk0) =
                    SignCheckPIOP::<B>::verify_non_neg_uint32(verifier, col)?;
                for segment in [chunk3, chunk2, chunk1, chunk0] {
                    Self::add_range_lookup_oracle(verifier, &segment, 16, has_zero)?;
                }
            }
            DataType::Int32 | DataType::Date32 => {
                let (chunk3, chunk2, chunk1, chunk0) =
                    SignCheckPIOP::<B>::verify_non_neg_int32(verifier, col)?;
                Self::add_range_lookup_oracle(verifier, &chunk3, 15, has_zero)?;
                for segment in [chunk2, chunk1, chunk0] {
                    Self::add_range_lookup_oracle(verifier, &segment, 16, has_zero)?;
                }
            }
            DataType::UInt64 => {
                let (chunk3, chunk2, chunk1, chunk0) =
                    SignCheckPIOP::<B>::verify_non_neg_uint64(verifier, col)?;
                for segment in [chunk3, chunk2, chunk1, chunk0] {
                    Self::add_range_lookup_oracle(verifier, &segment, 16, has_zero)?;
                }
            }
            DataType::Int64 => {
                let (chunk3, chunk2, chunk1, chunk0) =
                    SignCheckPIOP::<B>::verify_non_neg_int64(verifier, col)?;
                Self::add_range_lookup_oracle(verifier, &chunk3, 15, has_zero)?;
                for segment in [chunk2, chunk1, chunk0] {
                    Self::add_range_lookup_oracle(verifier, &segment, 16, has_zero)?;
                }
            }
            DataType::Decimal128(..) => {
                let (top, rest) = SignCheckPIOP::<B>::verify_non_neg_int128(verifier, col)?;
                Self::add_range_lookup_oracle(verifier, &top, 15, has_zero)?;
                for segment in rest {
                    Self::add_range_lookup_oracle(verifier, &segment, 16, has_zero)?;
                }
            }
            DataType::Utf8View => {
                let segments = SignCheckPIOP::<B>::verify_non_neg_uint256(verifier, col)?;
                for segment in segments {
                    Self::add_range_lookup_oracle(verifier, &segment, 16, has_zero)?;
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
}
