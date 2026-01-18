use std::sync::Arc;

use arithmetic::table::TrackedTable;
use arithmetic::table_oracle::TrackedTableOracle;
use ark_piop::arithmetic::mat_poly::mle::MLE;
use ark_piop::errors::{SnarkError, SnarkResult};
use ark_piop::test_utils::test_prelude;
use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use indexmap::IndexMap;

use super::{INPUT_LABEL, Sign, SignNode};
use crate::irs::nodes::Node;
use crate::irs::payloads::PayloadStructure;
use crate::irs::tree::Tree;
use crate::prover::passes::gadget_initialization::GadgetInitializationPass as ProverGadgetInitializationPass;
use crate::prover::passes::proving::ProvingPass;
use crate::prover::passes::virtualization::VirtualizationPass as ProverVirtualizationPass;
use crate::verifier::passes::gadget_initialization::GadgetInitializationPass as VerifierGadgetInitializationPass;
use crate::verifier::passes::verify::VerifyPass;
use crate::verifier::passes::virtualization::VirtualizationPass as VerifierVirtualizationPass;

type Backend = DefaultSnarkBackend;
const LOG_SIZE: usize = 2;

fn assert_soundness_error(err: SnarkError) {
    #[cfg(feature = "honest-prover")]
    {
        assert!(matches!(
            err,
            ark_piop::errors::SnarkError::ProverError(
                ark_piop::prover::errors::ProverError::HonestProverError(
                    ark_piop::prover::errors::HonestProverError::FalseClaim
                )
            )
        ));
    }

    #[cfg(not(feature = "honest-prover"))]
    {
        assert!(matches!(
            err,
            ark_piop::errors::SnarkError::VerifierError(
                ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(_)
            )
        ));
    }
}

trait IntoField {
    fn into_field<B: SnarkBackend>(self) -> B::F;
}

macro_rules! impl_into_field_signed {
    ($($t:ty),+ $(,)?) => {
        $(
            impl IntoField for $t {
                fn into_field<B: SnarkBackend>(self) -> B::F {
                    <B as SnarkBackend>::F::from(self as i64)
                }
            }
        )+
    };
}

macro_rules! impl_into_field_unsigned {
    ($($t:ty),+ $(,)?) => {
        $(
            impl IntoField for $t {
                fn into_field<B: SnarkBackend>(self) -> B::F {
                    <B as SnarkBackend>::F::from(self as u128)
                }
            }
        )+
    };
}

impl_into_field_signed!(i8, i16, i32, i64, isize);
impl_into_field_unsigned!(u8, u16, u32, u64, u128, usize);

impl IntoField for i128 {
    fn into_field<B: SnarkBackend>(self) -> B::F {
        if self >= i128::from(i64::MIN) && self <= i128::from(i64::MAX) {
            <B as SnarkBackend>::F::from(self as i64)
        } else if self < 0 {
            -<B as SnarkBackend>::F::from((-self) as u128)
        } else {
            <B as SnarkBackend>::F::from(self as u128)
        }
    }
}

fn evals_from_ints<T: IntoField + Copy>(evals: &[T]) -> Vec<<Backend as SnarkBackend>::F> {
    evals
        .iter()
        .map(|value| (*value).into_field::<Backend>())
        .collect()
}

fn run_sign_lookup_roundtrip(
    sign: Sign,
    data_type: DataType,
    evals: Vec<<Backend as SnarkBackend>::F>,
) -> SnarkResult<()> {
    run_sign_lookup_roundtrip_multi(vec![sign], vec![(data_type, evals)])
}

fn run_sign_lookup_roundtrip_multi(
    signs: Vec<Sign>,
    columns: Vec<(DataType, Vec<<Backend as SnarkBackend>::F>)>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<Backend>().unwrap();

    assert_eq!(
        signs.len(),
        columns.len(),
        "signs and columns must have matching lengths"
    );

    let mut tracked_polys = IndexMap::new();
    let mut tracked_poly_ids = Vec::with_capacity(columns.len());
    let mut fields = Vec::with_capacity(columns.len());
    for (idx, (data_type, evals)) in columns.into_iter().enumerate() {
        assert_eq!(
            evals.len(),
            1_usize << LOG_SIZE,
            "test evals must match LOG_SIZE"
        );
        let mle = MLE::from_evaluations_vec(LOG_SIZE, evals);
        let tracked_poly = prover.track_and_commit_mat_mv_poly(&mle).unwrap();
        tracked_poly_ids.push(tracked_poly.id());
        let field = Arc::new(Field::new(format!("input_{idx}"), data_type, false));
        tracked_polys.insert(field.clone(), tracked_poly);
        fields.push(field);
    }
    let schema = Schema::new(fields);
    let tracked_table = TrackedTable::new(Some(schema.clone()), tracked_polys, LOG_SIZE);

    let sign_node = Arc::new(SignNode::<Backend>::new(
        crate::irs::nodes::gadget::utils::sign::SignConfig::PerColumn(signs),
    ));
    let root = Arc::new(Node::Gadget(sign_node.clone()));
    let tree = Tree::new_from_root(root.clone());

    let gadget_payload = IndexMap::from([(INPUT_LABEL.to_string(), tracked_table)]);
    let mut prover_payloads = tree
        .arena()
        .keys()
        .map(|id| (*id, None))
        .collect::<IndexMap<_, _>>();
    prover_payloads.insert(
        root.id(),
        Some(PayloadStructure::GadgetPayload(gadget_payload)),
    );
    let tracked_ir = crate::prover::irs::TrackedIr::new(tree.clone(), prover_payloads);

    let virtualization_pass = ProverVirtualizationPass::<Backend>::new(&tracked_ir);
    let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);
    let gadget_ir_view = crate::prover::irs::VirtualizedIr::new(
        virtualized_ir.tree().clone(),
        virtualized_ir.payloads().clone(),
    );
    let gadget_initialization_pass = ProverGadgetInitializationPass::<Backend>::new(gadget_ir_view);
    let gadget_ready_ir = virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);

    let proving_ir_view = crate::prover::irs::GadgetReadyIr::new(
        gadget_ready_ir.tree().clone(),
        gadget_ready_ir.payloads().clone(),
    );
    let proving_pass = ProvingPass::<Backend>::new(prover.clone(), proving_ir_view);
    let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&proving_pass);
    proving_pass.take_result()?;

    let proof = prover.build_proof()?;
    verifier.set_proof(proof);

    let mut tracked_oracles = IndexMap::new();
    for (idx, tracked_poly_id) in tracked_poly_ids.into_iter().enumerate() {
        let tracked_oracle = verifier.track_mv_com_by_id(tracked_poly_id).unwrap();
        let field_ref = schema.fields()[idx].clone();
        tracked_oracles.insert(field_ref, tracked_oracle);
    }
    let table_oracle = TrackedTableOracle::new(Some(schema), tracked_oracles, LOG_SIZE);

    let gadget_payload = IndexMap::from([(INPUT_LABEL.to_string(), table_oracle)]);
    let mut verifier_payloads = tree
        .arena()
        .keys()
        .map(|id| (*id, None))
        .collect::<IndexMap<_, _>>();
    verifier_payloads.insert(
        root.id(),
        Some(PayloadStructure::GadgetPayload(gadget_payload)),
    );
    let tracked_ir = crate::verifier::irs::TrackedIr::new(tree, verifier_payloads);

    let virtualization_pass = VerifierVirtualizationPass::<Backend>::new(&tracked_ir);
    let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);
    let gadget_ir_view = crate::verifier::irs::VirtualizedIr::new(
        virtualized_ir.tree().clone(),
        virtualized_ir.payloads().clone(),
    );
    let gadget_initialization_pass =
        VerifierGadgetInitializationPass::<Backend>::new(gadget_ir_view);
    let gadget_ready_ir = virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);

    let verify_ir_view = crate::verifier::irs::GadgetReadyIr::new(
        gadget_ready_ir.tree().clone(),
        gadget_ready_ir.payloads().clone(),
    );
    let verify_pass = VerifyPass::<Backend>::new(verifier.clone(), verify_ir_view);
    let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&verify_pass);
    verify_pass.take_result()?;

    verifier.verify()?;
    Ok(())
}

#[test]
fn gadget_sign_completeness_nonnegative_uint8() {
    let evals = evals_from_ints(&[5_i64, 1, 2, 3]);
    run_sign_lookup_roundtrip(Sign::NonNegative, DataType::UInt8, evals).unwrap();
}
#[test]
fn gadget_sign_completeness_nonpositive_int8() {
    let evals = evals_from_ints(&[0_i64, -1, -2, 0]);
    run_sign_lookup_roundtrip(Sign::NonPositive, DataType::Int8, evals).unwrap();
}

#[test]
fn gadget_sign_completeness_positive_uint8() {
    let evals = evals_from_ints(&[1_i64, 2, 3, 4]);
    run_sign_lookup_roundtrip(Sign::Positive, DataType::UInt8, evals).unwrap();
}

#[test]
fn gadget_sign_completeness_negative_int8() {
    let evals = evals_from_ints(&[-1_i64, -2, -3, -4]);
    run_sign_lookup_roundtrip(Sign::Negative, DataType::Int8, evals).unwrap();
}

#[test]
fn gadget_sign_soundness_positive_uint8_rejects_zero() {
    let evals = evals_from_ints(&[1_i64, 0, 2, 3]);
    let err = run_sign_lookup_roundtrip(Sign::Positive, DataType::UInt8, evals).unwrap_err();
    assert_soundness_error(err);
}
#[test]
fn gadget_sign_soundness_nonnegative_int8_rejects_negative() {
    let evals = evals_from_ints(&[-1_i64, 0, 2, 3]);
    let err = run_sign_lookup_roundtrip(Sign::NonNegative, DataType::Int8, evals).unwrap_err();
    assert_soundness_error(err);
}

#[test]
fn gadget_sign_soundness_nonpositive_int8_rejects_positive() {
    let evals = evals_from_ints(&[-1_i64, 0, 2, -3]);
    let err = run_sign_lookup_roundtrip(Sign::NonPositive, DataType::Int8, evals).unwrap_err();
    assert_soundness_error(err);
}

#[test]
fn gadget_sign_soundness_negative_int8_rejects_zero() {
    let evals = evals_from_ints(&[-1_i64, -2, 0, -3]);
    let err = run_sign_lookup_roundtrip(Sign::Negative, DataType::Int8, evals).unwrap_err();
    assert_soundness_error(err);
}

#[test]
fn gadget_sign_completeness_nonnegative_uint16() {
    let evals = evals_from_ints(&[0_u16, 1, 2, 3]);
    run_sign_lookup_roundtrip(Sign::NonNegative, DataType::UInt16, evals).unwrap();
}

#[test]
fn gadget_sign_completeness_nonnegative_uint32() {
    let evals = evals_from_ints(&[0_u32, 1, 2, 3]);
    run_sign_lookup_roundtrip(Sign::NonNegative, DataType::UInt32, evals).unwrap();
}

#[test]
fn gadget_sign_completeness_nonnegative_uint64() {
    let evals = evals_from_ints(&[0_u64, 1, 2, 3]);
    run_sign_lookup_roundtrip(Sign::NonNegative, DataType::UInt64, evals).unwrap();
}

#[test]
fn gadget_sign_completeness_nonnegative_int16() {
    let evals = evals_from_ints(&[0_i16, 1, 2, 3]);
    run_sign_lookup_roundtrip(Sign::NonNegative, DataType::Int16, evals).unwrap();
}

#[test]
fn gadget_sign_completeness_nonnegative_int32() {
    let evals = evals_from_ints(&[0_i32, 1, 2, 3]);
    run_sign_lookup_roundtrip(Sign::NonNegative, DataType::Int32, evals).unwrap();
}

#[test]
fn gadget_sign_completeness_nonnegative_int64() {
    let evals = evals_from_ints(&[0_i64, 1, 2, 3]);
    run_sign_lookup_roundtrip(Sign::NonNegative, DataType::Int64, evals).unwrap();
}

#[test]
fn gadget_sign_completeness_nonnegative_uint256() {
    let evals = evals_from_ints(&[0_u128, 1, 2, 3]);
    run_sign_lookup_roundtrip(Sign::NonNegative, DataType::Utf8View, evals).unwrap();
}

#[test]
fn gadget_sign_soundness_positive_int128_rejects_zero() {
    let evals = evals_from_ints(&[1_i128, 0, 2, 3]);
    let err =
        run_sign_lookup_roundtrip(Sign::Positive, DataType::Decimal128(38, 0), evals).unwrap_err();
    assert_soundness_error(err);
}

#[test]
fn gadget_sign_soundness_nonnegative_int32_rejects_negative() {
    let evals = evals_from_ints(&[-1_i32, 0, 2, 3]);
    let err = run_sign_lookup_roundtrip(Sign::NonNegative, DataType::Int32, evals).unwrap_err();
    assert_soundness_error(err);
}

#[test]
fn gadget_sign_completeness_multi_column_mixed_signs() {
    let col0 = evals_from_ints(&[1_i64, 2, 3, 4]);
    let col1 = evals_from_ints(&[0_i64, -1, -2, 0]);
    run_sign_lookup_roundtrip_multi(
        vec![Sign::Positive, Sign::NonPositive],
        vec![(DataType::Int64, col0), (DataType::Int64, col1)],
    )
    .unwrap();
}
