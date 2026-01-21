use super::*;
use std::sync::Arc;

use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_piop::arithmetic::mat_poly::mle::MLE;
use ark_piop::errors::{SnarkError, SnarkResult};
use ark_piop::prover::ArgProver;
use ark_piop::prover::structs::polynomial::TrackedPoly;
use ark_piop::test_utils::test_prelude;
use ark_piop::{DefaultSnarkBackend, SnarkBackend};
use datafusion::arrow::datatypes::{DataType, Field};
use indexmap::IndexMap;

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
                    if self < 0 {
                        -<B as SnarkBackend>::F::from((-self) as u128)
                    } else {
                        <B as SnarkBackend>::F::from(self as u128)
                    }
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

impl_into_field_signed!(i8, i16, i32, i64, i128, isize);
impl_into_field_unsigned!(u8, u16, u32, u64, u128, usize);

fn evals_from_ints<T: IntoField + Copy>(evals: &[T]) -> Vec<<Backend as SnarkBackend>::F> {
    evals
        .iter()
        .map(|value| (*value).into_field::<Backend>())
        .collect()
}

fn tracked_poly_from_evals(
    prover: &mut ArgProver<Backend>,
    evals: Vec<<Backend as SnarkBackend>::F>,
) -> TrackedPoly<Backend> {
    let mle = MLE::from_evaluations_vec(LOG_SIZE, evals);
    prover.track_and_commit_mat_mv_poly(&mle).unwrap()
}

struct BinCmpCase<T> {
    left: [T; 4],
    right: RightInput<T>,
    output: [T; 4],
    activator: Option<[T; 4]>,
}

enum RightInput<T> {
    Column([T; 4]),
    Literal(T),
}

fn bin_cmp_case<T>(
    left: [T; 4],
    right: RightInput<T>,
    output: [T; 4],
    activator: Option<[T; 4]>,
) -> BinCmpCase<T> {
    BinCmpCase {
        left,
        right,
        output,
        activator,
    }
}

fn right_col<T>(values: [T; 4]) -> RightInput<T> {
    RightInput::Column(values)
}

fn right_lit<T>(value: T) -> RightInput<T> {
    RightInput::Literal(value)
}

fn expand_right<T: Copy>(right: &RightInput<T>) -> [T; 4] {
    match right {
        RightInput::Column(values) => *values,
        RightInput::Literal(value) => [*value; 4],
    }
}

fn end_to_end_bin_geq_prove_and_verify<T: IntoField + Copy>(
    data_type: DataType,
    left: &[T],
    right: &[T],
    output: &[T],
    activator: Option<&[T]>,
) -> SnarkResult<()> {
    // Keep the test vectors consistent with the log size of this gadget (2^LOG_SIZE rows).
    let expected_len = 1 << LOG_SIZE;
    debug_assert_eq!(left.len(), expected_len);
    debug_assert_eq!(right.len(), expected_len);
    debug_assert_eq!(output.len(), expected_len);
    if let Some(activator) = activator {
        debug_assert_eq!(activator.len(), expected_len);
    }

    // Set up a fresh prover/verifier pair with shared transcript parameters.
    let (mut prover, mut verifier) = test_prelude::<Backend>().unwrap();

    // Commit prover polynomials for the left/right operands, output bit, and shared activator.
    let left_poly = tracked_poly_from_evals(&mut prover, evals_from_ints(left));
    let right_poly = tracked_poly_from_evals(&mut prover, evals_from_ints(right));
    let output_poly = tracked_poly_from_evals(&mut prover, evals_from_ints(output));
    let shared_activator =
        activator.map(|activator| tracked_poly_from_evals(&mut prover, evals_from_ints(activator)));

    // Wrap each tracked polynomial as a single-column tracked table with the same activator.
    let left_table = TrackedTable::single_column_with_activator(
        Arc::new(Field::new("left", data_type.clone(), false)),
        left_poly.clone(),
        shared_activator.clone(),
    );
    let right_table = TrackedTable::single_column_with_activator(
        Arc::new(Field::new("right", data_type.clone(), false)),
        right_poly.clone(),
        shared_activator.clone(),
    );
    let output_table = TrackedTable::single_column_with_activator(
        Arc::new(Field::new("output", data_type.clone(), false)),
        output_poly.clone(),
        shared_activator.clone(),
    );

    // Build a BinCmp gadget node and a minimal tree with that gadget as the root.
    let bin_node = Arc::new(BinCmpNode::<Backend>::geq());
    let root = Arc::new(Node::Gadget(bin_node.clone()));
    let tree = Tree::new_from_root(root.clone());

    // Seed the prover IR with payloads for every node so virtualization doesn't miss IDs.
    let gadget_payload = IndexMap::from([
        (LEFT_INPUT_LABEL.to_string(), left_table.clone()),
        (RIGHT_INPUT_LABEL.to_string(), right_table.clone()),
        (OUTPUT_LABEL.to_string(), output_table.clone()),
    ]);
    let mut payloads = tree
        .arena()
        .keys()
        .map(|id| (*id, None))
        .collect::<IndexMap<_, _>>();
    payloads.insert(
        root.id(),
        Some(PayloadStructure::GadgetPayload(gadget_payload)),
    );
    let tracked_ir = crate::prover::irs::TrackedIr::new(tree.clone(), payloads);

    // Run the virtualization pass so the gadget can inject any virtual witnesses.
    let virtualization_pass = ProverVirtualizationPass::<Backend>::new(&tracked_ir);
    let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);

    // Run gadget initialization to produce the child sign gadget payloads.
    let gadget_ir_view = crate::prover::irs::VirtualizedIr::new(
        virtualized_ir.tree().clone(),
        virtualized_ir.payloads().clone(),
    );
    let gadget_initialization_pass =
        ProverGadgetInitializationPass::<Backend>::new(gadget_ir_view, prover.clone());
    let gadget_ready_ir = virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);

    // Run the proving pass to invoke every gadget in post-order.
    let proving_ir_view = crate::prover::irs::GadgetReadyIr::new(
        gadget_ready_ir.tree().clone(),
        gadget_ready_ir.payloads().clone(),
    );
    let proving_pass = ProvingPass::<Backend>::new(prover.clone(), proving_ir_view);
    let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&proving_pass);
    proving_pass.take_result()?;

    // Finalize the prover transcript into a proof that the verifier can consume.
    let proof = prover.build_proof()?;

    // Move the proof into the verifier transcript state.
    verifier.set_proof(proof);

    // Track commitments in a deterministic order to keep tracker IDs aligned.
    let mut tracked_ids = vec![left_poly.id(), right_poly.id(), output_poly.id()];
    if let Some(shared_activator) = &shared_activator {
        tracked_ids.push(shared_activator.id());
    }
    tracked_ids.sort();
    let mut oracle_by_id = IndexMap::new();
    for id in tracked_ids {
        oracle_by_id.insert(id, verifier.track_mv_com_by_id(id)?);
    }

    // Extract tracked oracles for each input column.
    let left_oracle = oracle_by_id[&left_poly.id()].clone();
    let right_oracle = oracle_by_id[&right_poly.id()].clone();
    let output_oracle = oracle_by_id[&output_poly.id()].clone();
    let activator_oracle = shared_activator
        .as_ref()
        .map(|shared_activator| oracle_by_id[&shared_activator.id()].clone());

    // Build the verifier payloads that mirror the prover's tracked tables.
    let mut verifier_payloads = tree
        .arena()
        .keys()
        .map(|id| (*id, None))
        .collect::<IndexMap<_, _>>();
    verifier_payloads.insert(
        root.id(),
        Some(PayloadStructure::GadgetPayload(IndexMap::from([
            (
                LEFT_INPUT_LABEL.to_string(),
                TrackedTableOracle::single_column_with_activator(
                    Arc::new(Field::new("left", data_type.clone(), false)),
                    left_oracle,
                    activator_oracle.clone(),
                ),
            ),
            (
                RIGHT_INPUT_LABEL.to_string(),
                TrackedTableOracle::single_column_with_activator(
                    Arc::new(Field::new("right", data_type.clone(), false)),
                    right_oracle,
                    activator_oracle.clone(),
                ),
            ),
            (
                OUTPUT_LABEL.to_string(),
                TrackedTableOracle::single_column_with_activator(
                    Arc::new(Field::new("output", data_type, false)),
                    output_oracle,
                    activator_oracle,
                ),
            ),
        ]))),
    );

    // Re-run virtualization and gadget initialization on the verifier side.
    let tracked_ir = crate::verifier::irs::TrackedIr::new(tree, verifier_payloads);
    let virtualization_pass = VerifierVirtualizationPass::<Backend>::new(&tracked_ir);
    let virtualized_ir = tracked_ir.apply_local_pass_sequential(&virtualization_pass);
    let gadget_ir_view = crate::verifier::irs::VirtualizedIr::new(
        virtualized_ir.tree().clone(),
        virtualized_ir.payloads().clone(),
    );
    let gadget_initialization_pass =
        VerifierGadgetInitializationPass::<Backend>::new(gadget_ir_view, verifier.clone());
    let gadget_ready_ir = virtualized_ir.apply_local_pass_sequential(&gadget_initialization_pass);

    // Run the verifier pass to invoke every gadget against the proof transcript.
    let verify_ir_view = crate::verifier::irs::GadgetReadyIr::new(
        gadget_ready_ir.tree().clone(),
        gadget_ready_ir.payloads().clone(),
    );
    let verify_pass = VerifyPass::<Backend>::new(verifier.clone(), verify_ir_view);
    let _final_ir = gadget_ready_ir.apply_local_pass_sequential(&verify_pass);
    verify_pass.take_result()?;

    // Run the global verifier checks to finish the roundtrip.
    verifier.verify()?;
    Ok(())
}

fn run_bin_cmp_completeness_cases<T: IntoField + Copy>(
    data_type: DataType,
    cases: &[BinCmpCase<T>],
) {
    for case in cases {
        let activator = case.activator.as_ref().map(|values| &values[..]);
        let right_vals = expand_right(&case.right);
        end_to_end_bin_geq_prove_and_verify(
            data_type.clone(),
            &case.left,
            &right_vals,
            &case.output,
            activator,
        )
        .unwrap();
    }
}

fn run_bin_cmp_soundness_cases<T: IntoField + Copy>(data_type: DataType, cases: &[BinCmpCase<T>]) {
    for case in cases {
        let activator = case.activator.as_ref().map(|values| &values[..]);
        let right_vals = expand_right(&case.right);
        let err = end_to_end_bin_geq_prove_and_verify(
            data_type.clone(),
            &case.left,
            &right_vals,
            &case.output,
            activator,
        )
        .unwrap_err();
        assert_soundness_error(err);
    }
}

#[test]
fn gadget_bin_cmp_completeness_uint8() {
    let cases: [BinCmpCase<u8>; 4] = [
        bin_cmp_case(
            [20_u8, 3, 4, 5],
            right_col([20_u8, 4, 3, 6]),
            [1_u8, 0, 1, 0],
            None,
        ),
        bin_cmp_case(
            [0_u8, 5, 2, 7],
            right_col([1_u8, 4, 3, 6]),
            [0_u8, 1, 0, 1],
            None,
        ),
        bin_cmp_case(
            [0_u8, 5, 2, 7],
            right_col([1_u8, 4, 3, 6]),
            [0_u8, 1, 0, 1],
            Some([0_u8, 1, 1, 1]),
        ),
        bin_cmp_case(
            [0_u8, 5, 2, 7],
            right_lit(2_u8),
            [0_u8, 1, 1, 0],
            Some([0_u8, 1, 1, 0]),
        ),
    ];
    run_bin_cmp_completeness_cases(DataType::UInt8, &cases);
}

#[test]
fn gadget_bin_cmp_soundness_uint8() {
    let cases: [BinCmpCase<u8>; 3] = [
        bin_cmp_case(
            [1_u8, 2, 3, 4],
            right_col([0_u8, 3, 3, 5]),
            [1_u8, 1, 1, 0],
            None,
        ),
        bin_cmp_case(
            [4_u8, 2, 1, 0],
            right_col([4_u8, 1, 2, 0]),
            [0_u8, 1, 0, 1],
            None,
        ),
        bin_cmp_case(
            [2_u8, 5, 1, 7],
            right_lit(2_u8),
            [0_u8, 0, 1, 1],
            Some([1_u8, 0, 1, 0]),
        ),
    ];
    run_bin_cmp_soundness_cases(DataType::UInt8, &cases);
}

#[test]
fn gadget_bin_cmp_completeness_int8() {
    let cases: [BinCmpCase<i8>; 3] = [
        bin_cmp_case(
            [20_i8, -3, -4, -5],
            right_col([20_i8, 2, 3, 4]),
            [1_i8, 0, 0, 0],
            None,
        ),
        bin_cmp_case(
            [0_i8, 5, -2, -7],
            right_col([-1_i8, 4, -1, -6]),
            [1_i8, 1, 0, 0],
            None,
        ),
        bin_cmp_case(
            [2_i8, 5, 1, 7],
            right_lit(2_i8),
            [1_i8, 1, 0, 1],
            Some([1_i8, 0, 1, 0]),
        ),
    ];
    run_bin_cmp_completeness_cases(DataType::Int8, &cases);
}

#[test]
fn gadget_bin_cmp_soundness_int8() {
    let cases: [BinCmpCase<i8>; 3] = [
        bin_cmp_case(
            [1_i8, 2, 3, 4],
            right_col([0_i8, 3, 3, 5]),
            [1_i8, 1, 1, 0],
            None,
        ),
        bin_cmp_case(
            [4_i8, 2, 1, 0],
            right_col([4_i8, 1, 2, 0]),
            [0_i8, 1, 0, 1],
            None,
        ),
        bin_cmp_case(
            [2_i8, 5, 1, 7],
            right_lit(2_i8),
            [0_i8, 0, 1, 1],
            Some([1_i8, 0, 1, 0]),
        ),
    ];
    run_bin_cmp_soundness_cases(DataType::Int8, &cases);
}

#[test]
fn gadget_bin_cmp_completeness_uint16() {
    let cases: [BinCmpCase<u16>; 3] = [
        bin_cmp_case(
            [20_u16, 3, 4, 5],
            right_col([20_u16, 4, 3, 6]),
            [1_u16, 0, 1, 0],
            None,
        ),
        bin_cmp_case(
            [0_u16, 5, 2, 7],
            right_col([1_u16, 4, 3, 6]),
            [0_u16, 1, 0, 1],
            None,
        ),
        bin_cmp_case(
            [2_u16, 5, 1, 7],
            right_lit(2_u16),
            [1_u16, 1, 0, 1],
            Some([1_u16, 0, 1, 0]),
        ),
    ];
    run_bin_cmp_completeness_cases(DataType::UInt16, &cases);
}

#[test]
fn gadget_bin_cmp_soundness_uint16() {
    let cases: [BinCmpCase<u16>; 3] = [
        bin_cmp_case(
            [1_u16, 2, 3, 4],
            right_col([0_u16, 3, 3, 5]),
            [1_u16, 1, 1, 0],
            None,
        ),
        bin_cmp_case(
            [4_u16, 2, 1, 0],
            right_col([4_u16, 1, 2, 0]),
            [0_u16, 1, 0, 1],
            None,
        ),
        bin_cmp_case(
            [2_u16, 5, 1, 7],
            right_lit(2_u16),
            [0_u16, 0, 1, 1],
            Some([1_u16, 0, 1, 0]),
        ),
    ];
    run_bin_cmp_soundness_cases(DataType::UInt16, &cases);
}

#[test]
fn gadget_bin_cmp_completeness_int16() {
    let cases: [BinCmpCase<i16>; 3] = [
        bin_cmp_case(
            [20_i16, -3, -4, -5],
            right_col([20_i16, 2, 3, 4]),
            [1_i16, 0, 0, 0],
            None,
        ),
        bin_cmp_case(
            [0_i16, 5, -2, -7],
            right_col([-1_i16, 4, -1, -6]),
            [1_i16, 1, 0, 0],
            None,
        ),
        bin_cmp_case(
            [2_i16, 5, 1, 7],
            right_lit(2_i16),
            [1_i16, 1, 0, 1],
            Some([1_i16, 0, 1, 0]),
        ),
    ];
    run_bin_cmp_completeness_cases(DataType::Int16, &cases);
}

#[test]
fn gadget_bin_cmp_soundness_int16() {
    let cases: [BinCmpCase<i16>; 3] = [
        bin_cmp_case(
            [1_i16, 2, 3, 4],
            right_col([0_i16, 3, 3, 5]),
            [1_i16, 1, 1, 0],
            None,
        ),
        bin_cmp_case(
            [4_i16, 2, 1, 0],
            right_col([4_i16, 1, 2, 0]),
            [0_i16, 1, 0, 1],
            None,
        ),
        bin_cmp_case(
            [2_i16, 5, 1, 7],
            right_lit(2_i16),
            [0_i16, 0, 1, 1],
            Some([1_i16, 0, 1, 0]),
        ),
    ];
    run_bin_cmp_soundness_cases(DataType::Int16, &cases);
}

#[test]
fn gadget_bin_cmp_completeness_uint32() {
    let cases: [BinCmpCase<u32>; 3] = [
        bin_cmp_case(
            [20_u32, 3, 4, 5],
            right_col([20_u32, 4, 3, 6]),
            [1_u32, 0, 1, 0],
            None,
        ),
        bin_cmp_case(
            [0_u32, 5, 2, 7],
            right_col([1_u32, 4, 3, 6]),
            [0_u32, 1, 0, 1],
            None,
        ),
        bin_cmp_case(
            [2_u32, 5, 1, 7],
            right_lit(2_u32),
            [1_u32, 1, 0, 1],
            Some([1_u32, 0, 1, 0]),
        ),
    ];
    run_bin_cmp_completeness_cases(DataType::UInt32, &cases);
}

#[test]
fn gadget_bin_cmp_soundness_uint32() {
    let cases: [BinCmpCase<u32>; 3] = [
        bin_cmp_case(
            [1_u32, 2, 3, 4],
            right_col([0_u32, 3, 3, 5]),
            [1_u32, 1, 1, 0],
            None,
        ),
        bin_cmp_case(
            [4_u32, 2, 1, 0],
            right_col([4_u32, 1, 2, 0]),
            [0_u32, 1, 0, 1],
            None,
        ),
        bin_cmp_case(
            [2_u32, 5, 1, 7],
            right_lit(2_u32),
            [0_u32, 0, 1, 1],
            Some([1_u32, 0, 1, 0]),
        ),
    ];
    run_bin_cmp_soundness_cases(DataType::UInt32, &cases);
}

#[test]
fn gadget_bin_cmp_completeness_int32() {
    let cases: [BinCmpCase<i32>; 3] = [
        bin_cmp_case(
            [20_i32, -3, -4, -5],
            right_col([20_i32, 2, 3, 4]),
            [1_i32, 0, 0, 0],
            None,
        ),
        bin_cmp_case(
            [0_i32, 5, -2, -7],
            right_col([-1_i32, 4, -1, -6]),
            [1_i32, 1, 0, 0],
            None,
        ),
        bin_cmp_case(
            [2_i32, 5, 1, 7],
            right_lit(2_i32),
            [1_i32, 1, 0, 1],
            Some([1_i32, 0, 1, 0]),
        ),
    ];
    run_bin_cmp_completeness_cases(DataType::Int32, &cases);
}

#[test]
fn gadget_bin_cmp_soundness_int32() {
    let cases: [BinCmpCase<i32>; 3] = [
        bin_cmp_case(
            [1_i32, 2, 3, 4],
            right_col([0_i32, 3, 3, 5]),
            [1_i32, 1, 1, 0],
            None,
        ),
        bin_cmp_case(
            [4_i32, 2, 1, 0],
            right_col([4_i32, 1, 2, 0]),
            [0_i32, 1, 0, 1],
            None,
        ),
        bin_cmp_case(
            [2_i32, 5, 1, 7],
            right_lit(2_i32),
            [0_i32, 0, 1, 1],
            Some([1_i32, 0, 1, 0]),
        ),
    ];
    run_bin_cmp_soundness_cases(DataType::Int32, &cases);
}

#[test]
fn gadget_bin_cmp_completeness_uint64() {
    let cases: [BinCmpCase<u64>; 3] = [
        bin_cmp_case(
            [20_u64, 3, 4, 5],
            right_col([20_u64, 4, 3, 6]),
            [1_u64, 0, 1, 0],
            None,
        ),
        bin_cmp_case(
            [0_u64, 5, 2, 7],
            right_col([1_u64, 4, 3, 6]),
            [0_u64, 1, 0, 1],
            None,
        ),
        bin_cmp_case(
            [2_u64, 5, 1, 7],
            right_lit(2_u64),
            [1_u64, 1, 0, 1],
            Some([1_u64, 0, 1, 0]),
        ),
    ];
    run_bin_cmp_completeness_cases(DataType::UInt64, &cases);
}

#[test]
fn gadget_bin_cmp_soundness_uint64() {
    let cases: [BinCmpCase<u64>; 3] = [
        bin_cmp_case(
            [1_u64, 2, 3, 4],
            right_col([0_u64, 3, 3, 5]),
            [1_u64, 1, 1, 0],
            None,
        ),
        bin_cmp_case(
            [4_u64, 2, 1, 0],
            right_col([4_u64, 1, 2, 0]),
            [0_u64, 1, 0, 1],
            None,
        ),
        bin_cmp_case(
            [2_u64, 5, 1, 7],
            right_lit(2_u64),
            [0_u64, 0, 1, 1],
            Some([1_u64, 0, 1, 0]),
        ),
    ];
    run_bin_cmp_soundness_cases(DataType::UInt64, &cases);
}

#[test]
fn gadget_bin_cmp_completeness_int64() {
    let cases: [BinCmpCase<i64>; 3] = [
        bin_cmp_case(
            [20_i64, -3, -4, -5],
            right_col([20_i64, 2, 3, 4]),
            [1_i64, 0, 0, 0],
            None,
        ),
        bin_cmp_case(
            [0_i64, 5, -2, -7],
            right_col([-1_i64, 4, -1, -6]),
            [1_i64, 1, 0, 0],
            None,
        ),
        bin_cmp_case(
            [2_i64, 5, 1, 7],
            right_lit(2_i64),
            [1_i64, 1, 0, 1],
            Some([1_i64, 0, 1, 0]),
        ),
    ];
    run_bin_cmp_completeness_cases(DataType::Int64, &cases);
}

#[test]
fn gadget_bin_cmp_soundness_int64() {
    let cases: [BinCmpCase<i64>; 3] = [
        bin_cmp_case(
            [1_i64, 2, 3, 4],
            right_col([0_i64, 3, 3, 5]),
            [1_i64, 1, 1, 0],
            None,
        ),
        bin_cmp_case(
            [4_i64, 2, 1, 0],
            right_col([4_i64, 1, 2, 0]),
            [0_i64, 1, 0, 1],
            None,
        ),
        bin_cmp_case(
            [2_i64, 5, 1, 7],
            right_lit(2_i64),
            [0_i64, 0, 1, 1],
            Some([1_i64, 0, 1, 0]),
        ),
    ];
    run_bin_cmp_soundness_cases(DataType::Int64, &cases);
}

#[test]
fn gadget_bin_cmp_completeness_uint128() {
    let cases: [BinCmpCase<u128>; 3] = [
        bin_cmp_case(
            [20_u128, 3, 4, 5],
            right_col([20_u128, 4, 3, 6]),
            [1_u128, 0, 1, 0],
            None,
        ),
        bin_cmp_case(
            [0_u128, 5, 2, 7],
            right_col([1_u128, 4, 3, 6]),
            [0_u128, 1, 0, 1],
            None,
        ),
        bin_cmp_case(
            [2_u128, 5, 1, 7],
            right_lit(2_u128),
            [1_u128, 1, 0, 1],
            Some([1_u128, 0, 1, 0]),
        ),
    ];
    run_bin_cmp_completeness_cases(DataType::Decimal128(38, 0), &cases);
}

#[test]
fn gadget_bin_cmp_soundness_uint128() {
    let cases: [BinCmpCase<u128>; 3] = [
        bin_cmp_case(
            [1_u128, 2, 3, 4],
            right_col([0_u128, 3, 3, 5]),
            [1_u128, 1, 1, 0],
            None,
        ),
        bin_cmp_case(
            [4_u128, 2, 1, 0],
            right_col([4_u128, 1, 2, 0]),
            [0_u128, 1, 0, 1],
            None,
        ),
        bin_cmp_case(
            [2_u128, 5, 1, 7],
            right_lit(2_u128),
            [0_u128, 0, 1, 1],
            Some([1_u128, 0, 1, 0]),
        ),
    ];
    run_bin_cmp_soundness_cases(DataType::Decimal128(38, 0), &cases);
}

#[test]
fn gadget_bin_cmp_completeness_int128() {
    let cases: [BinCmpCase<i128>; 3] = [
        bin_cmp_case(
            [20_i128, -3, -4, -5],
            right_col([20_i128, 2, 3, 4]),
            [1_i128, 0, 0, 0],
            None,
        ),
        bin_cmp_case(
            [0_i128, 5, -2, -7],
            right_col([-1_i128, 4, -1, -6]),
            [1_i128, 1, 0, 0],
            None,
        ),
        bin_cmp_case(
            [2_i128, 5, 1, 7],
            right_lit(2_i128),
            [1_i128, 1, 0, 1],
            Some([1_i128, 0, 1, 0]),
        ),
    ];
    run_bin_cmp_completeness_cases(DataType::Decimal128(38, 0), &cases);
}

#[test]
fn gadget_bin_cmp_soundness_int128() {
    let cases: [BinCmpCase<i128>; 3] = [
        bin_cmp_case(
            [1_i128, 2, 3, 4],
            right_col([0_i128, 3, 3, 5]),
            [1_i128, 1, 1, 0],
            None,
        ),
        bin_cmp_case(
            [4_i128, 2, 1, 0],
            right_col([4_i128, 1, 2, 0]),
            [0_i128, 1, 0, 1],
            None,
        ),
        bin_cmp_case(
            [2_i128, 5, 1, 7],
            right_lit(2_i128),
            [0_i128, 0, 1, 1],
            Some([1_i128, 0, 1, 0]),
        ),
    ];
    run_bin_cmp_soundness_cases(DataType::Decimal128(38, 0), &cases);
}
