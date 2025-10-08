use crate::select::SelectCheckPIOP;
use arithmetic::table::{TrackedTable, TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::{PCS, kzg10::KZG10, pst13::PST13},
    piop::PIOP,
    test_utils::test_prelude,
    to_field_vec,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::structs::{SelectConfig, SelectProverInput, SelectVerifierInput, WhereClause};

#[test]
fn eq_filter_is_complete() -> SnarkResult<()> {
    select_check_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        WhereClause::Eq(1, Fr::from(25u64)),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([0, 0, 0, 0, 1, 0, 0, 1], Fr),
    )?;

    select_check_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        WhereClause::Eq(1, Fr::from(25u64)),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 0], Fr),
        to_field_vec!([0, 0, 0, 0, 1, 0, 0, 0], Fr),
    )?;

    Ok(())
}

#[test]
fn eq_filter_is_sound() -> SnarkResult<()> {
    select_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        WhereClause::Eq(1, Fr::from(25u64)),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([0, 1, 0, 0, 1, 0, 0, 1], Fr),
    )?;

    select_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        WhereClause::Eq(1, Fr::from(25u64)),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([0, 0, 0, 0, 1, 0, 0, 0], Fr),
    )?;

    Ok(())
}

#[test]
fn geq_filter_is_complete() -> SnarkResult<()> {
    select_check_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        WhereClause::Geq(1, Fr::from(26u64)),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([0, 0, 0, 0, 0, 1, 0, 0], Fr),
    )?;
    select_check_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        WhereClause::Geq(1, Fr::from(25u64)),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([0, 0, 0, 0, 1, 1, 0, 1], Fr),
    )?;

    select_check_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        WhereClause::Geq(1, Fr::from(25u64)),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 0], Fr),
        to_field_vec!([0, 0, 0, 0, 1, 1, 0, 0], Fr),
    )?;

    Ok(())
}

#[test]
fn geq_filter_is_sound() -> SnarkResult<()> {
    select_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        WhereClause::Geq(1, Fr::from(9u64)),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([1, 1, 0, 1, 1, 1, 0, 1], Fr),
    )?;

    select_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        WhereClause::Geq(1, Fr::from(9u64)),
        to_field_vec!([5, 10, 5, 20, 25, 30, 8, 25], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([0, 1, 0, 1, 1, 0, 0, 1], Fr),
    )?;
    Ok(())
}

#[test]
fn leq_filter_is_complete() -> SnarkResult<()> {
    select_check_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        WhereClause::Leq(1, Fr::from(26u64)),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 0, 1, 1], Fr),
    )?;
    select_check_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        WhereClause::Leq(1, Fr::from(25u64)),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 0, 1, 1], Fr),
    )?;

    select_check_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        WhereClause::Leq(1, Fr::from(25u64)),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 0], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 0, 1, 0], Fr),
    )?;

    Ok(())
}

#[test]
fn leq_filter_is_sound() -> SnarkResult<()> {
    select_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        WhereClause::Leq(1, Fr::from(9u64)),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([0, 0, 1, 0, 0, 0, 1, 0], Fr),
    )?;
    select_check_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        WhereClause::Leq(1, Fr::from(9u64)),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([1, 0, 1, 0, 1, 0, 1, 0], Fr),
    )?;
    Ok(())
}

fn select_check_soundness_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    where_clause: WhereClause<Fr>,
    input_values: Vec<Fr>,
    input_activator_values: Vec<Fr>,
    out_activator_values: Vec<Fr>,
) -> SnarkResult<()> {
    let err = select_check_helper::<Fr, MvPCS, UvPCS>(
        where_clause,
        input_values,
        input_activator_values,
        out_activator_values,
    )
    .unwrap_err();

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

    Ok(())
}

fn select_check_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    where_clause: WhereClause<Fr>,
    input_values: Vec<Fr>,
    input_activator_values: Vec<Fr>,
    out_activator_values: Vec<Fr>,
) -> SnarkResult<()> {
    let nv = 3;
    let (mut prover, mut verifier) = test_prelude::<Fr, MvPCS, UvPCS>()?;

    // Column 1
    let mle_1 = MLE::from_evaluations_vec(nv, to_field_vec!([1, 2, 3, 1, 5, 6, 1, 5], Fr));
    let tr_p_1 = prover.track_and_commit_mat_mv_poly(&mle_1).unwrap();
    // Column 2
    let mle_2 = MLE::from_evaluations_vec(nv, input_values);
    let tr_p_2 = prover.track_and_commit_mat_mv_poly(&mle_2).unwrap();
    // Column 3
    let mle_3 =
        MLE::from_evaluations_vec(nv, to_field_vec!([591, 100, 23, 120, 225, 30, 5, 89], Fr));
    let tr_p_3 = prover.track_and_commit_mat_mv_poly(&mle_3).unwrap();

    // Input activation column, all rows are activated
    let in_activator_mle = MLE::from_evaluations_vec(nv, input_activator_values);
    let in_activator_tr_p = prover.track_and_commit_mat_mv_poly(&in_activator_mle).unwrap();

    // Output activation column
    let out_activator_mle = MLE::from_evaluations_vec(nv, out_activator_values);
    let out_activator_tr_p = prover.track_and_commit_mat_mv_poly(&out_activator_mle).unwrap();

    let schema = Schema::new(vec![
        Field::new("col1", DataType::UInt8, false),
        Field::new("col2", DataType::UInt8, false),
        Field::new("col3", DataType::UInt8, false),
    ]);

    // Input table
    let in_table = TrackedTable::new(
        Some(schema.clone()),
        vec![tr_p_1.clone(), tr_p_2.clone(), tr_p_3.clone()],
        Some(in_activator_tr_p.clone()),
        3,
    );

    // Output table
    let out_table = TrackedTable::new(
        Some(schema.clone()),
        vec![tr_p_1.clone(), tr_p_2.clone(), tr_p_3.clone()],
        Some(out_activator_tr_p.clone()),
        3,
    );

    let select_instr = SelectConfig { where_clause };

    let select_check_prover_input = SelectProverInput {
        input_table: in_table,
        output_table: out_table,
        select_conf: select_instr.clone(),
    };

    // Prove step
    SelectCheckPIOP::<Fr, MvPCS, UvPCS>::prove(&mut prover, select_check_prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);

    // Transfer comitments
    let tr_comm_1 = verifier.track_mv_com_by_id(tr_p_1.id())?;
    let tr_comm_2 = verifier.track_mv_com_by_id(tr_p_2.id())?;
    let tr_comm_3 = verifier.track_mv_com_by_id(tr_p_3.id())?;
    let in_activator_tr_comm = verifier.track_mv_com_by_id(in_activator_tr_p.id())?;
    let out_activator_tr_comm = verifier.track_mv_com_by_id(out_activator_tr_p.id())?;

    // Input and Output table comitments
    let in_tracked_Table_oracle = TrackedTableOracle::new(
        Some(schema.clone()),
        vec![tr_comm_1.clone(), tr_comm_2.clone(), tr_comm_3.clone()],
        Some(in_activator_tr_comm),
        nv,
    );
    let out_tracked_Table_oracle = TrackedTableOracle::new(
        Some(schema),
        vec![tr_comm_1, tr_comm_2, tr_comm_3],
        Some(out_activator_tr_comm),
        nv,
    );

    let select_check_verifier_input = SelectVerifierInput {
        input_tracked_Table_oracle: in_tracked_Table_oracle,
        output_tracked_Table_oracle: out_tracked_Table_oracle,
        select_conf: select_instr.clone(),
    };

    // Verify step
    SelectCheckPIOP::<Fr, MvPCS, UvPCS>::verify(&mut verifier, select_check_verifier_input)?;

    verifier.verify()?;

    Ok(())
}
