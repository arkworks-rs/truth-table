use super::{
    GroupByProverInput, GroupByVerifierInput,
    structs::{AggregationType, GroupByConfig},
};
use crate::group_by::GroupByPIOP;

use arithmetic::table::{ArithTable, TableComm};
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

#[test]
fn groupby_count_is_complete() {
    groupby_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 2, 3, 1, 5, 6, 1, 5], Fr),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([2, 1, 1, 1, 2, 1, 0, 0], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 0, 0], Fr),
        AggregationType::Count,
    )
    .unwrap();

    groupby_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 2, 3, 1, 5, 6, 1, 5], Fr),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([1, 1, 0, 1, 1, 1, 1, 0], Fr),
        to_field_vec!([2, 1, 10, 1, 1, 1, 0, 0], Fr),
        to_field_vec!([1, 1, 0, 1, 1, 1, 0, 0], Fr),
        AggregationType::Count,
    )
    .unwrap();
}

#[test]
fn groupby_count_is_sound() {
    groupby_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 2, 3, 1, 5, 6, 1, 5], Fr),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([2, 1, 1, 1, 2, 1, 0, 0], Fr),
        to_field_vec!([1, 1, 0, 1, 1, 1, 0, 0], Fr),
        AggregationType::Count,
    )
    .unwrap();

    groupby_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 2, 3, 1, 5, 6, 1, 5], Fr),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([1, 1, 0, 1, 1, 1, 1, 0], Fr),
        to_field_vec!([2, 11, 10, 1, 1, 1, 0, 0], Fr),
        to_field_vec!([0, 1, 0, 1, 1, 1, 0, 0], Fr),
        AggregationType::Count,
    )
    .unwrap();
}

#[test]
fn groupby_sum_is_complete() {
    groupby_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 2, 3, 1, 5, 6, 1, 5], Fr),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([10, 11, 12, 13, 14, 15, 16, 17], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([26, 11, 12, 13, 31, 15, 0, 0], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 0, 0], Fr),
        AggregationType::Sum,
    )
    .unwrap();

    groupby_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 2, 3, 1, 5, 6, 1, 5], Fr),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([10, 11, 12, 13, 14, 15, 16, 17], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 0, 1], Fr),
        to_field_vec!([10, 11, 12, 13, 31, 15, 0, 0], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 0, 0], Fr),
        AggregationType::Sum,
    )
    .unwrap();
}
#[test]
fn groupby_sum_is_sound() {
    groupby_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 2, 3, 1, 5, 6, 1, 5], Fr),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([10, 11, 12, 13, 14, 15, 16, 17], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([26, 1, 12, 13, 31, 15, 0, 0], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 0, 0], Fr),
        AggregationType::Sum,
    )
    .unwrap_err();

    groupby_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 2, 3, 1, 5, 6, 1, 5], Fr),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([10, 11, 12, 13, 14, 15, 16, 17], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 0, 0, 1], Fr),
        to_field_vec!([10, 11, 12, 13, 31, 15, 0, 0], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 0, 0], Fr),
        AggregationType::Sum,
    )
    .unwrap_err();
}

#[test]
fn groupby_max_is_complete() {
    groupby_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 2, 3, 1, 5, 6, 1, 5], Fr),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([10, 11, 12, 13, 14, 15, 16, 17], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([10, 11, 12, 13, 14, 15, 16, 17], Fr),
        to_field_vec!([0, 1, 1, 1, 0, 1, 1, 1], Fr),
        AggregationType::Max,
    )
    .unwrap();

    groupby_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 2, 3, 1, 5, 6, 1, 5], Fr),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([10, 11, 12, 13, 14, 15, 16, 17], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 0], Fr),
        to_field_vec!([10, 11, 12, 13, 14, 15, 16, 17], Fr),
        to_field_vec!([0, 1, 1, 1, 1, 1, 1, 0], Fr),
        AggregationType::Max,
    )
    .unwrap();
}

#[test]
fn groupby_max_is_sound() {
    groupby_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 2, 3, 1, 5, 6, 1, 5], Fr),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([10, 11, 12, 13, 14, 15, 16, 17], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([26, 11, 12, 13, 17, 15, 0, 0], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 0, 0], Fr),
        AggregationType::Max,
    )
    .unwrap();

    groupby_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 2, 3, 1, 5, 6, 1, 5], Fr),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([10, 11, 12, 13, 14, 15, 16, 17], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 0], Fr),
        to_field_vec!([10, 11, 12, 13, 14, 15, 16, 17], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 0, 0], Fr),
        AggregationType::Max,
    )
    .unwrap();
}

#[test]
fn groupby_min_is_complete() {
    groupby_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 2, 3, 1, 5, 6, 1, 5], Fr),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([10, 11, 12, 13, 14, 15, 16, 17], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([10, 11, 12, 13, 14, 15, 16, 17], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 0, 0], Fr),
        AggregationType::Min,
    )
    .unwrap();

    groupby_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 2, 3, 1, 5, 6, 1, 5], Fr),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([10, 11, 12, 13, 14, 15, 16, 17], Fr),
        to_field_vec!([0, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([10, 11, 12, 13, 14, 15, 16, 17], Fr),
        to_field_vec!([0, 1, 1, 1, 1, 1, 1, 0], Fr),
        AggregationType::Min,
    )
    .unwrap();
}

#[test]
fn groupby_min_is_sound() {
    groupby_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 2, 3, 1, 5, 6, 1, 5], Fr),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([10, 1, 12, 13, 14, 15, 16, 17], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([10, 11, 12, 13, 14, 15, 16, 17], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 0, 0], Fr),
        AggregationType::Min,
    )
    .unwrap();

    // The output is correct but not aligned
    groupby_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        3,
        to_field_vec!([1, 2, 3, 1, 5, 6, 1, 5], Fr),
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
        to_field_vec!([16, 11, 12, 13, 14, 15, 10, 17], Fr),
        to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr),
        to_field_vec!([10, 11, 12, 13, 14, 15, 16, 17], Fr),
        to_field_vec!([0, 1, 1, 1, 1, 1, 1, 0], Fr),
        AggregationType::Min,
    )
    .unwrap();
}

fn groupby_test_soundness_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    nv: usize,
    in_gp_values_1: Vec<Fr>,
    in_gp_values_2: Vec<Fr>,
    in_tarvalues: Vec<Fr>,
    in_actv: Vec<Fr>,
    out_tarvalues: Vec<Fr>,
    out_actv: Vec<Fr>,
    aggregation_type: AggregationType,
) -> SnarkResult<()> {
    let err = groupby_test_helper::<Fr, MvPCS, UvPCS>(
        nv,
        in_gp_values_1,
        in_gp_values_2,
        in_tarvalues,
        in_actv,
        out_tarvalues,
        out_actv,
        aggregation_type,
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

#[allow(clippy::too_many_arguments)]
fn groupby_test_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    nv: usize,
    in_gp_values_1: Vec<Fr>,
    in_gp_values_2: Vec<Fr>,
    in_tarvalues: Vec<Fr>,
    in_actv: Vec<Fr>,
    out_tarvalues: Vec<Fr>,
    out_actv: Vec<Fr>,
    aggregation_type: AggregationType,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<Fr, MvPCS, UvPCS>()?;

    // Grouping column 1
    let gp_mle_1 = MLE::from_evaluations_vec(nv, in_gp_values_1);
    let gp_tr_p_1 = prover.track_and_commit_mat_mv_poly(&gp_mle_1).unwrap();
    // Grouping column 2
    let gp_mle_2 = MLE::from_evaluations_vec(nv, in_gp_values_2);
    let gp_tr_p_2 = prover.track_and_commit_mat_mv_poly(&gp_mle_2).unwrap();
    // Input activation column, all rows are activated
    let in_actv_mle = MLE::from_evaluations_vec(nv, in_actv);
    let in_actv_tr_p = prover.track_and_commit_mat_mv_poly(&in_actv_mle).unwrap();

    // Output activation column, Last two rows are grouped with others and not
    // activated
    let out_actv_mle = MLE::from_evaluations_vec(nv, out_actv);
    let out_actv_tr_p = prover.track_and_commit_mat_mv_poly(&out_actv_mle).unwrap();

    let input_tarmle = MLE::from_evaluations_vec(nv, in_tarvalues);
    let input_tartr_poly = prover
        .track_and_commit_mat_mv_poly(&input_tarmle)
        .unwrap();

    let in_tr_ps = vec![
        gp_tr_p_1.clone(),
        gp_tr_p_2.clone(),
        input_tartr_poly.clone(),
    ];

    // Input table to the group by query
    let in_schema = Schema::new(
        (1..=in_tr_ps.len())
            .map(|i| Field::new(format!("col{}", i), DataType::UInt8, false))
            .collect::<Vec<Field>>(),
    );
    let in_table = ArithTable::new(
        Some(in_schema.clone()),
        in_tr_ps.clone(),
        Some(in_actv_tr_p.clone()),
        8,
    );

    // Output table from the group by query
    let mut out_tr_ps = vec![gp_tr_p_1.clone(), gp_tr_p_2.clone()];
    let out_tarmle = MLE::from_evaluations_vec(nv, out_tarvalues);
    let out_tartr_p = prover
        .track_and_commit_mat_mv_poly(&out_tarmle)
        .unwrap();
    out_tr_ps.push(out_tartr_p.clone());

    let out_schema = Schema::new(
        (1..=out_tr_ps.len())
            .map(|i| Field::new(format!("col{}", i), DataType::UInt8, false))
            .collect::<Vec<Field>>(),
    );
    let out_table = ArithTable::new(
        Some(out_schema.clone()),
        out_tr_ps,
        Some(out_actv_tr_p.clone()),
        6,
    );

    let group_by_instr = GroupByConfig {
        gpd_col_indices: vec![0, 1],
        agg_instr: vec![(2, aggregation_type)],
    };

    let group_by_check_prover_input = GroupByProverInput {
        input_table: in_table,
        output_table: out_table,
        instr: group_by_instr.clone(),
    };

    GroupByPIOP::<Fr, MvPCS, UvPCS>::prove(&mut prover, group_by_check_prover_input)?;
    let proof = prover.build_proof().unwrap();
    verifier.set_proof(proof);
    let gp_tr_comm_1 = verifier.track_mv_com_by_id(gp_tr_p_1.id())?;
    let gp_tr_comm_2 = verifier.track_mv_com_by_id(gp_tr_p_2.id())?;
    let in_actv_tr_comm = verifier.track_mv_com_by_id(in_actv_tr_p.id())?;
    let out_actv_tr_comm = verifier.track_mv_com_by_id(out_actv_tr_p.id())?;
    let input_tartr_comm = verifier.track_mv_com_by_id(input_tartr_poly.id())?;
    let in_tr_comms = vec![
        gp_tr_comm_1.clone(),
        gp_tr_comm_2.clone(),
        input_tartr_comm,
    ];
    let in_table_comm = TableComm::new(
        Some(in_schema),
        in_tr_comms.clone(),
        Some(in_actv_tr_comm),
        nv,
    );
    let out_tartr_comm = verifier.track_mv_com_by_id(out_tartr_p.id())?;
    let out_tr_comms = vec![gp_tr_comm_1, gp_tr_comm_2, out_tartr_comm];
    let out_table_comm = TableComm::new(Some(out_schema), out_tr_comms, Some(out_actv_tr_comm), nv);

    let group_by_check_verifier_input = GroupByVerifierInput {
        input_table_comm: in_table_comm,
        output_table_comm: out_table_comm,
        instr: group_by_instr,
    };
    GroupByPIOP::<Fr, MvPCS, UvPCS>::verify(&mut verifier, group_by_check_verifier_input)?;

    verifier.verify()?;

    // exit successfully
    Ok(())
}
