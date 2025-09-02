use arithmetic::col::{ArithCol, ColCom};
use arithmetic::table::ArithTable;
use arithmetic::table::TableComm;
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

use crate::inner_join::InnerJoinPIOP;
use crate::inner_join::{
    prover::{InnerJoinProver, InnerJoinProverInput},
    verifier::{InnerJoinVerifier, InnerJoinVerifierInput},
};

fn inner_join_is_complete() -> SnarkResult<()> {
    inner_join_test_helper::<
        Fr,
        KZG10<Fr, Bls12_381>,
        PST13<Fr, Bls12_381>>(
            2,
            None,
            vec![to_field_vec!([1, 1, 2, 2]), to_field_vec!([5, 6, 7, 8])],
            2,
            None,
            vec![to_field_vec!([1, 1, 2, 2]), to_field_vec!([9, 10, 11, 12])],
            3,
            None,
            vec![to_field_vec!([1, 1, 1, 1, 2, 2, 2, 2]), to_field_vec!([5, 5, 6, 6, 7, 7, 8, 8]), to_field_vec!([9, 10, 9, 10, 11, 12, 11, 12])],
            1,
            None,
            to_field_vec!([1, 2]),
            1,
            None,
            to_field_vec!([1, 2]),
            1,
            None,
            to_field_vec!([1, 2]),
            1,
            None,
            to_field_vec!([1, 2]),
            to_field_vec!([0, 0, 1, 1, 2, 2, 3, 3]),
            to_field_vec!([0, 1, 0, 1, 2, 3, 2, 3]),
            to_field_vec!([0, 1, 2, 3, 4, 5, 6, 7]),
            to_field_vec!([2, 2, 2, 2]),
            to_field_vec!([2, 2, 2, 2])
        )?;
    Ok(())
}

fn inner_join_test_soundness_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    nv_left_table: usize,
    actv_left_table: Option<Vec<Fr>>,
    data_left_table: Vec<Vec<Fr>>,
    nv_right_table: usize,
    actv_right_table: Option<Vec<Fr>>,
    data_right_table: Vec<Vec<Fr>>,
    nv_out_table: usize,
    actv_out_table: Option<Vec<Fr>>,
    data_out_table: Vec<Vec<Fr>>,
    nv_left_keysupp: usize,
    actv_left_keysupp: Option<Vec<Fr>>,
    data_left_keysupp: Vec<Fr>,
    nv_right_keysupp: usize,
    actv_right_keysupp: Option<Vec<Fr>>,
    data_right_keysupp: Vec<Fr>,
    nv_out_keysupp: usize,
    actv_out_keysupp: Option<Vec<Fr>>,
    data_out_keysupp: Vec<Fr>,
    nv_all_keysupp: usize,
    actv_all_keysupp: Option<Vec<Fr>>,
    data_all_keysupp: Vec<Fr>,
    join_left_source_data: Vec<Fr>,
    join_right_source_data: Vec<Fr>,
    index_poly_data: Vec<Fr>,
    right_table_multiplicity_data: Vec<Fr>,
    left_table_multiplicity_data: Vec<Fr>,
) -> SnarkResult<()> {
    let err = inner_join_test_helper(nv_left_table, actv_left_table, data_left_table, nv_right_table, actv_right_table, data_right_table, nv_out_table, actv_out_table, data_out_table, nv_left_keysupp, actv_left_keysupp, data_left_keysupp, nv_right_keysupp, actv_right_keysupp, data_right_keysupp, nv_out_keysupp, actv_out_keysupp, data_out_keysupp, nv_all_keysupp, actv_all_keysupp, data_all_keysupp, join_left_source_data, join_right_source_data, index_poly_data, right_table_multiplicity_data, left_table_multiplicity_data).unwrap_err();
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

fn inner_join_test_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    nv_left_table: usize,
    actv_left_table: Option<Vec<Fr>>,
    data_left_table: Vec<Vec<Fr>>,
    nv_right_table: usize,
    actv_right_table: Option<Vec<Fr>>,
    data_right_table: Vec<Vec<Fr>>,
    nv_out_table: usize,
    actv_out_table: Option<Vec<Fr>>,
    data_out_table: Vec<Vec<Fr>>,
    nv_left_keysupp: usize,
    actv_left_keysupp: Option<Vec<Fr>>,
    data_left_keysupp: Vec<Fr>,
    nv_right_keysupp: usize,
    actv_right_keysupp: Option<Vec<Fr>>,
    data_right_keysupp: Vec<Fr>,
    nv_out_keysupp: usize,
    actv_out_keysupp: Option<Vec<Fr>>,
    data_out_keysupp: Vec<Fr>,
    nv_all_keysupp: usize,
    actv_all_keysupp: Option<Vec<Fr>>,
    data_all_keysupp: Vec<Fr>,
    join_left_source_data: Vec<Fr>,
    join_right_source_data: Vec<Fr>,
    index_poly_data: Vec<Fr>,
    right_table_multiplicity_data: Vec<Fr>,
    left_table_multiplicity_data: Vec<Fr>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<Fr, MvPCS, UvPCS>()?;

    //left table prep
    let actv_left_table_poly = match actv_left_table {
        Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(nv_left_table, &actv_values),
        )?),
            None => None,
        };
    let data_left_table_polys = data_left_table.iter().map(|col| {
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv_left_table, col))
    }).collect::<SnarkResult<Vec<_>>>()?;


    // right table prep
    let actv_right_table_poly = match actv_right_table {
        Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(nv_right_table, &actv_values),
        )?),
            None => None,
        };
    let data_right_table_polys = data_right_table.iter().map(|col| {
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv_right_table, col))
    }).collect::<SnarkResult<Vec<_>>>()?;

    // output table prep
    let actv_out_table_poly = match actv_out_table {
        Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(nv_out_table, &actv_values),
        )?),
            None => None,
        };
    let data_out_table_polys = data_out_table.iter().map(|col| {
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(nv_out_table, col))
    }).collect::<SnarkResult<Vec<_>>>()?;

    // keysupp prep
    let actv_left_keysupp_poly = match actv_left_keysupp {
        Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(nv_left_keysupp, &actv_values),
        )?),
            None => None,
        };
    let data_left_keysupp_poly = prover.track_mat_mv_poly(&MLE::from_evaluations_slice(nv_left_keysupp, &data_left_keysupp));

    let actv_right_keysupp_poly = match actv_right_keysupp {
        Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(nv_right_keysupp, &actv_values),
        )?),
            None => None,
        };
    let data_right_keysupp_poly = prover.track_mat_mv_poly(&MLE::from_evaluations_slice(nv_right_keysupp, &data_right_keysupp));

    let actv_out_keysupp_poly = match actv_out_keysupp {
        Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(nv_out_keysupp, &actv_values),
        )?),
            None => None,
        };
    let data_out_keysupp_poly = prover.track_mat_mv_poly(&MLE::from_evaluations_slice(nv_out_keysupp, &data_out_keysupp));
    
    let actv_all_keysupp_poly = match actv_all_keysupp {
        Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(nv_all_keysupp, &actv_values),
        )?),
            None => None,
        };
    let data_all_keysupp_poly = prover.track_mat_mv_poly(&MLE::from_evaluations_slice(nv_all_keysupp, &data_all_keysupp));

    // source col prep
    let join_left_source_poly = prover.track_and_commit_mat_mv_poly(
        &MLE::from_evaluations_slice(nv_out_table, &join_left_source_data),
    )?;
    let join_right_source_poly = prover.track_and_commit_mat_mv_poly(
        &MLE::from_evaluations_slice(nv_out_table, &join_right_source_data),
    )?;

    // index poly prep
    let highest_nv = nv_left_table.max(nv_right_table).max(nv_out_table);
    let index_poly = prover.track_and_commit_mat_mv_poly(
        &MLE::from_evaluations_slice(highest_nv, &index_poly_data),
    )?;

    // multiplicity poly prep
    let right_table_multiplicity_poly = prover.track_and_commit_mat_mv_poly(
        &MLE::from_evaluations_slice(nv_right_table, &right_table_multiplicity_data),
    )?;
    let left_table_multiplicity_poly = prover.track_and_commit_mat_mv_poly(
        &MLE::from_evaluations_slice(nv_left_table, &left_table_multiplicity_data),
    )?;

    let inner_join_prover_input: InnerJoinProverInput<Fr, MvPCS::Poly, UvPCS::Poly> =
        InnerJoinProverInput {
            left_table: ArithTable::new(None, data_left_table_polys, actv_left_table_poly, nv_left_table),
            right_table: ArithTable::new(None, data_right_table_polys, actv_right_table_poly, nv_right_table),
            out_table: ArithTable::new(None, data_out_table_polys, actv_out_table_poly, nv_out_table),
            // keysupps
            left_key_support: ArithCol::new(None, data_left_keysupp_poly, actv_left_keysupp_poly),
            right_key_support: ArithCol::new(None, data_right_keysupp_poly, actv_right_keysupp_poly),
            out_key_support: ArithCol::new(None, data_out_keysupp_poly, actv_out_keysupp_poly),
            all_key_support: ArithCol::new(None, data_all_keysupp_poly, actv_all_keysupp_poly),
            // source cols
            join_left_source: ArithCol::new(None, join_left_source_poly, actv_left_table_poly.clone()),
            join_right_source: ArithCol::new(None, join_right_source_poly, actv_right_table_poly.clone()),
            // index poly
            index_poly: index_poly,
            // multiplicity polys
            right_table_multiplicity: right_table_multiplicity_poly,
            left_table_multiplicity: left_table_multiplicity_poly,
        };
    
    InnerJoinPIOP::<Fr, MvPCS, UvPCS>::prove(&mut prover, inner_join_prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);
    //////////////////////////////////////////////////////
    
    let actv_left_table_comm = match &actv_left_table {
        Some(_) => Some(verifier.track_mv_com_by_id(verifier.peek_next_id())),
        None => None,
    };
    let data_left_table_coms = data_left_table.iter().map(|_| {
        verifier.track_mv_com_by_id(verifier.peek_next_id())
    }).collect::<Vec<_>>();
    let actv_right_table_comm = match &actv_right_table {
        Some(_) => Some(verifier.track_mv_com_by_id(verifier.peek_next_id())),
        None => None,
    };
    let data_right_table_coms = data_right_table.iter().map(|_| {
        verifier.track_mv_com_by_id(verifier.peek_next_id())
    }).collect::<Vec<_>>();
    let actv_out_table_comm = match &actv_out_table {
        Some(_) => Some(verifier.track_mv_com_by_id(verifier.peek_next_id())),
        None => None,
    };
    let data_out_table_coms = data_out_table.iter().map(|_| {
        verifier.track_mv_com_by_id(verifier.peek_next_id())
    }).collect::<Vec<_>>();

    let actv_left_keysupp_comm = match &actv_left_keysupp {
        Some(_) => Some(verifier.track_mv_com_by_id(verifier.peek_next_id())),
        None => None,
    };
    let data_left_keysupp_comm = verifier.track_mv_com_by_id(verifier.peek_next_id());
    let actv_right_keysupp_comm = match &actv_right_keysupp {
        Some(_) => Some(verifier.track_mv_com_by_id(verifier.peek_next_id())),
        None => None,
    };
    let data_right_keysupp_comm = verifier.track_mv_com_by_id(verifier.peek_next_id());
    let actv_out_keysupp_comm = match &actv_out_keysupp {
        Some(_) => Some(verifier.track_mv_com_by_id(verifier.peek_next_id())),
        None => None,
    };
    let data_out_keysupp_comm = verifier.track_mv_com_by_id(verifier.peek_next_id());
    let actv_all_keysupp_comm = match &actv_all_keysupp {
        Some(_) => Some(verifier.track_mv_com_by_id(verifier.peek_next_id())),
        None => None,
    };
    let data_all_keysupp_comm = verifier.track_mv_com_by_id(verifier.peek_next_id());
    let join_left_source_comm = verifier.track_mv_com_by_id(verifier.peek_next_id());
    let join_right_source_comm = verifier.track_mv_com_by_id(verifier.peek_next_id());
    let index_poly_comm = verifier.track_mv_com_by_id(verifier.peek_next_id());
    let right_table_multiplicity_comm = verifier.track_mv_com_by_id(verifier.peek_next_id());
    let left_table_multiplicity_comm = verifier.track_mv_com_by_id(verifier.peek_next_id());

    let inner_join_verifier_input: InnerJoinVerifierInput<Fr, MvPCS::Com, UvPCS::Com> =
        InnerJoinVerifierInput {
            left_table_comm: TableComm::new(None, data_left_table_coms, actv_left_table_comm, nv_left_table),
            right_table_comm: TableComm::new(None, data_right_table_coms, actv_right_table_comm, nv_right_table),
            out_table_comm: TableComm::new(None, data_out_table_coms, actv_out_table_comm, nv_out_table),
            left_key_support_comm: ColComm::new(None, data_left_keysupp_comm, actv_left_keysupp_comm),
            right_key_support_comm: ColComm::new(None, data_right_keysupp_comm, actv_right_keysupp_comm),
            out_key_support_comm: ColComm::new(None, data_out_keysupp_comm, actv_out_keysupp_comm),
            all_key_support_comm: ColComm::new(None, data_all_keysupp_comm, actv_all_keysupp_comm),
            join_left_source_comm: ColComm::new(None, join_left_source_comm, actv_left_table_comm.clone()),
            join_right_source_comm: ColComm::new(None, join_right_source_comm, actv_right_table_comm.clone()),
            index_poly_comm,
            right_table_multiplicity_comm,
            left_table_multiplicity_comm,
        };
    
    InnerJoinPIOP::<Fr, MvPCS, UvPCS>::verify(&mut verifier, inner_join_verifier_input)?;
    verifier.verify()?;
    Ok(())

}