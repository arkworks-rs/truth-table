use arithmetic::{
    col::{ArithCol, ColCom},
    table::{ArithTable, TableComm},
};
use ark_ec::pairing::Pairing;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::{PCS, kzg10::KZG10, pst13::PST13},
    piop::PIOP,
    test_utils::test_prelude,
    to_field_vec,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};

use crate::inner_join::{InnerJoinPIOP, InnerJoinProverInput, InnerJoinVerifierInput};

struct InnerJoinTestInput<E: Pairing> {
    pub nv_left_table: usize,
    pub actv_left_table: Option<Vec<E::ScalarField>>,
    pub data_left_table: Vec<Vec<E::ScalarField>>,
    pub nv_right_table: usize,
    pub actv_right_table: Option<Vec<E::ScalarField>>,
    pub data_right_table: Vec<Vec<E::ScalarField>>,
    pub nv_out_table: usize,
    pub actv_out_table: Option<Vec<E::ScalarField>>,
    pub data_out_table: Vec<Vec<E::ScalarField>>,
    pub nv_left_keysupp: usize,
    pub actv_left_keysupp: Option<Vec<E::ScalarField>>,
    pub data_left_keysupp: Vec<E::ScalarField>,
    pub nv_right_keysupp: usize,
    pub actv_right_keysupp: Option<Vec<E::ScalarField>>,
    pub data_right_keysupp: Vec<E::ScalarField>,
    pub nv_out_keysupp: usize,
    pub actv_out_keysupp: Option<Vec<E::ScalarField>>,
    pub data_out_keysupp: Vec<E::ScalarField>,
    pub nv_all_keysupp: usize,
    pub actv_all_keysupp: Option<Vec<E::ScalarField>>,
    pub data_all_keysupp: Vec<E::ScalarField>,
    pub join_left_source_data: Vec<E::ScalarField>,
    pub join_right_source_data: Vec<E::ScalarField>,
    pub right_table_multiplicity_data: Vec<E::ScalarField>,
    pub left_table_multiplicity_data: Vec<E::ScalarField>,
}

#[test]
fn inner_join_is_complete() -> SnarkResult<()> {
    let input = InnerJoinTestInput {
        nv_left_table: 2,
        actv_left_table: None,
        data_left_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([5, 6, 7, 8], Fr),
        ],
        nv_right_table: 2,
        actv_right_table: None,
        data_right_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([9, 10, 11, 12], Fr),
        ],
        nv_out_table: 3,
        actv_out_table: None,
        data_out_table: vec![
            to_field_vec!([1, 1, 1, 1, 2, 2, 2, 2], Fr),
            to_field_vec!([5, 5, 6, 6, 7, 7, 8, 8], Fr),
            to_field_vec!([9, 10, 9, 10, 11, 12, 11, 12], Fr),
        ],
        nv_left_keysupp: 1,
        actv_left_keysupp: None,
        data_left_keysupp: to_field_vec!([1, 2], Fr),
        nv_right_keysupp: 1,
        actv_right_keysupp: None,
        data_right_keysupp: to_field_vec!([1, 2], Fr),
        nv_out_keysupp: 1,
        actv_out_keysupp: None,
        data_out_keysupp: to_field_vec!([1, 2], Fr),
        nv_all_keysupp: 1,
        actv_all_keysupp: None,
        data_all_keysupp: to_field_vec!([1, 2], Fr),
        join_left_source_data: to_field_vec!([0, 0, 1, 1, 2, 2, 3, 3], Fr),
        join_right_source_data: to_field_vec!([0, 1, 0, 1, 2, 3, 2, 3], Fr),
        right_table_multiplicity_data: to_field_vec!([2, 2, 2, 2], Fr),
        left_table_multiplicity_data: to_field_vec!([2, 2, 2, 2], Fr),
    };
    inner_join_test_helper::<Bls12_381, PST13<Bls12_381>, KZG10<Bls12_381>>(input)?;
    Ok(())
}

fn inner_join_test_soundness_helper(input: InnerJoinTestInput<Bls12_381>) -> SnarkResult<()> {
    let err =
        inner_join_test_helper::<Bls12_381, PST13<Bls12_381>, KZG10<Bls12_381>>(input).unwrap_err();
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
    E: Pairing,
    MvPCS: PCS<E::ScalarField, Poly = MLE<E::ScalarField>>,
    UvPCS: PCS<E::ScalarField, Poly = LDE<E::ScalarField>>,
>(
    input: InnerJoinTestInput<E>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<E::ScalarField, MvPCS, UvPCS>()?;

    // left table prep
    let actv_left_table_poly = match &input.actv_left_table {
        Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(input.nv_left_table, actv_values.as_slice()),
        )?),
        None => None,
    };
    let data_left_table_polys = input
        .data_left_table
        .iter()
        .map(|col| {
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(
                input.nv_left_table,
                col.as_slice(),
            ))
        })
        .collect::<SnarkResult<Vec<_>>>()?;

    // right table prep
    let actv_right_table_poly = match &input.actv_right_table {
        Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(input.nv_right_table, actv_values.as_slice()),
        )?),
        None => None,
    };
    let data_right_table_polys = input
        .data_right_table
        .iter()
        .map(|col| {
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(
                input.nv_right_table,
                col.as_slice(),
            ))
        })
        .collect::<SnarkResult<Vec<_>>>()?;

    // output table prep
    let actv_out_table_poly = match &input.actv_out_table {
        Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(input.nv_out_table, actv_values.as_slice()),
        )?),
        None => None,
    };
    let data_out_table_polys = input
        .data_out_table
        .iter()
        .map(|col| {
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(
                input.nv_out_table,
                col.as_slice(),
            ))
        })
        .collect::<SnarkResult<Vec<_>>>()?;

    // keysupp prep
    let actv_left_keysupp_poly = match &input.actv_left_keysupp {
        Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(input.nv_left_keysupp, actv_values.as_slice()),
        )?),
        None => None,
    };
    let data_left_keysupp_poly = prover.track_and_commit_mat_mv_poly(
        &MLE::from_evaluations_slice(input.nv_left_keysupp, input.data_left_keysupp.as_slice()),
    )?;

    let actv_right_keysupp_poly = match &input.actv_right_keysupp {
        Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(input.nv_right_keysupp, actv_values.as_slice()),
        )?),
        None => None,
    };
    let data_right_keysupp_poly = prover.track_and_commit_mat_mv_poly(
        &MLE::from_evaluations_slice(input.nv_right_keysupp, input.data_right_keysupp.as_slice()),
    )?;

    let actv_out_keysupp_poly = match &input.actv_out_keysupp {
        Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(input.nv_out_keysupp, actv_values.as_slice()),
        )?),
        None => None,
    };
    let data_out_keysupp_poly = prover.track_and_commit_mat_mv_poly(
        &MLE::from_evaluations_slice(input.nv_out_keysupp, input.data_out_keysupp.as_slice()),
    )?;

    let actv_all_keysupp_poly = match &input.actv_all_keysupp {
        Some(actv_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(input.nv_all_keysupp, actv_values.as_slice()),
        )?),
        None => None,
    };
    let data_all_keysupp_poly = prover.track_and_commit_mat_mv_poly(
        &MLE::from_evaluations_slice(input.nv_all_keysupp, input.data_all_keysupp.as_slice()),
    )?;

    // source col prep
    let join_left_source_poly = prover.track_and_commit_mat_mv_poly(
        &MLE::from_evaluations_slice(input.nv_out_table, input.join_left_source_data.as_slice()),
    )?;
    let join_right_source_poly = prover.track_and_commit_mat_mv_poly(
        &MLE::from_evaluations_slice(input.nv_out_table, input.join_right_source_data.as_slice()),
    )?;

    // multiplicity poly prep
    let right_table_multiplicity_poly =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(
            input.nv_right_table,
            input.right_table_multiplicity_data.as_slice(),
        ))?;
    let left_table_multiplicity_poly =
        prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(
            input.nv_left_table,
            input.left_table_multiplicity_data.as_slice(),
        ))?;

    let inner_join_prover_input: InnerJoinProverInput<E::ScalarField, MvPCS, UvPCS> =
        InnerJoinProverInput {
            left_table: ArithTable::new(
                None,
                data_left_table_polys,
                actv_left_table_poly.clone(),
                input.nv_left_table,
            ),
            right_table: ArithTable::new(
                None,
                data_right_table_polys,
                actv_right_table_poly.clone(),
                input.nv_right_table,
            ),
            out_table: ArithTable::new(
                None,
                data_out_table_polys,
                actv_out_table_poly,
                input.nv_out_table,
            ),
            // keysupps
            left_key_support: ArithCol::new(None, data_left_keysupp_poly, actv_left_keysupp_poly),
            right_key_support: ArithCol::new(
                None,
                data_right_keysupp_poly,
                actv_right_keysupp_poly,
            ),
            out_key_support: ArithCol::new(None, data_out_keysupp_poly, actv_out_keysupp_poly),
            all_key_support: ArithCol::new(None, data_all_keysupp_poly, actv_all_keysupp_poly),
            // source cols
            join_left_source: ArithCol::new(
                None,
                join_left_source_poly,
                actv_left_table_poly.clone(),
            ),
            join_right_source: ArithCol::new(
                None,
                join_right_source_poly,
                actv_right_table_poly.clone(),
            ),
            // multiplicity polys
            right_table_multiplicity: right_table_multiplicity_poly,
            left_table_multiplicity: left_table_multiplicity_poly,
        };

    InnerJoinPIOP::<E::ScalarField, MvPCS, UvPCS>::prove(&mut prover, inner_join_prover_input)?;
    dbg!(prover.get_and_append_challenge(b"inner_join"));
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);
    //////////////////////////////////////////////////////

    let actv_left_table_comm = match &input.actv_left_table {
        Some(_) => {
            let id = verifier.peek_next_id();
            Some(verifier.track_mv_com_by_id(id).unwrap())
        },

        None => None,
    };
    let data_left_table_coms = input
        .data_left_table
        .iter()
        .map(|_| {
            let id = verifier.peek_next_id();
            verifier.track_mv_com_by_id(id).unwrap()
        })
        .collect::<Vec<_>>();
    let actv_right_table_comm = match &input.actv_right_table {
        Some(_) => {
            let id = verifier.peek_next_id();
            Some(verifier.track_mv_com_by_id(id).unwrap())
        },
        None => None,
    };
    let data_right_table_coms = input
        .data_right_table
        .iter()
        .map(|_| {
            let id = verifier.peek_next_id();
            verifier.track_mv_com_by_id(id).unwrap()
        })
        .collect::<Vec<_>>();
    let actv_out_table_comm = match &input.actv_out_table {
        Some(_) => {
            let id = verifier.peek_next_id();
            Some(verifier.track_mv_com_by_id(id).unwrap())
        },
        None => None,
    };
    let data_out_table_coms = input
        .data_out_table
        .iter()
        .map(|_| {
            let id = verifier.peek_next_id();
            verifier.track_mv_com_by_id(id).unwrap()
        })
        .collect::<Vec<_>>();

    let actv_left_keysupp_comm = match &input.actv_left_keysupp {
        Some(_) => {
            let id = verifier.peek_next_id();
            Some(verifier.track_mv_com_by_id(id).unwrap())
        },
        None => None,
    };
    let data_left_keysupp_id = verifier.peek_next_id();
    let data_left_keysupp_comm = verifier.track_mv_com_by_id(data_left_keysupp_id).unwrap();

    let actv_right_keysupp_comm = match &input.actv_right_keysupp {
        Some(_) => {
            let id = verifier.peek_next_id();
            Some(verifier.track_mv_com_by_id(id).unwrap())
        },
        None => None,
    };
    let data_right_keysupp_id = verifier.peek_next_id();
    let data_right_keysupp_comm = verifier.track_mv_com_by_id(data_right_keysupp_id).unwrap();
    let actv_out_keysupp_comm = match &input.actv_out_keysupp {
        Some(_) => {
            let id = verifier.peek_next_id();
            Some(verifier.track_mv_com_by_id(id).unwrap())
        },
        None => None,
    };
    let data_out_keysupp_id = verifier.peek_next_id();
    let data_out_keysupp_comm = verifier.track_mv_com_by_id(data_out_keysupp_id).unwrap();

    let actv_all_keysupp_comm = match &input.actv_all_keysupp {
        Some(_) => {
            let id = verifier.peek_next_id();
            Some(verifier.track_mv_com_by_id(id).unwrap())
        },
        None => None,
    };
    let data_all_keysupp_id = verifier.peek_next_id();
    let data_all_keysupp_comm = verifier.track_mv_com_by_id(data_all_keysupp_id)?;
    let join_left_source_id = verifier.peek_next_id();
    let join_left_source_comm = verifier.track_mv_com_by_id(join_left_source_id)?;
    let join_right_source_id = verifier.peek_next_id();
    let join_right_source_comm = verifier.track_mv_com_by_id(join_right_source_id)?;
    let right_table_multiplicity_id = verifier.peek_next_id();
    let right_table_multiplicity_comm = verifier.track_mv_com_by_id(right_table_multiplicity_id)?;
    let left_table_multiplicity_id = verifier.peek_next_id();
    let left_table_multiplicity_comm = verifier.track_mv_com_by_id(left_table_multiplicity_id)?;

    let inner_join_verifier_input: InnerJoinVerifierInput<E::ScalarField, MvPCS, UvPCS> =
        InnerJoinVerifierInput {
            left_table_comm: TableComm::new(
                None,
                data_left_table_coms,
                actv_left_table_comm.clone(),
                input.nv_left_table,
            ),
            right_table_comm: TableComm::new(
                None,
                data_right_table_coms,
                actv_right_table_comm.clone(),
                input.nv_right_table,
            ),
            out_table_comm: TableComm::new(
                None,
                data_out_table_coms,
                actv_out_table_comm,
                input.nv_out_table,
            ),
            left_key_support_comm: ColCom::new(
                None,
                data_left_keysupp_comm,
                actv_left_keysupp_comm,
                input.nv_left_keysupp,
            ),
            right_key_support_comm: ColCom::new(
                None,
                data_right_keysupp_comm,
                actv_right_keysupp_comm,
                input.nv_right_keysupp,
            ),
            out_key_support_comm: ColCom::new(
                None,
                data_out_keysupp_comm,
                actv_out_keysupp_comm,
                input.nv_out_keysupp,
            ),
            all_key_support_comm: ColCom::new(
                None,
                data_all_keysupp_comm,
                actv_all_keysupp_comm,
                input.nv_all_keysupp,
            ),
            join_left_source_comm: ColCom::new(
                None,
                join_left_source_comm,
                actv_left_table_comm.clone(),
                input.nv_out_table,
            ),
            join_right_source_comm: ColCom::new(
                None,
                join_right_source_comm,
                actv_right_table_comm.clone(),
                input.nv_out_table,
            ),
            right_table_multiplicity: right_table_multiplicity_comm,
            left_table_multiplicity: left_table_multiplicity_comm,
        };

    InnerJoinPIOP::<E::ScalarField, MvPCS, UvPCS>::verify(
        &mut verifier,
        inner_join_verifier_input,
    )?;
    dbg!(verifier.get_and_append_challenge(b"inner_join"));
    verifier.verify()?;
    Ok(())
}
