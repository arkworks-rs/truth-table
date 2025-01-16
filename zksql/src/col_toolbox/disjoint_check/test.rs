use arithmetic::{ark_ff, ark_poly};
use crypto::ark_ec::pairing::Pairing;
use arithmetic::ark_ff::{Field, PrimeField};
use arithmetic::ark_poly::DenseMultilinearExtension;
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use crypto::{ark_ec, pcs::{multilinear_kzg::MultilinearKzgPCS, PolynomialCommitmentScheme}};


use kit::ark_std::{test_rng, One};

use crate::{
    col_toolbox::disjoint_check::{utils::calc_disjoint_check_advice, DisjointCheck},
    tracker::prelude::*,
};

#[test]
fn test_disjoint_check_with_advice() -> Result<(), PolyIOPErrors> {
    // testing params
    let range_nv = 10;
    let range_nums = (0..2_usize.pow(range_nv as u32)).collect::<Vec<usize>>();
    let range_mle = DenseMultilinearExtension::from_evaluations_vec(
        range_nv,
        range_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let mut rng = test_rng();

    // PCS params
    let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, range_nv)?;
    let (pcs_prover_param, pcs_verifier_param) =
        MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(10))?;

    // create trackers
    let mut prover_tracker: ProverTrackerRef<
        <ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField,
        MultilinearKzgPCS<Bls12_381>,
    > = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
    let mut verifier_tracker: VerifierTrackerRef<
        <ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField,
        MultilinearKzgPCS<Bls12_381>,
    > = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

    // // Test good path 1: a and b are same size, are disjoint, no dups
    // print!("SuppCheck good path 1 test: ");
    // let poly_a_nv = 4;
    // let poly_b_nv = 4;
    // let poly_a_nums = (0..2_usize.pow(poly_a_nv as u32)).collect::<Vec<usize>>();
    // let poly_b_nums = poly_a_nums.iter().map(|x| x + 2_usize.pow(poly_a_nv as
    // u32)).collect::<Vec<usize>>();

    // let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(poly_a_nv,
    // poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect());
    // let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(poly_b_nv,
    // poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect());
    // let one_poly_4 = DenseMultilinearExtension::from_evaluations_vec(poly_a_nv,
    // vec![Fr::one(); 2_usize.pow(poly_a_nv as u32)]);

    // test_disjoint_check_with_advice_helper::<Bls12_381,
    // MultilinearKzgPCS::<Bls12_381>>(     &mut prover_tracker,
    //     &mut verifier_tracker,
    //     &poly_a_mle.clone(),
    //     &one_poly_4.clone(),
    //     &poly_b_mle,
    //     &one_poly_4.clone(),
    //     &range_mle.clone(),
    // )?;
    // println!("passed");

    // test good path 2: a and b are different sizes, non-trivial selector, no dups
    print!("SuppCheck good path 2 test: ");
    let poly_a_nv = 3;
    let poly_b_nv = 2;
    let poly_a_nums = (0..2_usize.pow(poly_a_nv as u32)).collect::<Vec<usize>>();
    let sel_a_nums = vec![1, 1, 1, 1, 1, 1, 0, 0];
    let poly_b_nums = [10, 11, 12, 0];
    let sel_b_nums = [1, 1, 1, 0];

    let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_a_nv,
        poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let sel_a_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_a_nv,
        sel_a_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_b_nv,
        poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let sel_b_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_b_nv,
        sel_b_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );

    test_disjoint_check_with_advice_helper::<
        <ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField,
        MultilinearKzgPCS<Bls12_381>,
    >(
        &mut prover_tracker,
        &mut verifier_tracker,
        &poly_a_mle.clone(),
        &sel_a_mle.clone(),
        &poly_b_mle,
        &sel_b_mle.clone(),
        &range_mle.clone(),
    )?;
    println!("passed");

    // test good path 3: a and b are same size, are disjoint, with dups
    print!("SuppCheck good path 3 test: ");
    let poly_a_nv = 3;
    let poly_b_nv = 3;
    let poly_a_nums = [1, 1, 2, 0, 0, 0, 0, 0];
    let sel_a_nums = [1, 1, 1, 0, 0, 0, 0, 0];
    let poly_b_nums = [0, 0, 0, 8, 9, 9, 0, 0];
    let sel_b_nums = [0, 0, 0, 1, 1, 1, 0, 0];
    let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_a_nv,
        poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let sel_a_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_a_nv,
        sel_a_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_b_nv,
        poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let sel_b_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_b_nv,
        sel_b_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    test_disjoint_check_with_advice_helper::<
        <ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField,
        MultilinearKzgPCS<Bls12_381>,
    >(
        &mut prover_tracker,
        &mut verifier_tracker,
        &poly_a_mle.clone(),
        &sel_a_mle.clone(),
        &poly_b_mle,
        &sel_b_mle.clone(),
        &range_mle.clone(),
    )?;
    println!("passed");

    // test bad path 1: a and b are sets, there is a shared element
    print!("SuppCheck bad path 1 test: ");
    let poly_a_nums = vec![0, 1];
    let poly_b_nums = vec![1, 2];
    let sel_a_nums = vec![1, 1];
    let sel_b_nums = vec![1, 1];

    let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(
        1,
        poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let sel_a_mle = DenseMultilinearExtension::from_evaluations_vec(
        1,
        sel_a_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(
        1,
        poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let sel_b_mle = DenseMultilinearExtension::from_evaluations_vec(
        1,
        sel_b_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );

    let bad_res = test_disjoint_check_with_advice_helper::<
        <ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField,
        MultilinearKzgPCS<Bls12_381>,
    >(
        &mut prover_tracker.deep_copy(),
        &mut verifier_tracker.deep_copy(),
        &poly_a_mle.clone(),
        &sel_a_mle.clone(),
        &poly_b_mle,
        &sel_b_mle.clone(),
        &range_mle.clone(),
    );
    assert!(bad_res.is_err());
    println!("passed");

    // test bad path 2: a and b are cols, there are shared elements
    print!("SuppCheck bad path 2 test: ");
    let poly_a_nv = 3;
    let poly_b_nv = 3;
    let poly_a_nums = [1, 1, 2, 5, 5, 6, 0, 0];
    let sel_a_nums = [1, 1, 1, 1, 1, 1, 0, 0];
    let poly_b_nums = [5, 6, 6, 8, 9, 9, 0, 0];
    let sel_b_nums = [1, 1, 1, 1, 1, 1, 0, 0];
    let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_a_nv,
        poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let sel_a_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_a_nv,
        sel_a_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_b_nv,
        poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let sel_b_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_b_nv,
        sel_b_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let bad_res2 = test_disjoint_check_with_advice_helper::<
        <ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField,
        MultilinearKzgPCS<Bls12_381>,
    >(
        &mut prover_tracker,
        &mut verifier_tracker,
        &poly_a_mle.clone(),
        &sel_a_mle.clone(),
        &poly_b_mle,
        &sel_b_mle.clone(),
        &range_mle.clone(),
    );
    assert!(bad_res2.is_err());
    println!("passed");

    Ok(())
}

fn test_disjoint_check_with_advice_helper<F: PrimeField + PrimeField, PCS>(
    prover_tracker: &mut ProverTrackerRef<F, PCS>,
    verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
    col_a_poly: &DenseMultilinearExtension<F>,
    col_a_sel: &DenseMultilinearExtension<F>,
    col_b_poly: &DenseMultilinearExtension<F>,
    col_b_sel: &DenseMultilinearExtension<F>,
    range_poly: &DenseMultilinearExtension<F>,
) -> Result<(), PolyIOPErrors>
where
    PCS: PolynomialCommitmentScheme<F>,
{
    let col_a = Col::new(
        prover_tracker.track_and_commit_poly(col_a_poly.clone())?,
        prover_tracker.track_and_commit_poly(col_a_sel.clone())?,
    );
    let col_b = Col::new(
        prover_tracker.track_and_commit_poly(col_b_poly.clone())?,
        prover_tracker.track_and_commit_poly(col_b_sel.clone())?,
    );
    let range_col = Col::new(
        prover_tracker.track_and_commit_poly(range_poly.clone())?,
        prover_tracker.track_and_commit_poly(range_poly.clone())?,
    );
    let (col_c_mle, col_c_sel_mle, m_a_mle, m_b_mle) = calc_disjoint_check_advice(&col_a, &col_b)?;
    let col_c = Col::new(
        prover_tracker.track_and_commit_poly(col_c_mle)?,
        prover_tracker.track_and_commit_poly(col_c_sel_mle)?,
    );
    let m_a = prover_tracker.track_and_commit_poly(m_a_mle)?;
    let m_b = prover_tracker.track_and_commit_poly(m_b_mle)?;

    DisjointCheck::<F, PCS>::prove_with_advice(
        prover_tracker,
        &col_a,
        &col_b,
        &col_c,
        &m_a,
        &m_b,
        &range_col,
    )?;
    let proof = prover_tracker.compile_proof()?;

    // set up verifier tracker, create subclaims, and verify IOPProofs
    verifier_tracker.set_compiled_proof(proof);
    let col_a_comm = ColComm::new(
        verifier_tracker.transfer_prover_comm(col_a.inner_poly.id),
        verifier_tracker.transfer_prover_comm(col_a.actv_poly.id),
        col_a.num_vars(),
    );
    let col_b_comm = ColComm::new(
        verifier_tracker.transfer_prover_comm(col_b.inner_poly.id),
        verifier_tracker.transfer_prover_comm(col_b.actv_poly.id),
        col_b.num_vars(),
    );
    let range_col_comm = ColComm::new(
        verifier_tracker.transfer_prover_comm(range_col.inner_poly.id),
        verifier_tracker.transfer_prover_comm(range_col.actv_poly.id),
        range_col.num_vars(),
    );
    let col_c_comm = ColComm::new(
        verifier_tracker.transfer_prover_comm(col_c.inner_poly.id),
        verifier_tracker.transfer_prover_comm(col_c.actv_poly.id),
        col_c.num_vars(),
    );
    let m_a_comm = verifier_tracker.transfer_prover_comm(m_a.id);
    let m_b_comm = verifier_tracker.transfer_prover_comm(m_b.id);
    DisjointCheck::<F, PCS>::verify_with_advice(
        verifier_tracker,
        &col_a_comm,
        &col_b_comm,
        &col_c_comm,
        &m_a_comm,
        &m_b_comm,
        &range_col_comm,
    )?;
    verifier_tracker.verify_claims()?;

    // check that the ProverTracker and VerifierTracker are in the same state
    let p_tracker = prover_tracker.clone_underlying_tracker();
    let v_tracker = verifier_tracker.clone_underlying_tracker();
    assert_eq!(p_tracker.num_tracked_polys, v_tracker.num_tracked_polys);
    assert_eq!(p_tracker.sum_check_claims, v_tracker.sum_check_claims);
    assert_eq!(p_tracker.zero_check_claims, v_tracker.zero_check_claims);

    Ok(())
}

#[test]
fn test_disjoint_check() -> Result<(), PolyIOPErrors> {
    // testing params
    let range_nv = 10;
    let range_nums = (0..2_usize.pow(range_nv as u32)).collect::<Vec<usize>>();
    let range_mle = DenseMultilinearExtension::from_evaluations_vec(
        range_nv,
        range_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let mut rng = test_rng();

    // PCS params
    let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, range_nv)?;
    let (pcs_prover_param, pcs_verifier_param) =
        MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(10))?;

    // create trackers
    let mut prover_tracker: ProverTrackerRef<
        <ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField,
        MultilinearKzgPCS<Bls12_381>,
    > = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
    let mut verifier_tracker: VerifierTrackerRef<
        <ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField,
        MultilinearKzgPCS<Bls12_381>,
    > = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);

    // Test good path 1: a and b are same size, are disjoint, no dups
    print!("SuppCheck good path 1 test: ");
    let poly_a_nv = 4;
    let poly_b_nv = 4;
    let poly_a_nums = (0..2_usize.pow(poly_a_nv as u32)).collect::<Vec<usize>>();
    let poly_b_nums = poly_a_nums
        .iter()
        .map(|x| x + 2_usize.pow(poly_a_nv as u32))
        .collect::<Vec<usize>>();

    let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_a_nv,
        poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_b_nv,
        poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let one_poly_4 = DenseMultilinearExtension::from_evaluations_vec(
        poly_a_nv,
        vec![Fr::one(); 2_usize.pow(poly_a_nv as u32)],
    );

    test_disjoint_check_helper::<
        <ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField,
        MultilinearKzgPCS<Bls12_381>,
    >(
        &mut prover_tracker,
        &mut verifier_tracker,
        &poly_a_mle.clone(),
        &one_poly_4.clone(),
        &poly_b_mle,
        &one_poly_4.clone(),
        &range_mle.clone(),
    )?;
    println!("passed");

    // test good path 2: a and b are different sizes, non-trivial selector, no dups
    print!("SuppCheck good path 2 test: ");
    let poly_a_nv = 3;
    let poly_b_nv = 2;
    let poly_a_nums = (0..2_usize.pow(poly_a_nv as u32)).collect::<Vec<usize>>();
    let sel_a_nums = vec![1, 1, 1, 1, 1, 1, 0, 0];
    let poly_b_nums = [10, 11, 12, 0];
    let sel_b_nums = [1, 1, 1, 0];

    let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_a_nv,
        poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let sel_a_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_a_nv,
        sel_a_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_b_nv,
        poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let sel_b_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_b_nv,
        sel_b_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );

    test_disjoint_check_helper::<
        <ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField,
        MultilinearKzgPCS<Bls12_381>,
    >(
        &mut prover_tracker,
        &mut verifier_tracker,
        &poly_a_mle.clone(),
        &sel_a_mle.clone(),
        &poly_b_mle,
        &sel_b_mle.clone(),
        &range_mle.clone(),
    )?;
    println!("passed");

    // test good path 3: a and b are same size, are disjoint, with dups
    print!("SuppCheck good path 3 test: ");
    let poly_a_nv = 3;
    let poly_b_nv = 3;
    let poly_a_nums = [1, 1, 2, 0, 0, 0, 0, 0];
    let sel_a_nums = [1, 1, 1, 0, 0, 0, 0, 0];
    let poly_b_nums = [0, 0, 0, 8, 9, 9, 0, 0];
    let sel_b_nums = [0, 0, 0, 1, 1, 1, 0, 0];
    let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_a_nv,
        poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let sel_a_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_a_nv,
        sel_a_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_b_nv,
        poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let sel_b_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_b_nv,
        sel_b_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    test_disjoint_check_helper::<
        <ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField,
        MultilinearKzgPCS<Bls12_381>,
    >(
        &mut prover_tracker,
        &mut verifier_tracker,
        &poly_a_mle.clone(),
        &sel_a_mle.clone(),
        &poly_b_mle,
        &sel_b_mle.clone(),
        &range_mle.clone(),
    )?;
    println!("passed");

    // test bad path 1: a and b are sets, there is a shared element
    print!("SuppCheck bad path 1 test: ");
    let poly_a_nums = vec![0, 1];
    let poly_b_nums = vec![1, 2];
    let sel_a_nums = vec![1, 1];
    let sel_b_nums = vec![1, 1];

    let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(
        1,
        poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let sel_a_mle = DenseMultilinearExtension::from_evaluations_vec(
        1,
        sel_a_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(
        1,
        poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let sel_b_mle = DenseMultilinearExtension::from_evaluations_vec(
        1,
        sel_b_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );

    let bad_res = test_disjoint_check_helper::<
        <ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField,
        MultilinearKzgPCS<Bls12_381>,
    >(
        &mut prover_tracker.deep_copy(),
        &mut verifier_tracker.deep_copy(),
        &poly_a_mle.clone(),
        &sel_a_mle.clone(),
        &poly_b_mle,
        &sel_b_mle.clone(),
        &range_mle.clone(),
    );
    assert!(bad_res.is_err());
    println!("passed");

    // test bad path 2: a and b are cols, there are shared elements
    print!("SuppCheck bad path 2 test: ");
    let poly_a_nv = 3;
    let poly_b_nv = 3;
    let poly_a_nums = [1, 1, 2, 5, 5, 6, 0, 0];
    let sel_a_nums = [1, 1, 1, 1, 1, 1, 0, 0];
    let poly_b_nums = [5, 6, 6, 8, 9, 9, 0, 0];
    let sel_b_nums = [1, 1, 1, 1, 1, 1, 0, 0];
    let poly_a_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_a_nv,
        poly_a_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let sel_a_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_a_nv,
        sel_a_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let poly_b_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_b_nv,
        poly_b_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let sel_b_mle = DenseMultilinearExtension::from_evaluations_vec(
        poly_b_nv,
        sel_b_nums.iter().map(|x| Fr::from(*x as u64)).collect(),
    );
    let bad_res2 = test_disjoint_check_helper::<
        <ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField,
        MultilinearKzgPCS<Bls12_381>,
    >(
        &mut prover_tracker,
        &mut verifier_tracker,
        &poly_a_mle.clone(),
        &sel_a_mle.clone(),
        &poly_b_mle,
        &sel_b_mle.clone(),
        &range_mle.clone(),
    );
    assert!(bad_res2.is_err());
    println!("passed");

    Ok(())
}

fn test_disjoint_check_helper<F: PrimeField + PrimeField, PCS>(
    prover_tracker: &mut ProverTrackerRef<F, PCS>,
    verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
    col_a_poly: &DenseMultilinearExtension<F>,
    col_a_sel: &DenseMultilinearExtension<F>,
    col_b_poly: &DenseMultilinearExtension<F>,
    col_b_sel: &DenseMultilinearExtension<F>,
    range_poly: &DenseMultilinearExtension<F>,
) -> Result<(), PolyIOPErrors>
where
    PCS: PolynomialCommitmentScheme<F>,
{
    let col_a = Col::new(
        prover_tracker.track_and_commit_poly(col_a_poly.clone())?,
        prover_tracker.track_and_commit_poly(col_a_sel.clone())?,
    );
    let col_b = Col::new(
        prover_tracker.track_and_commit_poly(col_b_poly.clone())?,
        prover_tracker.track_and_commit_poly(col_b_sel.clone())?,
    );
    let range_col = Col::new(
        prover_tracker.track_and_commit_poly(range_poly.clone())?,
        prover_tracker.track_and_commit_poly(range_poly.clone())?,
    );

    DisjointCheck::<F, PCS>::prove(prover_tracker, &col_a, &col_b, &range_col)?;
    let proof = prover_tracker.compile_proof()?;

    // set up verifier tracker, create subclaims, and verify IOPProofs
    verifier_tracker.set_compiled_proof(proof);
    let col_a_comm = ColComm::new(
        verifier_tracker.transfer_prover_comm(col_a.inner_poly.id),
        verifier_tracker.transfer_prover_comm(col_a.actv_poly.id),
        col_a.num_vars(),
    );
    let col_b_comm = ColComm::new(
        verifier_tracker.transfer_prover_comm(col_b.inner_poly.id),
        verifier_tracker.transfer_prover_comm(col_b.actv_poly.id),
        col_b.num_vars(),
    );
    let range_col_comm = ColComm::new(
        verifier_tracker.transfer_prover_comm(range_col.inner_poly.id),
        verifier_tracker.transfer_prover_comm(range_col.actv_poly.id),
        range_col.num_vars(),
    );
    DisjointCheck::<F, PCS>::verify(verifier_tracker, &col_a_comm, &col_b_comm, &range_col_comm)?;
    verifier_tracker.verify_claims()?;

    // check that the ProverTracker and VerifierTracker are in the same state
    let p_tracker = prover_tracker.clone_underlying_tracker();
    let v_tracker = verifier_tracker.clone_underlying_tracker();
    assert_eq!(p_tracker.num_tracked_polys, v_tracker.num_tracked_polys);
    assert_eq!(p_tracker.sum_check_claims, v_tracker.sum_check_claims);
    assert_eq!(p_tracker.zero_check_claims, v_tracker.zero_check_claims);

    Ok(())
}
