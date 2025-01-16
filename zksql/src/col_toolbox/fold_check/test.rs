use arithmetic::{
    ark_ff,
    ark_ff::{Field, PrimeField},
    ark_poly,
    ark_poly::DenseMultilinearExtension,
    mle::mat::{fold_mles, rand_mles, random_permutation_mles},
};
use ark_std::One;
use crypto::ark_ec::pairing::Pairing;

use ark_std::test_rng;
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use crypto::{
    ark_ec,
    pcs::{multilinear_kzg::MultilinearKzgPCS, PolynomialCommitmentScheme},
};
use kit::ark_std::{self, UniformRand};

use crate::{
    col_toolbox::eq_check::EqCheckIOP,
    tracker::{prelude::*, test_utils::test_prelude},
};

use super::FoldCheckPIOP;

// Sets up randomized inputs for testing EqCheckCheck
#[test]
fn test_fold_check() -> Result<(), PolyIOPErrors> {
    let mut rng = test_rng();
    let nv = 8;
    let num = 8;

    let (mut prover_tracker, mut verifier_tracker) =
        test_prelude::<Fr, MultilinearKzgPCS<Bls12_381>>(nv)?;
    let input_mles = rand_mles(num, nv, &mut rng);
    let actv_mle = DenseMultilinearExtension::from_evaluations_vec(
        nv,
        vec![Fr::one(); 2_usize.pow(nv as u32)],
    );
    let actv_tracked_mle = prover_tracker.track_and_commit_poly(actv_mle).unwrap();
    let challs = vec![Fr::rand(&mut rng); num];
    let folded_poly = fold_mles(&input_mles, &challs);

    let folded_tracked_poly = Col {
        inner_poly: prover_tracker
            .track_and_commit_poly(folded_poly.clone())
            .unwrap(),
        actv_poly: actv_tracked_mle.clone(),
    };

    let input_cols: Vec<Col<Fr, MultilinearKzgPCS<Bls12_381>>> = input_mles
        .iter()
        .map(|mle| Col {
            inner_poly: prover_tracker.track_and_commit_poly(mle.clone()).unwrap(),
            actv_poly: actv_tracked_mle.clone(),
        })
        .collect();

    FoldCheckPIOP::<Fr, MultilinearKzgPCS<Bls12_381>>::prove(
        &mut prover_tracker,
        &input_cols,
        &folded_tracked_poly,
        &challs,
    );
    let proof = prover_tracker.compile_proof().unwrap();
    verifier_tracker.set_compiled_proof(proof);

    let actv_comm = verifier_tracker.transfer_prover_comm(actv_tracked_mle.id);
    let folded_comm = ColComm::new(
        verifier_tracker.transfer_prover_comm(folded_tracked_poly.inner_poly.id),
        actv_comm.clone(),
        actv_tracked_mle.num_vars(),
    );
    let input_comms: Vec<ColComm<Fr, MultilinearKzgPCS<Bls12_381>>> = input_cols
        .iter()
        .map(|col| {
            ColComm::new(
                verifier_tracker.transfer_prover_comm(col.inner_poly.id),
                actv_comm.clone(),
                actv_tracked_mle.num_vars(),
            )
        })
        .collect();

    FoldCheckPIOP::<Fr, MultilinearKzgPCS<Bls12_381>>::verify(
        &mut verifier_tracker,
        &input_comms,
        &folded_comm,
        &challs,
    );

    verifier_tracker.verify_claims().unwrap();

    // exit successfully
    Ok(())
}
