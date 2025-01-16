
use arithmetic::{
    ark_ff::{self, Field, PrimeField},
    ark_poly::{self, DenseMultilinearExtension},
    mle::mat::{fold_mles, rand_mles, random_permutation_mles},
    to_field_vec,
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

use super::NoDupPIOP;

// Sets up randomized inputs for testing EqCheckCheck
#[test]
fn works() -> Result<(), PolyIOPErrors> {
    let mut rng = test_rng();
    let nv = 3;
    let range_nv = 5;

    let (mut prover_tracker, mut verifier_tracker) =
        test_prelude::<Fr, MultilinearKzgPCS<Bls12_381>>(range_nv)?;
    let range_tr_p =
        prover_tracker.track_and_commit_poly(DenseMultilinearExtension::from_evaluations_vec(
            range_nv,
            (0..2_usize.pow(range_nv as u32))
                .map(|x| Fr::from(x as u64))
                .collect::<Vec<_>>(),
        ))?;
    let range_sel_p =
        prover_tracker.track_and_commit_poly(DenseMultilinearExtension::from_evaluations_vec(
            range_nv,
            vec![Fr::one(); 2_usize.pow(range_nv as u32)],
        ))?;
    let range_col = Col {
        inner_poly: range_tr_p.clone(),
        actv_poly: range_sel_p.clone(),
    };
    let in_mle = DenseMultilinearExtension::from_evaluations_vec(
        nv,
        to_field_vec!([4, 3, 10, 23, 1, 20, 18, 2], Fr),
    );
    let in_tr_p = prover_tracker.track_and_commit_poly(in_mle).unwrap();
    let in_actv_p = prover_tracker
        .track_and_commit_poly(DenseMultilinearExtension::from_evaluations_vec(
            nv,
            vec![Fr::one(); 2_usize.pow(nv as u32)],
        ))
        .unwrap();
    let in_col = Col {
        inner_poly: in_tr_p.clone(),
        actv_poly: in_actv_p.clone(),
    };

    NoDupPIOP::<Fr, MultilinearKzgPCS<Bls12_381>>::prove(&mut prover_tracker, &in_col, &range_col)?;
    let proof = prover_tracker.compile_proof().unwrap();
    verifier_tracker.set_compiled_proof(proof);
    let range_tr_comm = verifier_tracker.transfer_prover_comm(range_tr_p.id);
    let range_sel_comm = verifier_tracker.transfer_prover_comm(range_sel_p.id);
    let range_col_comm = ColComm::new(range_tr_comm, range_sel_comm, range_nv);
    let in_comm = verifier_tracker.transfer_prover_comm(in_tr_p.id);
    let actv_comm = verifier_tracker.transfer_prover_comm(in_actv_p.id);
    let in_comm = ColComm::new(in_comm, actv_comm, nv);
    NoDupPIOP::<Fr, MultilinearKzgPCS<Bls12_381>>::verify(&mut verifier_tracker, &in_comm, &range_col_comm)?;

    verifier_tracker.verify_claims().unwrap();

    // exit successfully
    Ok(())
}
