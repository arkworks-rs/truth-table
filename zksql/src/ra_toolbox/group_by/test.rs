use arithmetic::{
    ark_ff::{self, Field, PrimeField},
    ark_poly::{self, DenseMultilinearExtension},
    mle::mat::{fold_mles, rand_mles, random_permutation_mles}, to_field_vec,
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

use super::{
    data_structures::{AggregationType, GroupByInstruction},
    FoldCheckPIOP, GroupByPIOP,
};

// Sets up randomized inputs for testing EqCheckCheck
#[test]
fn works() -> Result<(), PolyIOPErrors> {
    let mut rng = test_rng();
    let nv = 3;
    let range_nv = 5;
    let num = 2;

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

    let gp_mle_1 = DenseMultilinearExtension::from_evaluations_vec(
        nv,
        to_field_vec!([1, 2, 3, 1, 5, 6, 1, 5], Fr),
    );
    let gp_tr_p_1 = prover_tracker.track_and_commit_poly(gp_mle_1).unwrap();
    let gp_mle_2 = DenseMultilinearExtension::from_evaluations_vec(
        nv,
        to_field_vec!([5, 10, 5, 20, 25, 30, 5, 25], Fr),
    );
    let gp_tr_p_2 = prover_tracker.track_and_commit_poly(gp_mle_2).unwrap();

    let in_actv_mle = DenseMultilinearExtension::from_evaluations_vec(
        nv,
        vec![Fr::one(); 2_usize.pow(nv as u32)],
    );
    let in_actv_tr_p = prover_tracker
        .track_and_commit_poly(in_actv_mle.clone())
        .unwrap();
    let out_actv_mle = DenseMultilinearExtension::from_evaluations_vec(
        nv,
        to_field_vec!([1, 1, 1, 1, 1, 1, 0, 0], Fr),
    );
    let out_actv_tr_p = prover_tracker
        .track_and_commit_poly(out_actv_mle.clone())
        .unwrap();

    let rnd_mles: Vec<DenseMultilinearExtension<Fr>> = rand_mles(num, nv, &mut rng);
    let rnd_tr_ps = rnd_mles
        .iter()
        .map(|mle| prover_tracker.track_and_commit_poly(mle.clone()).unwrap())
        .collect::<Vec<_>>();

    let mut in_out_tr_ps = vec![gp_tr_p_1.clone(), gp_tr_p_2.clone()];
    in_out_tr_ps.extend_from_slice(&rnd_tr_ps);

    let in_table = Table::new(in_out_tr_ps.clone(), in_actv_tr_p.clone());
    let out_table = Table::new(in_out_tr_ps, out_actv_tr_p.clone());

    let group_by_instr = GroupByInstruction {
        gpd_col_indices: vec![0, 1],
        agg_instr: vec![(3, AggregationType::Sum)],
    };

    GroupByPIOP::<Fr, MultilinearKzgPCS<Bls12_381>>::prove(
        &mut prover_tracker,
        &in_table,
        &out_table,
        &range_col,
        &group_by_instr,
    );
    let proof = prover_tracker.compile_proof().unwrap();
    verifier_tracker.set_compiled_proof(proof);
    let range_tr_comm = verifier_tracker.transfer_prover_comm(range_tr_p.id);
    let range_sel_comm = verifier_tracker.transfer_prover_comm(range_sel_p.id);
    let range_col_comm = ColComm::new(range_tr_comm, range_sel_comm, range_nv);
    let gp_tr_comm_1 = verifier_tracker.transfer_prover_comm(gp_tr_p_1.id);
    let gp_tr_comm_2 = verifier_tracker.transfer_prover_comm(gp_tr_p_2.id);
    let in_actv_tr_comm = verifier_tracker.transfer_prover_comm(in_actv_tr_p.id);
    let out_actv_tr_comm = verifier_tracker.transfer_prover_comm(out_actv_tr_p.id);
    let rnd_tr_comms = rnd_tr_ps
        .iter()
        .map(|tr_p| verifier_tracker.transfer_prover_comm(tr_p.id))
        .collect::<Vec<_>>();
    let mut in_out_tr_comms = vec![gp_tr_comm_1, gp_tr_comm_2];
    in_out_tr_comms.extend_from_slice(&rnd_tr_comms);
    let in_table_comm = TableComm::new(in_out_tr_comms.clone(), in_actv_tr_comm, nv);
    let out_table_comm = TableComm::new(in_out_tr_comms, out_actv_tr_comm, nv);

    GroupByPIOP::<Fr, MultilinearKzgPCS<Bls12_381>>::verify(
        &mut verifier_tracker,
        &in_table_comm,
        &out_table_comm,
        &range_col_comm,
        &group_by_instr,
    );

    verifier_tracker.verify_claims().unwrap();

    // exit successfully
    Ok(())
}
