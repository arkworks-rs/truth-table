use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_piop::{
    DefaultSnarkBackend, arithmetic::mat_poly::mle::MLE, errors::SnarkResult, piop::PIOP,
    test_utils::test_prelude,
};
use ark_poly::MultilinearExtension;
use ark_std::test_rng;
use ark_test_curves::bls12_381::Fr;

use super::{FoldCheckPIOP, FoldCheckProverInput, FoldCheckVerifierInput};

// Sets up randomized inputs for testing EqCheck
#[test]
fn test_fold_check() -> SnarkResult<()> {
    // Ensure tracing subscriber is initialized once for test output
    let mut rng = test_rng();
    let nv = 8;
    let num = 8;

    let (mut prover, mut verifier) = test_prelude::<DefaultSnarkBackend>()?;
    let input_mles = (0..num)
        .map(|_| MLE::rand(nv, &mut rng))
        .collect::<Vec<_>>();
    let activator_mle = MLE::from_evaluations_vec(nv, vec![Fr::ONE; 2_usize.pow(nv as u32)]);
    let activator_tracked_mle = prover.track_and_commit_mat_mv_poly(&activator_mle).unwrap();
    let challs = vec![Fr::rand(&mut rng); num];
    let folded_poly = fold_mles(&input_mles, &challs);

    let folded_tracked_poly = TrackedCol::new(
        prover.track_and_commit_mat_mv_poly(&folded_poly).unwrap(),
        Some(activator_tracked_mle.clone()),
        None,
    );

    let input_cols: Vec<TrackedCol<DefaultSnarkBackend>> = input_mles
        .iter()
        .map(|mle| {
            TrackedCol::new(
                prover.track_and_commit_mat_mv_poly(mle).unwrap(),
                Some(activator_tracked_mle.clone()),
                None,
            )
        })
        .collect();
    let fold_check_piop_prover_input = FoldCheckProverInput {
        in_cols: input_cols.clone(),             // The input columns to be folded
        folded_col: folded_tracked_poly.clone(), // The column that is the result of folding
        challs: challs.clone(),                  // The challenges used for folding
    };

    let _result =
        FoldCheckPIOP::<DefaultSnarkBackend>::prove(&mut prover, fold_check_piop_prover_input);
    let proof = prover.build_proof().unwrap();
    verifier.set_proof(proof);

    let activatorm = verifier.track_mv_com_by_id(activator_tracked_mle.id())?;
    let folded_comm = TrackedColOracle::new(
        verifier.track_mv_com_by_id(folded_tracked_poly.data_tracked_poly().id())?,
        Some(activatorm.clone()),
        None,
    );
    let input_comms: Vec<TrackedColOracle<DefaultSnarkBackend>> = input_cols
        .iter()
        .map(|col| {
            TrackedColOracle::new(
                verifier
                    .track_mv_com_by_id(col.data_tracked_poly().id())
                    .unwrap(),
                Some(activatorm.clone()),
                None,
            )
        })
        .collect();

    let fold_check_verifier_input = FoldCheckVerifierInput {
        in_cms: input_comms.clone(), // The input column comitments to be folded
        folded_cm: folded_comm.clone(), /* The commitment of the column that is the result of
                                      * folding */
        challs: challs.clone(), // The challenges used for folding
    };

    let _result =
        FoldCheckPIOP::<DefaultSnarkBackend>::verify(&mut verifier, fold_check_verifier_input);

    verifier.verify().unwrap();

    // exit successfully
    Ok(())
}

pub fn fold_mles<F: PrimeField>(mles: &[MLE<F>], challs: &[F]) -> MLE<F> {
    let nv = mles[0].num_vars();
    let mut res = Vec::with_capacity(1 << nv);
    for i in 0..(1 << nv) {
        let mut val = F::zero();
        for (mle, chall) in mles.iter().zip(challs.iter()) {
            val += mle.evaluations()[i] * chall;
        }
        res.push(val);
    }
    MLE::from_evaluations_vec(nv, res)
}
