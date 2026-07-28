//! Tests for `BroadcastCheckPIOP`.
//!
//! Layout: a tiny setup with two strings and four characters, each string
//! contributing two characters. The `ind` column carries distinct row ids;
//! `src` maps characters back to their owning string. Happy-path tests
//! prove + verify end-to-end. Negative-path tests corrupt one input and
//! expect the verifier to reject.

use arithmetic::col::TrackedCol;
use arithmetic::col_oracle::TrackedColOracle;
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::SnarkResult,
    piop::PIOP,
    test_utils::prelude_with_vars,
};

use super::{
    BroadcastCheckPIOP, BroadcastCheckProverInput, BroadcastCheckVerifierInput,
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const STR_NV: usize = 1;
const CHAR_NV: usize = 2;

fn setup() -> (
    ark_piop::prover::ArgProver<B>,
    ark_piop::verifier::ArgVerifier<B>,
) {
    // Small SRS is enough — the largest tracked poly here has 2^2 = 4 evals.
    prelude_with_vars::<B>(4).expect("prelude_with_vars(4) should succeed")
}

/// Track + commit a matrix poly so the verifier sees the commitment.
fn track_and_commit(
    prover: &mut ark_piop::prover::ArgProver<B>,
    evals: Vec<F>,
    nv: usize,
) -> SnarkResult<ark_piop::prover::structs::polynomial::TrackedPoly<B>> {
    prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(nv, evals))
}

/// Runs the full prove + verify pipeline for one input tuple.
/// Returns Ok(()) on successful end-to-end verification.
fn run_pipeline(str_evals_x: Vec<F>, char_evals_x_prime: Vec<F>) -> SnarkResult<()> {
    let (mut prover, mut verifier) = setup();

    // Fixed shape: 2 strings, 4 chars. ind = [0, 1], src = [0, 0, 1, 1].
    let ind_evals: Vec<F> = (0..(1 << STR_NV) as u64).map(F::from).collect();
    let src_evals: Vec<F> = vec![F::from(0u64), F::from(0u64), F::from(1u64), F::from(1u64)];

    let str_x = track_and_commit(&mut prover, str_evals_x.clone(), STR_NV)?;
    let char_x_prime = track_and_commit(&mut prover, char_evals_x_prime.clone(), CHAR_NV)?;
    let src_poly = track_and_commit(&mut prover, src_evals.clone(), CHAR_NV)?;
    let ind_poly = track_and_commit(&mut prover, ind_evals.clone(), STR_NV)?;

    let str_col = TrackedCol::new(str_x.clone(), None, None);
    let char_col = TrackedCol::new(char_x_prime.clone(), None, None);
    let src_col = TrackedCol::new(src_poly.clone(), None, None);
    let ind_col = TrackedCol::new(ind_poly.clone(), None, None);

    BroadcastCheckPIOP::<B>::prove(
        &mut prover,
        BroadcastCheckProverInput {
            str_col,
            char_col,
            src_col,
            ind_col,
        },
    )?;

    let proof = prover.build_proof()?;
    verifier.set_proof(proof);

    let str_x_o = verifier.track_mv_com_by_id(str_x.id())?;
    let char_x_prime_o = verifier.track_mv_com_by_id(char_x_prime.id())?;
    let src_o = verifier.track_mv_com_by_id(src_poly.id())?;
    let ind_o = verifier.track_mv_com_by_id(ind_poly.id())?;

    let str_col_o = TrackedColOracle::new(str_x_o, None, None);
    let char_col_o = TrackedColOracle::new(char_x_prime_o, None, None);
    let src_col_o = TrackedColOracle::new(src_o, None, None);
    let ind_col_o = TrackedColOracle::new(ind_o, None, None);

    BroadcastCheckPIOP::<B>::verify(
        &mut verifier,
        BroadcastCheckVerifierInput {
            str_col_oracle: str_col_o,
            char_col_oracle: char_col_o,
            src_col_oracle: src_col_o,
            ind_col_oracle: ind_col_o,
        },
    )?;

    verifier.verify()?;
    Ok(())
}

#[test]
fn broadcast_holds_end_to_end() {
    // Strings: x = [10, 20]. Chars: x' = [10, 10, 20, 20] (broadcast of x).
    let str_x = vec![F::from(10u64), F::from(20u64)];
    let char_x_prime = vec![
        F::from(10u64),
        F::from(10u64),
        F::from(20u64),
        F::from(20u64),
    ];
    run_pipeline(str_x, char_x_prime).expect("broadcast should verify");
}

#[test]
fn broadcast_holds_with_zero_values() {
    // Edge: broadcast of zeros.
    let str_x = vec![F::from(0u64), F::from(0u64)];
    let char_x_prime = vec![F::from(0u64); 4];
    run_pipeline(str_x, char_x_prime).expect("zero broadcast should verify");
}

#[test]
fn broadcast_violation_char_value_rejected() {
    // Corrupt char 2: should belong to string 1 with value 20, but we set 99.
    let str_x = vec![F::from(10u64), F::from(20u64)];
    let char_x_prime = vec![
        F::from(10u64),
        F::from(10u64),
        F::from(99u64), // <-- wrong
        F::from(20u64),
    ];
    assert!(
        run_pipeline(str_x, char_x_prime).is_err(),
        "corrupted broadcast must not verify"
    );
}

#[test]
fn broadcast_violation_swap_within_string_rejected() {
    // Swap so char 0 (owned by string 0) carries string 1's value. This is
    // still boolean-valued and same-set as the honest x', so any collapse
    // that isn't fingerprinting would let it through.
    let str_x = vec![F::from(10u64), F::from(20u64)];
    let char_x_prime = vec![
        F::from(20u64), // wrong: owned by string 0 (value 10)
        F::from(10u64), // wrong: owned by string 0 (value 10)
        F::from(10u64), // wrong: owned by string 1 (value 20)
        F::from(20u64),
    ];
    assert!(
        run_pipeline(str_x, char_x_prime).is_err(),
        "cross-string swap must not verify"
    );
}

#[test]
fn broadcast_with_activator_end_to_end() {
    // Same 4-char layout, but char index 3 is inactive: its value can be
    // anything (garbage) and the check should still pass because the
    // activator masks it out. String side has no activator (all rows valid).
    let (mut prover, mut verifier) = setup();

    let str_x_evals = vec![F::from(10u64), F::from(20u64)];
    let char_x_prime_evals = vec![
        F::from(10u64),
        F::from(10u64),
        F::from(20u64),
        F::from(777u64), // inactive slot: garbage OK
    ];
    let src_evals = vec![F::from(0u64), F::from(0u64), F::from(1u64), F::from(1u64)];
    let ind_evals = vec![F::from(0u64), F::from(1u64)];
    // Mixed activator (avoids the all-ones → constant-fold path).
    let char_act_evals = vec![F::from(1u64), F::from(1u64), F::from(1u64), F::from(0u64)];

    let str_x = track_and_commit(&mut prover, str_x_evals, STR_NV).unwrap();
    let char_x_prime =
        track_and_commit(&mut prover, char_x_prime_evals, CHAR_NV).unwrap();
    let src_poly = track_and_commit(&mut prover, src_evals, CHAR_NV).unwrap();
    let ind_poly = track_and_commit(&mut prover, ind_evals, STR_NV).unwrap();
    let char_act = track_and_commit(&mut prover, char_act_evals, CHAR_NV).unwrap();

    let str_col = TrackedCol::new(str_x.clone(), None, None);
    let char_col = TrackedCol::new(char_x_prime.clone(), Some(char_act.clone()), None);
    let src_col = TrackedCol::new(src_poly.clone(), Some(char_act.clone()), None);
    let ind_col = TrackedCol::new(ind_poly.clone(), None, None);

    BroadcastCheckPIOP::<B>::prove(
        &mut prover,
        BroadcastCheckProverInput {
            str_col,
            char_col,
            src_col,
            ind_col,
        },
    )
    .expect("prove should succeed");

    let proof = prover.build_proof().unwrap();
    verifier.set_proof(proof);

    let str_x_o = verifier.track_mv_com_by_id(str_x.id()).unwrap();
    let char_x_prime_o = verifier.track_mv_com_by_id(char_x_prime.id()).unwrap();
    let src_o = verifier.track_mv_com_by_id(src_poly.id()).unwrap();
    let ind_o = verifier.track_mv_com_by_id(ind_poly.id()).unwrap();
    let char_act_o = verifier.track_mv_com_by_id(char_act.id()).unwrap();

    let str_col_o = TrackedColOracle::new(str_x_o, None, None);
    let char_col_o = TrackedColOracle::new(char_x_prime_o, Some(char_act_o.clone()), None);
    let src_col_o = TrackedColOracle::new(src_o, Some(char_act_o), None);
    let ind_col_o = TrackedColOracle::new(ind_o, None, None);

    BroadcastCheckPIOP::<B>::verify(
        &mut verifier,
        BroadcastCheckVerifierInput {
            str_col_oracle: str_col_o,
            char_col_oracle: char_col_o,
            src_col_oracle: src_col_o,
            ind_col_oracle: ind_col_o,
        },
    )
    .expect("verify should succeed");

    verifier.verify().expect("end-to-end verification should succeed");
}
