//! Tests for `ActivatorConsistencyCheckPIOP`.
//!
//! Layout: 2 strings, 4 characters — string 0 owns chars {0, 1}, string 1
//! owns chars {2, 3}. `ind = [0, 1]`, `src = [0, 0, 1, 1]`. Different tests
//! vary the length column and activators to exercise consistent and
//! inconsistent cases.

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
    ActivatorConsistencyCheckPIOP, ActivatorConsistencyCheckProverInput,
    ActivatorConsistencyCheckVerifierInput,
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const STR_NV: usize = 1;
const CHAR_NV: usize = 2;

fn setup() -> (
    ark_piop::prover::ArgProver<B>,
    ark_piop::verifier::ArgVerifier<B>,
) {
    prelude_with_vars::<B>(4).expect("prelude_with_vars(4) should succeed")
}

fn track_and_commit(
    prover: &mut ark_piop::prover::ArgProver<B>,
    evals: Vec<F>,
    nv: usize,
) -> SnarkResult<ark_piop::prover::structs::polynomial::TrackedPoly<B>> {
    prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(nv, evals))
}

/// Fixed src/ind vectors: 4 chars, string 0 owns {0,1}, string 1 owns {2,3}.
fn fixed_src_evals() -> Vec<F> {
    vec![F::from(0u64), F::from(0u64), F::from(1u64), F::from(1u64)]
}
fn fixed_ind_evals() -> Vec<F> {
    vec![F::from(0u64), F::from(1u64)]
}

/// Runs the full prove + verify pipeline with the given per-string length,
/// char activator, and string activator. `None` for an activator means "no
/// activator" (all rows active).
#[allow(clippy::type_complexity)]
fn run_pipeline(
    length_evals: Vec<F>,
    char_act_evals: Option<Vec<F>>,
    str_act_evals: Option<Vec<F>>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = setup();

    let src = track_and_commit(&mut prover, fixed_src_evals(), CHAR_NV)?;
    let ind = track_and_commit(&mut prover, fixed_ind_evals(), STR_NV)?;
    let length = track_and_commit(&mut prover, length_evals, STR_NV)?;
    let char_act = match char_act_evals {
        Some(v) => Some(track_and_commit(&mut prover, v, CHAR_NV)?),
        None => None,
    };
    let str_act = match str_act_evals {
        Some(v) => Some(track_and_commit(&mut prover, v, STR_NV)?),
        None => None,
    };

    let src_col = TrackedCol::new(src.clone(), char_act.clone(), None);
    let ind_col = TrackedCol::new(ind.clone(), str_act.clone(), None);

    ActivatorConsistencyCheckPIOP::<B>::prove(
        &mut prover,
        ActivatorConsistencyCheckProverInput {
            src_col,
            ind_col,
            length_poly: length.clone(),
        },
    )?;

    let proof = prover.build_proof()?;
    verifier.set_proof(proof);

    let src_o = verifier.track_mv_com_by_id(src.id())?;
    let ind_o = verifier.track_mv_com_by_id(ind.id())?;
    let length_o = verifier.track_mv_com_by_id(length.id())?;
    let char_act_o = match char_act {
        Some(p) => Some(verifier.track_mv_com_by_id(p.id())?),
        None => None,
    };
    let str_act_o = match str_act {
        Some(p) => Some(verifier.track_mv_com_by_id(p.id())?),
        None => None,
    };

    let src_col_o = TrackedColOracle::new(src_o, char_act_o, None);
    let ind_col_o = TrackedColOracle::new(ind_o, str_act_o, None);

    ActivatorConsistencyCheckPIOP::<B>::verify(
        &mut verifier,
        ActivatorConsistencyCheckVerifierInput {
            src_col_oracle: src_col_o,
            ind_col_oracle: ind_col_o,
            length_oracle: length_o,
        },
    )?;

    verifier.verify()?;
    Ok(())
}

#[test]
fn consistent_no_activators() {
    // 2 chars per string, all active. length = [2, 2].
    let length = vec![F::from(2u64), F::from(2u64)];
    run_pipeline(length, None, None).expect("consistent inputs should verify");
}

#[test]
fn consistent_char_activator_deactivates_one() {
    // Deactivate char 3 (owned by string 1). Expected length: string 0 → 2,
    // string 1 → 1. Use a mixed activator so neither side folds to a constant.
    let length = vec![F::from(2u64), F::from(1u64)];
    let char_act = Some(vec![
        F::from(1u64),
        F::from(1u64),
        F::from(1u64),
        F::from(0u64),
    ]);
    run_pipeline(length, char_act, None).expect("consistent w/ char activator should verify");
}

#[test]
fn wrong_length_rejected() {
    // Actual char count for each string is 2. Claim length = [2, 3].
    let length = vec![F::from(2u64), F::from(3u64)];
    assert!(
        run_pipeline(length, None, None).is_err(),
        "length overstatement must not verify"
    );
}

#[test]
fn understated_length_rejected() {
    // Understated: actual = 2 per string, claim = [1, 2].
    let length = vec![F::from(1u64), F::from(2u64)];
    assert!(
        run_pipeline(length, None, None).is_err(),
        "length understatement must not verify"
    );
}

#[test]
fn inactive_string_ignores_length() {
    // String 1 is inactive: its l value should not contribute regardless.
    // Char activator masks off chars 2 and 3 so the LHS also excludes them.
    // Length[1] can be anything (say 999) and the check should still pass.
    let length = vec![F::from(2u64), F::from(999u64)];
    let char_act = Some(vec![
        F::from(1u64),
        F::from(1u64),
        F::from(0u64),
        F::from(0u64),
    ]);
    let str_act = Some(vec![F::from(1u64), F::from(0u64)]);
    run_pipeline(length, char_act, str_act)
        .expect("inactive string with masked chars should verify regardless of length");
}

#[test]
fn inactive_string_with_active_chars_rejected() {
    // String 1 is inactive (RHS multiplicity 0) but its chars are still
    // active on the LHS (chars 2 & 3 → count 2 for key=1). LHS != RHS.
    let length = vec![F::from(2u64), F::from(2u64)];
    let str_act = Some(vec![F::from(1u64), F::from(0u64)]);
    assert!(
        run_pipeline(length, None, str_act).is_err(),
        "inactive string with active chars must not verify"
    );
}
