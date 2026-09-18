//! ResultCheck binds committed internal rows to a verifier-owned public table.
//! These tests exercise bag equality, not ordered result equality. Public R
//! uses evaluable local oracles rather than another proof-owned commitment.
//! A proof is nevertheless bound to one exact arithmetized public encoding:
//! reordering the statement requires a fresh proof even though that fresh proof
//! is valid. The production boundary rejects public NULLs because validity
//! columns are not yet part of that encoding. These are field-encoding tests;
//! general SQL-value equality additionally requires a NULL-free internal query
//! pipeline until internal validity columns are authenticated.

use std::sync::Arc;

use arithmetic::{ACTIVATOR_FIELD, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    prover::{
        ArgProver,
        errors::{HonestProverError, ProverError},
        structs::proof::SNARKProof,
    },
    test_utils::prelude_with_vars,
    types::TrackerID,
    verifier::{ArgVerifier, structs::oracle::Oracle},
};
use ark_poly::Polynomial;
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use indexmap::IndexMap;

use super::{
    RESULT_CHECK_MAX_CHALLENGE_FIELD_BITS, RESULT_CHECK_SECURITY_BITS,
    has_result_check_security_margin, prove_result_check, public_evaluations, verify_result_check,
};

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

#[test]
fn security_margin_boundary_is_strict_and_checked() {
    let capacity_bits = 10usize;
    let required = capacity_bits + RESULT_CHECK_SECURITY_BITS + 2;
    assert!(has_result_check_security_margin(
        required + 1,
        capacity_bits,
        capacity_bits
    ));
    assert!(!has_result_check_security_margin(
        required,
        capacity_bits,
        capacity_bits
    ));
    assert!(!has_result_check_security_margin(usize::MAX, usize::MAX, 0));
    assert!(has_result_check_security_margin(
        RESULT_CHECK_MAX_CHALLENGE_FIELD_BITS,
        capacity_bits,
        capacity_bits
    ));
    assert!(!has_result_check_security_margin(
        RESULT_CHECK_MAX_CHALLENGE_FIELD_BITS + 1,
        capacity_bits,
        capacity_bits
    ));
}

#[derive(Clone)]
struct Table {
    data: Vec<Vec<u64>>,
    active: Vec<u64>,
}

impl Table {
    fn new(data: &[&[u64]], active: &[u64]) -> Self {
        assert!(active.len().is_power_of_two());
        assert!(data.iter().all(|column| column.len() == active.len()));
        Self {
            data: data.iter().map(|column| column.to_vec()).collect(),
            active: active.to_vec(),
        }
    }

    fn nv(&self) -> usize {
        self.active.len().ilog2() as usize
    }

    fn columns(&self) -> Vec<(FieldRef, MLE<F>)> {
        let mut columns: Vec<_> = self
            .data
            .iter()
            .enumerate()
            .map(|(index, values)| {
                (
                    Arc::new(Field::new(
                        format!("column_{index}"),
                        DataType::UInt64,
                        false,
                    )),
                    self.polynomial(values),
                )
            })
            .collect();
        columns.push((ACTIVATOR_FIELD.clone(), self.polynomial(&self.active)));
        columns
    }

    fn polynomial(&self, values: &[u64]) -> MLE<F> {
        MLE::from_evaluations_vec(self.nv(), values.iter().copied().map(F::from).collect())
    }
}

struct Fixture {
    proof: SNARKProof<B>,
    verifier: ArgVerifier<B>,
    input: Table,
    input_ids: Vec<TrackerID>,
    public_ids: Vec<TrackerID>,
}

fn prover_table(
    prover: &mut ArgProver<B>,
    table: &Table,
    is_public: bool,
) -> SnarkResult<(TrackedTable<B>, Vec<TrackerID>)> {
    let mut polys = IndexMap::new();
    let mut ids = Vec::new();
    for (field, polynomial) in table.columns() {
        let tracked = if is_public {
            prover.track_mat_mv_poly(polynomial)
        } else {
            prover.track_and_commit_mat_mv_poly(&polynomial)?
        };
        ids.push(tracked.id());
        polys.insert(field, tracked);
    }
    let schema = Schema::new(polys.keys().cloned().collect::<Vec<_>>());
    Ok((TrackedTable::new(Some(schema), polys, table.nv()), ids))
}

impl Fixture {
    fn prove(input: &Table, public: &Table) -> SnarkResult<Self> {
        let (mut prover, verifier) = prelude_with_vars::<B>(6)?;
        let (t_table, input_ids) = prover_table(&mut prover, input, false)?;
        let (r_table, public_ids) = prover_table(&mut prover, public, true)?;
        // Deliberately do not invoke ResultCheck::honest_prover_check: these
        // regressions must exercise the actual proof/verifier obligations.
        prove_result_check(&mut prover, &t_table, &r_table)?;
        let proof = prover.build_proof()?;
        Ok(Self {
            proof,
            verifier,
            input: input.clone(),
            input_ids,
            public_ids,
        })
    }

    fn prepare_verifier(
        &self,
        public: &Table,
    ) -> SnarkResult<(ArgVerifier<B>, TrackedTableOracle<B>, TrackedTableOracle<B>)> {
        let mut verifier = self.verifier.fork();
        verifier.set_proof(self.proof.clone());
        let mut input_oracles = IndexMap::new();
        for ((field, _), expected_id) in self.input.columns().into_iter().zip(&self.input_ids) {
            let oracle = verifier.track_next_mv_com()?;
            assert_eq!(
                oracle.id(),
                *expected_id,
                "input tracking must match prover"
            );
            input_oracles.insert(field, oracle);
        }
        let input_schema = Schema::new(input_oracles.keys().cloned().collect::<Vec<_>>());
        let t_table = TrackedTableOracle::new(Some(input_schema), input_oracles, self.input.nv());

        assert_eq!(public.data.len() + 1, self.public_ids.len());
        let mut public_oracles = IndexMap::new();
        for ((field, polynomial), expected_id) in public.columns().into_iter().zip(&self.public_ids)
        {
            let nv = public.nv();
            let oracle = verifier.track_base_oracle(Oracle::new_multivariate(
                nv,
                move |mut point: Vec<F>| {
                    // The final argument may query at a different global proof
                    // width. Ignore extra variables and set missing variables
                    // to zero, matching the production local-oracle adapter.
                    point.resize(nv, F::from(0_u64));
                    Ok(polynomial.evaluate(&point[..nv].to_vec()))
                },
            ));
            assert_eq!(
                oracle.id(),
                *expected_id,
                "public tracking must match prover"
            );
            public_oracles.insert(field, oracle);
        }
        let public_schema = Schema::new(public_oracles.keys().cloned().collect::<Vec<_>>());
        let r_table = TrackedTableOracle::new(Some(public_schema), public_oracles, public.nv());
        Ok((verifier, t_table, r_table))
    }

    fn verify(&self, public: &Table) -> SnarkResult<()> {
        let (mut verifier, t_table, r_table) = self.prepare_verifier(public)?;
        verify_result_check(&mut verifier, &t_table, &r_table)?;
        verifier.verify()
    }
}

#[test]
fn proof_owned_commitment_cannot_be_used_as_public_output() -> SnarkResult<()> {
    let input = Table::new(&[&[1, 2, 3, 4]], &[1, 1, 1, 1]);
    let fixture = Fixture::prove(&input, &input)?;
    let mut verifier = fixture.verifier.fork();
    verifier.set_proof(fixture.proof);

    // The first input column is a prover commitment. A low-level caller must
    // not be able to relabel it as a verifier-owned public-result oracle.
    let committed = verifier.track_next_mv_com()?;
    assert!(public_evaluations(&committed, input.nv()).is_err());
    Ok(())
}

#[test]
fn fresh_proof_for_reordered_public_bag_verifies() -> SnarkResult<()> {
    let input = Table::new(&[&[1, 2, 1, 3], &[10, 20, 10, 30]], &[1, 1, 1, 1]);
    let public = Table::new(&[&[3, 1, 2, 1], &[30, 10, 20, 10]], &[1, 1, 1, 1]);
    Fixture::prove(&input, &public)?.verify(&public)
}

#[test]
fn constant_valued_public_base_oracles_verify() -> SnarkResult<()> {
    let input = Table::new(&[&[7, 7, 7, 7]], &[1, 1, 1, 1]);
    Fixture::prove(&input, &input)?.verify(&input)
}

#[test]
fn compatibility_anchor_cannot_make_a_false_constant_result_pass() -> SnarkResult<()> {
    let input = Table::new(&[&[7, 7, 7, 7]], &[1, 1, 1, 1]);
    let public = Table::new(&[&[8, 8, 8, 8]], &[1, 1, 1, 1]);
    // This reaches the all-constant path, which emits the compatibility
    // commitment before comparing the verifier-computed target. The anchor is
    // valid, but because it is not an input to that comparison it cannot make
    // the false public bag acceptable. The same remains true for any other
    // nonconstant log-size-one anchor whose independently checked sum is one.
    match Fixture::prove(&input, &public) {
        Err(error) => {
            assert!(matches!(
                error,
                SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim
                )) | SnarkError::VerifierError(_)
            ));
            Ok(())
        }
        Ok(fixture) => {
            assert!(fixture.verify(&public).is_err());
            Ok(())
        }
    }
}

#[test]
fn same_proof_cannot_change_public_row_order() -> SnarkResult<()> {
    let input = Table::new(&[&[1, 2, 3, 4]], &[1, 1, 1, 1]);
    let fixture = Fixture::prove(&input, &input)?;
    fixture.verify(&input)?;
    let reordered = Table::new(&[&[4, 3, 2, 1]], &[1, 1, 1, 1]);
    assert!(fixture.verify(&reordered).is_err());
    Ok(())
}

#[test]
fn non_boolean_internal_activator_is_rejected() -> SnarkResult<()> {
    let input = Table::new(&[&[1, 2]], &[2, 0]);
    let public = Table::new(&[&[1, 2]], &[1, 1]);
    match Fixture::prove(&input, &public) {
        Err(error) => {
            assert!(matches!(
                error,
                SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim
                )) | SnarkError::VerifierError(_)
            ));
            Ok(())
        }
        Ok(fixture) => {
            assert!(fixture.verify(&public).is_err());
            Ok(())
        }
    }
}

#[test]
fn sparse_input_and_different_public_capacity_verify() -> SnarkResult<()> {
    let input = Table::new(
        &[&[1, 999, 2, 888, 1, 777, 3, 666]],
        &[1, 0, 1, 0, 1, 0, 1, 0],
    );
    let public = Table::new(&[&[3, 1, 2, 1]], &[1, 1, 1, 1]);
    Fixture::prove(&input, &public)?.verify(&public)
}

#[test]
fn inactive_public_payload_is_not_a_bag_member() -> SnarkResult<()> {
    let input = Table::new(&[&[1, 90, 2, 80]], &[1, 0, 1, 0]);
    let public = Table::new(&[&[70, 2, 60, 1]], &[0, 1, 0, 1]);
    Fixture::prove(&input, &public)?.verify(&public)
}

#[test]
fn empty_bags_verify_despite_unrelated_padding() -> SnarkResult<()> {
    let input = Table::new(&[&[91, 92, 93, 94]], &[0, 0, 0, 0]);
    let public = Table::new(&[&[81, 82]], &[0, 0]);
    Fixture::prove(&input, &public)?.verify(&public)
}

#[test]
fn empty_internal_bag_cannot_certify_a_nonempty_public_bag() -> SnarkResult<()> {
    let input = Table::new(&[&[91, 92]], &[0, 0]);
    let public = Table::new(&[&[91, 92]], &[1, 0]);
    match Fixture::prove(&input, &public) {
        Err(error) => {
            assert!(matches!(
                error,
                SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim
                )) | SnarkError::VerifierError(_)
            ));
            Ok(())
        }
        Ok(fixture) => {
            assert!(fixture.verify(&public).is_err());
            Ok(())
        }
    }
}

#[test]
fn same_proof_cannot_verify_a_changed_public_value() -> SnarkResult<()> {
    let input = Table::new(&[&[1, 2, 3, 4]], &[1, 1, 1, 1]);
    let fixture = Fixture::prove(&input, &input)?;
    fixture.verify(&input)?;
    let changed = Table::new(&[&[1, 2, 3, 99]], &[1, 1, 1, 1]);
    assert!(fixture.verify(&changed).is_err());
    Ok(())
}

#[test]
fn same_proof_cannot_change_duplicate_multiplicities() -> SnarkResult<()> {
    let input = Table::new(&[&[1, 1, 2, 3]], &[1, 1, 1, 1]);
    let fixture = Fixture::prove(&input, &input)?;
    fixture.verify(&input)?;
    let changed = Table::new(&[&[1, 2, 2, 3]], &[1, 1, 1, 1]);
    assert!(fixture.verify(&changed).is_err());
    Ok(())
}

#[test]
fn same_proof_cannot_drop_an_active_public_row() -> SnarkResult<()> {
    let input = Table::new(&[&[1, 2, 3, 4]], &[1, 1, 1, 1]);
    let fixture = Fixture::prove(&input, &input)?;
    fixture.verify(&input)?;
    let changed = Table::new(&[&[1, 2, 3, 4]], &[1, 1, 1, 0]);
    assert!(fixture.verify(&changed).is_err());
    Ok(())
}

#[test]
fn false_public_statement_is_not_certified_by_internal_rows() -> SnarkResult<()> {
    let input = Table::new(&[&[1, 1, 2, 3]], &[1, 1, 1, 1]);
    // A positive control rules out a general fixture/tracker failure.
    Fixture::prove(&input, &input)?.verify(&input)?;
    let false_public = Table::new(&[&[1, 2, 2, 3]], &[1, 1, 1, 1]);
    match Fixture::prove(&input, &false_public) {
        Err(error) => {
            // Honest-prover mode may reject the false sum at construction.
            // Other setup/build failures must not make this regression pass.
            assert!(matches!(
                error,
                SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim
                ))
            ));
        }
        Ok(fixture) => {
            let (mut verifier, t_table, r_table) = fixture.prepare_verifier(&false_public)?;
            // Unlike the same-proof mutation tests, the public digest matches:
            // only the algebraic multiset relation should reject this proof.
            verify_result_check(&mut verifier, &t_table, &r_table)?;
            assert!(verifier.verify().is_err());
        }
    }
    Ok(())
}
