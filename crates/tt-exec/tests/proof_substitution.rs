#![cfg(feature = "test-utils")]

//! A proof must verify only for the query and claimed result it was produced
//! for. Each case below hands the verifier an honestly generated proof paired
//! with a different query, a different claimed result, or a different table,
//! and requires the verifier not to accept. An honest pairing is checked first
//! so a rejection cannot come from a broken harness.
//!
//! A verifier panic counts as a rejection: this test is about soundness, not
//! about how cleanly a mismatch is reported.

use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
};

use datafusion::arrow::{
    array::{ArrayRef, UInt32Array},
    compute::{concat_batches, take},
    datatypes::Schema,
    record_batch::RecordBatch,
};
use datafusion::parquet::arrow::{ArrowWriter, arrow_reader::ParquetRecordBatchReaderBuilder};

use tt_exec::{
    paths::workspace_artifacts_dir,
    prove::{ProveBuilder, ProveOutputs},
    setup::DEFAULT_TEST_LOG_SIZE,
    test_utils::{resolve_key_paths, resolve_oracle_path, resolve_parquet_path},
    verify::VerifyBuilder,
};

const REGION_1: &str = "SELECT n_name FROM nation WHERE n_regionkey = 1";
// Same plan shape and the same number of matching rows as `REGION_1`.
const REGION_3: &str = "SELECT n_name FROM nation WHERE n_regionkey = 3";
const LOW_KEYS: &str = "SELECT n_name FROM nation WHERE n_nationkey < 5";
const REGION_TABLE: &str = "SELECT r_name FROM region WHERE r_regionkey = 1";
const TWO_COLUMNS: &str = "SELECT n_nationkey, n_name FROM nation WHERE n_nationkey < 5";
const NO_ROWS: &str = "SELECT n_name FROM nation WHERE n_regionkey = 9";

async fn oracle_paths(tables: &[&str], pk: &Path) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut parquets = Vec::new();
    let mut oracles = Vec::new();
    for table in tables {
        let parquet = resolve_parquet_path(table).expect("test parquet");
        oracles.push(
            resolve_oracle_path(&parquet, pk)
                .await
                .expect("table oracle"),
        );
        parquets.push(parquet);
    }
    (parquets, oracles)
}

async fn prove(query: &str, tables: &[&str], pk: &Path, tag: &str) -> ProveOutputs {
    let (parquets, oracles) = oracle_paths(tables, pk).await;
    let output = workspace_artifacts_dir().join(format!(
        "proof_substitution.{tag}.{}.pi",
        std::process::id()
    ));
    ProveBuilder::new()
        .with_query(query.to_owned())
        .with_parquet_paths(parquets)
        .with_oracle_paths(oracles)
        .with_pk_path(pk.to_path_buf())
        .with_output_path(Some(output))
        .build()
        .expect("prove builder")
        .run()
        .await
        .unwrap_or_else(|e| panic!("honest proof for `{query}` failed: {e:#}"))
}

enum Outcome {
    Accepted,
    Rejected(String),
}

/// Verifies on a fresh thread with its own runtime so a verifier panic is
/// observed as a rejection instead of aborting the test.
fn verify(query: &str, oracles: Vec<PathBuf>, proof: &ProveOutputs, vk: &Path) -> Outcome {
    verify_with_result(query, oracles, &proof.proof_path, &proof.result_path, vk)
}

fn verify_with_result(
    query: &str,
    oracles: Vec<PathBuf>,
    proof_path: &Path,
    result_path: &Path,
    vk: &Path,
) -> Outcome {
    let query = query.to_owned();
    let (proof_path, result_path, vk) = (
        proof_path.to_path_buf(),
        result_path.to_path_buf(),
        vk.to_path_buf(),
    );
    let joined = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("verifier runtime")
            .block_on(async move {
                VerifyBuilder::new()
                    .with_query(query)
                    .with_oracle_paths(oracles)
                    .with_proof_path(proof_path)
                    .with_result_path(result_path)
                    .with_vk_path(vk)
                    .build()?
                    .run()
                    .await
            })
    })
    .join();
    match joined {
        Ok(Ok(())) => Outcome::Accepted,
        Ok(Err(e)) => Outcome::Rejected(format!("error: {e:#}")),
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("<non-string panic>");
            Outcome::Rejected(format!("panic: {msg}"))
        }
    }
}

#[tokio::test]
async fn substituted_proofs_are_rejected() {
    let (pk, vk) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("keys");
    let (_, nation) = oracle_paths(&["nation"], &pk).await;

    let region_1 = prove(REGION_1, &["nation"], &pk, "region_1").await;
    let region_3 = prove(REGION_3, &["nation"], &pk, "region_3").await;
    let low_keys = prove(LOW_KEYS, &["nation"], &pk, "low_keys").await;
    let region_table = prove(REGION_TABLE, &["region"], &pk, "region_table").await;

    assert!(
        matches!(
            verify(REGION_1, nation.clone(), &region_1, &vk),
            Outcome::Accepted
        ),
        "honest proof for `{REGION_1}` must verify; otherwise the rejections below prove nothing"
    );

    let cases = [
        (
            "proof and result of a different literal",
            verify(REGION_3, nation.clone(), &region_1, &vk),
        ),
        (
            "honest proof with another query's result",
            verify_with_result(
                REGION_3,
                nation.clone(),
                &region_3.proof_path,
                &region_1.result_path,
                &vk,
            ),
        ),
        (
            "proof of a differently shaped query",
            verify(LOW_KEYS, nation.clone(), &region_1, &vk),
        ),
        (
            "proof of a query over another table",
            verify(REGION_1, nation.clone(), &region_table, &vk),
        ),
        (
            "proof of a differently shaped query, reversed",
            verify(REGION_1, nation.clone(), &low_keys, &vk),
        ),
    ];

    let mut accepted = Vec::new();
    for (name, outcome) in &cases {
        match outcome {
            Outcome::Accepted => {
                eprintln!("ACCEPTED  {name}");
                accepted.push(*name);
            }
            Outcome::Rejected(reason) => eprintln!("rejected  {name}: {reason}"),
        }
    }
    assert!(
        accepted.is_empty(),
        "verifier accepted substituted proofs: {accepted:?}"
    );
}

/// A query that the pre-filter narrows: the proof carries the commitments of
/// the fingerprint bins it tests, opened against the oracle's Merkle roots.
const PREFILTERED: &str =
    "SELECT l_returnflag FROM lineitem WHERE l_comment LIKE '%quickly%xylophone%'";

/// Rewrite the proof at `from` with its fingerprint openings replaced by
/// `forge(openings)`, into a sibling file tagged `tag`.
fn forge_openings(from: &Path, tag: &str, forge: impl FnOnce(&mut Vec<Vec<[u8; 32]>>)) -> PathBuf {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use front_end::structs::{Artifact, TTProof};
    let proof = TTProof::<tt_exec::backend::BenchBackend>::load(from).expect("load proof");
    let mut raw = Vec::new();
    proof
        .serialize_compressed(&mut raw)
        .expect("serialize proof");
    // The openings are the last field of the serialized proof.
    let mut openings = proof.fingerprint_openings().clone();
    raw.truncate(raw.len() - openings.compressed_size());
    forge(&mut openings);
    openings
        .serialize_compressed(&mut raw)
        .expect("serialize openings");
    let forged = TTProof::<tt_exec::backend::BenchBackend>::deserialize_compressed(&raw[..])
        .expect("forged proof parses");
    let path = from.with_extension(format!("{tag}.pi"));
    forged.save(&path).expect("save forged proof");
    path
}

#[tokio::test]
async fn forged_fingerprint_openings_are_rejected() {
    let (pk, vk) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("keys");
    let (_, lineitem) = oracle_paths(&["lineitem"], &pk).await;
    let honest = prove(PREFILTERED, &["lineitem"], &pk, "prefiltered").await;

    let openings = {
        use front_end::structs::{Artifact, TTProof};
        TTProof::<tt_exec::backend::BenchBackend>::load(&honest.proof_path)
            .expect("load proof")
            .fingerprint_openings()
            .clone()
    };
    assert!(
        !openings.is_empty(),
        "`{PREFILTERED}` must open fingerprint bins, or this test checks nothing"
    );
    assert!(
        matches!(
            verify(PREFILTERED, lineitem.clone(), &honest, &vk),
            Outcome::Accepted
        ),
        "honest pre-filtered proof must verify; otherwise the rejections below prove nothing"
    );

    let forgeries = [
        (
            "a sibling hash altered",
            forge_openings(&honest.proof_path, "flipped", |o| {
                let last = o
                    .iter_mut()
                    .rev()
                    .find(|s| !s.is_empty())
                    .expect("a sibling");
                last[0][0] ^= 1;
            }),
        ),
        (
            "a sibling hash dropped",
            forge_openings(&honest.proof_path, "short", |o| {
                o.iter_mut()
                    .rev()
                    .find(|s| !s.is_empty())
                    .expect("a sibling")
                    .pop();
            }),
        ),
        (
            "no openings at all",
            forge_openings(&honest.proof_path, "none", Vec::clear),
        ),
    ];
    let mut accepted = Vec::new();
    for (name, path) in &forgeries {
        match verify_with_result(
            PREFILTERED,
            lineitem.clone(),
            path,
            &honest.result_path,
            &vk,
        ) {
            Outcome::Accepted => {
                eprintln!("ACCEPTED  {name}");
                accepted.push(*name);
            }
            Outcome::Rejected(reason) => eprintln!("rejected  {name}: {reason}"),
        }
    }
    assert!(
        accepted.is_empty(),
        "verifier accepted forged fingerprint openings: {accepted:?}"
    );
}

fn read_result(path: &Path) -> RecordBatch {
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path).expect("open result"))
        .expect("result parquet")
        .build()
        .expect("result reader");
    let batches: Vec<RecordBatch> = reader.collect::<Result<_, _>>().expect("result batches");
    concat_batches(&batches[0].schema(), &batches).expect("concat result")
}

fn write_result(batch: &RecordBatch, tag: &str) -> PathBuf {
    let path = workspace_artifacts_dir().join(format!(
        "proof_substitution.{tag}.{}.result.parquet",
        std::process::id()
    ));
    let mut writer = ArrowWriter::try_new(
        File::create(&path).expect("create result"),
        batch.schema(),
        None,
    )
    .expect("result writer");
    writer.write(batch).expect("write result");
    writer.close().expect("close result");
    path
}

/// Rebuilds `batch` taking, for column `i`, the rows listed in `rows[i]`.
fn take_rows(batch: &RecordBatch, rows: &[&[u32]]) -> RecordBatch {
    let columns: Vec<ArrayRef> = batch
        .columns()
        .iter()
        .zip(rows)
        .map(|(column, rows)| take(column, &UInt32Array::from(rows.to_vec()), None).expect("take"))
        .collect();
    RecordBatch::try_new(batch.schema(), columns).expect("tampered result")
}

/// Claimed results derived from an honest one. A proof commits to the exact
/// result file it was produced with, so the honest file (or an unchanged
/// rewrite of it) must verify and any change to its rows or columns must not.
#[tokio::test]
async fn tampered_results_are_rejected() {
    let (pk, vk) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("keys");
    let (_, nation) = oracle_paths(&["nation"], &pk).await;

    let honest = prove(TWO_COLUMNS, &["nation"], &pk, "two_columns").await;
    let rows = read_result(&honest.result_path);
    assert_eq!(rows.num_rows(), 5, "fixture expects five result rows");
    let check = |result: &Path| {
        verify_with_result(TWO_COLUMNS, nation.clone(), &honest.proof_path, result, &vk)
    };

    let identity: &[u32] = &[0, 1, 2, 3, 4];
    let accepted = [
        ("honest result", honest.result_path.clone()),
        (
            "honest rows rewritten unchanged",
            write_result(&take_rows(&rows, &[identity, identity]), "rewritten"),
        ),
    ];
    for (name, result) in &accepted {
        if let Outcome::Rejected(reason) = check(result) {
            panic!("{name} must verify: {reason}");
        }
    }

    let mut extra_columns: Vec<ArrayRef> = rows.columns().to_vec();
    extra_columns.push(rows.column(0).clone());
    let mut extra_fields: Vec<_> = rows.schema().fields().iter().cloned().collect();
    extra_fields.push(Arc::new(rows.schema().field(0).clone().with_name("extra")));
    let extra = RecordBatch::try_new(Arc::new(Schema::new(extra_fields)), extra_columns)
        .expect("extra column result");

    let rejected = [
        (
            "values swapped between rows in one column",
            take_rows(&rows, &[identity, &[1, 0, 2, 3, 4]]),
        ),
        (
            "a row dropped",
            take_rows(&rows, &[&[0, 1, 2, 3], &[0, 1, 2, 3]]),
        ),
        (
            "a row replaced by a copy of another",
            take_rows(&rows, &[&[0, 0, 2, 3, 4], &[0, 0, 2, 3, 4]]),
        ),
        ("an extra column", extra),
    ];
    let mut wrongly_accepted = Vec::new();
    for (i, (name, batch)) in rejected.iter().enumerate() {
        match check(&write_result(batch, &format!("tampered{i}"))) {
            Outcome::Accepted => {
                eprintln!("ACCEPTED  {name}");
                wrongly_accepted.push(*name);
            }
            Outcome::Rejected(reason) => eprintln!("rejected  {name}: {reason}"),
        }
    }
    assert!(
        wrongly_accepted.is_empty(),
        "verifier accepted tampered results: {wrongly_accepted:?}"
    );
}

/// A query with no matching rows exercises the smallest result domain.
#[tokio::test]
async fn empty_result_verifies() {
    let (pk, vk) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("keys");
    let (_, nation) = oracle_paths(&["nation"], &pk).await;
    let proof = prove(NO_ROWS, &["nation"], &pk, "no_rows").await;
    match verify(NO_ROWS, nation, &proof, &vk) {
        Outcome::Accepted => {}
        Outcome::Rejected(reason) => panic!("honest empty result must verify: {reason}"),
    }
}
