#![cfg(feature = "test-utils")]
//! A dishonest prover against the many-to-many join. Each forgery rewrites
//! the join's matching pairs inside the prover ([`JoinForgery`]), and the
//! prover claims the result of the forged join, so the result check passes
//! and only the join's checks can reject:
//! - a dropped pair breaks MatchPair's count;
//! - a duplicated pair (the count kept) breaks the uniqueness of the sources;
//! - a pair of rows with different keys breaks the key equality.
//!
//! The forgery is process-wide, so this binary has a single test.

use std::{fs::File, path::Path};

use datafusion::arrow::{
    array::{Array, ArrayRef, Int64Array},
    compute::concat_batches,
    record_batch::RecordBatch,
};
use datafusion::parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use tt_core::test_utils::dishonest_prover::{JoinForgery, set_claimed_result, set_join_forgery};
use tt_exec::{
    paths::workspace_artifacts_dir,
    prove::{ProveBuilder, ProveOutputs},
    setup::DEFAULT_TEST_LOG_SIZE,
    test_utils::{resolve_key_paths, resolve_oracle_path, resolve_parquet_path, verify_on_thread},
};

/// Row `i` of `nation` has `n_nationkey = i`, so the pairs below are row ids.
const QUERY: &str = "SELECT n1.n_nationkey AS l, n2.n_nationkey AS r \
                     FROM nation n1 JOIN nation n2 ON n1.n_regionkey = n2.n_regionkey";

async fn prove(pk: &Path, oracle: &Path, tag: &str) -> ProveOutputs {
    ProveBuilder::new()
        .with_query(QUERY.to_owned())
        .with_parquet_paths(vec![
            resolve_parquet_path("nation").expect("nation parquet"),
        ])
        .with_oracle_paths(vec![oracle.to_path_buf()])
        .with_pk_path(pk.to_path_buf())
        .with_output_path(Some(
            workspace_artifacts_dir().join(format!("join_forgery.{tag}.{}.pi", std::process::id())),
        ))
        .build()
        .expect("prove builder")
        .run()
        .await
        .expect("the prover runs")
}

fn read_pairs(path: &Path) -> (RecordBatch, Vec<(i64, i64)>) {
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path).unwrap())
        .unwrap()
        .build()
        .unwrap();
    let batches: Vec<RecordBatch> = reader.map(Result::unwrap).collect();
    let batch = concat_batches(&batches[0].schema(), &batches).unwrap();
    let column = |idx: usize| {
        let array = datafusion::arrow::compute::cast(
            batch.column(idx),
            &datafusion::arrow::datatypes::DataType::Int64,
        )
        .unwrap();
        array.as_any().downcast_ref::<Int64Array>().unwrap().clone()
    };
    let (l, r) = (column(0), column(1));
    let pairs = (0..batch.num_rows())
        .map(|i| (l.value(i), r.value(i)))
        .collect();
    (batch, pairs)
}

/// `pairs` as a batch of `template`'s schema.
fn pairs_batch(template: &RecordBatch, pairs: &[(i64, i64)]) -> RecordBatch {
    let column = |values: Vec<i64>, idx: usize| -> ArrayRef {
        datafusion::arrow::compute::cast(
            &Int64Array::from(values),
            template.schema().field(idx).data_type(),
        )
        .unwrap()
    };
    RecordBatch::try_new(
        template.schema(),
        vec![
            column(pairs.iter().map(|p| p.0).collect(), 0),
            column(pairs.iter().map(|p| p.1).collect(), 1),
        ],
    )
    .unwrap()
}

#[tokio::test]
#[cfg_attr(
    feature = "honest-prover",
    ignore = "the honest prover refuses to prove a forgery"
)]
async fn forged_many_to_many_joins_are_rejected() {
    let (pk, vk) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("keys");
    let nation = resolve_parquet_path("nation").expect("nation parquet");
    let oracle = resolve_oracle_path(&nation, &pk)
        .await
        .expect("nation oracle");

    let honest = prove(&pk, &oracle, "honest").await;
    verify_on_thread(
        QUERY,
        vec![oracle.clone()],
        &honest.proof_path,
        &honest.result_path,
        &vk,
    )
    .expect("the honest proof must verify; otherwise the rejections below prove nothing");
    let (template, pairs) = read_pairs(&honest.result_path);
    let first = *pairs.iter().min().unwrap();
    let last = *pairs.iter().max().unwrap();
    assert_eq!((first, last), ((0, 0), (24, 24)));
    let without = |pair: (i64, i64)| -> Vec<(i64, i64)> {
        let mut rest = pairs.clone();
        rest.remove(rest.iter().position(|p| *p == pair).unwrap());
        rest
    };

    // Nation 24 is in region 1, nation 0 in region 0.
    let cases = [
        (JoinForgery::DropFirst, without(first)),
        (
            JoinForgery::DuplicateFirst,
            [without(last), vec![first]].concat(),
        ),
        (
            JoinForgery::MismatchFirst,
            [without(first), vec![(0, 24)]].concat(),
        ),
    ];
    let mut accepted = Vec::new();
    for (forgery, forged_pairs) in cases {
        let claimed = pairs_batch(&template, &forged_pairs);
        let forged = {
            let _forgery = set_join_forgery(forgery);
            let _claimed = set_claimed_result(Box::new(move |_| vec![claimed.clone()]));
            prove(&pk, &oracle, &format!("{forgery:?}")).await
        };
        match verify_on_thread(
            QUERY,
            vec![oracle.clone()],
            &forged.proof_path,
            &forged.result_path,
            &vk,
        ) {
            Ok(()) => accepted.push(forgery),
            Err(reason) => eprintln!("rejected {forgery:?}: {reason}"),
        }
    }
    assert!(accepted.is_empty(), "forged joins verified: {accepted:?}");
}
