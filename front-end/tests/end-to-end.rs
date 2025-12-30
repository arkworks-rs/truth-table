use std::sync::Arc;

use arithmetic::ACTIVATOR_COL_NAME;
use datafusion::{
    arrow::{
        array::{BooleanArray, Int64Array},
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    },
    datasource::MemTable,
    prelude::SessionContext,
};
use front_end::{
    prover::{TTProver, TTProverConfig},
    shared::TTSharedConfig,
    verifier::{TTVerifier, TTVerifierConfig},
};
type Backend = ark_piop::DefaultSnarkBackend;
use datafusion::datasource::TableProvider;
#[tokio::test]
async fn end_to_end() {
    // Build a tiny in-memory table with deterministic data.
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("value", DataType::Int64, true),
        Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![1, 2, 3, 4])),
            Arc::new(Int64Array::from(vec![
                Some(10),
                Some(20),
                Some(30),
                Some(40),
            ])),
            Arc::new(BooleanArray::from(vec![true, true, true, true])),
        ],
    )
    .unwrap();
    let mem_table = Arc::new(MemTable::try_new(schema, vec![vec![batch]]).unwrap());

    let queries = [
        "SELECT id, value FROM dummy",
        "SELECT id FROM dummy WHERE id = 1",
    ];

    for query in queries {
        let prover_ctx = SessionContext::new();
        prover_ctx
            .register_table("dummy", mem_table.clone())
            .expect("table registration should succeed");
        let verifier_ctx = SessionContext::new();
        verifier_ctx
            .register_table("dummy", mem_table.clone())
            .expect("table registration should succeed");

        // Use a small log size to keep key generation fast in tests.
        let (arg_prover, arg_verifier) = ark_piop::test_utils::prelude_with_vars::<Backend>(4)
            .expect("prover prelude should succeed");
        let prover_shared_config: TTSharedConfig<Backend> =
            TTSharedConfig::with_defaults(prover_ctx);
        let verifier_shared_config: TTSharedConfig<Backend> =
            TTSharedConfig::with_defaults(verifier_ctx);
        let prover_config = TTProverConfig::default();
        let prover = TTProver::new(prover_config, prover_shared_config, arg_prover);
        let verifier_config = TTVerifierConfig::default();
        let verifier = TTVerifier::new(verifier_config, verifier_shared_config, arg_verifier);

        let (output_table, proof) = prover.prove(query).await.expect("prove should succeed");
        assert!(
            !output_table.schema().fields().is_empty(),
            "output schema should not be empty"
        );

        verifier
            .verify(query, proof)
            .await
            .expect("verifier should verify proof");
    }
}
