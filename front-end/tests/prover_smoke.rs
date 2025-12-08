use std::sync::Arc;

use datafusion::{
    arrow::{
        array::Int64Array,
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    },
    datasource::{MemTable, TableProvider},
    prelude::SessionContext,
};
use front_end::{
    prover::{TTProver, TTProverConfig},
    shared::TTSharedConfig,
};

#[tokio::test]
async fn prove_runs_on_basic_queries() {
    // Build a tiny in-memory table with deterministic data.
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("value", DataType::Int64, true),
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
        ],
    )
    .unwrap();
    let mem_table = MemTable::try_new(schema, vec![vec![batch]]).unwrap();

    let session_ctx = SessionContext::new();
    session_ctx
        .register_table("dummy", Arc::new(mem_table))
        .expect("table registration should succeed");

    // Use a small log size to keep key generation fast in tests.
    let (arg_prover, _verifier) =
        ark_piop::test_utils::prelude_with_vars::<ark_piop::DefaultSnarkBackend>(4)
            .expect("prover prelude should succeed");
    let shared_config = TTSharedConfig::with_defaults(session_ctx);
    let prover_config = TTProverConfig::default();
    let prover = TTProver::new(prover_config, shared_config, arg_prover);

    let queries = [
        "SELECT id, value FROM dummy",
        "SELECT id FROM dummy WHERE id = 1",
    ];

    for query in queries {
        let (mem_table, _proof) = prover.prove(query).await.expect("prove should succeed");
        assert!(
            !mem_table.schema().fields().is_empty(),
            "output schema should not be empty"
        );
    }
}
