#![cfg(feature = "test-utils")]

//! Ranks (`c__rank`, TruthTable++ §3.2) are committed by the data owner for
//! every string column and loaded at a table scan only for the columns
//! `Tree::required_rank_columns` names, so a query without a string sort
//! key loads none.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use arithmetic::encoding::STRING_RANK_SUFFIX;
use arithmetic::table_oracle::ArithTableOracle;
use ark_piop::{SnarkBackend, arithmetic::mat_poly::mle::MLE, pcs::PCS, prover::ArgProver};
use ark_serialize::CanonicalDeserialize;
use datafusion::prelude::ParquetReadOptions;
use front_end::shared::TTSharedConfig;
use front_end::structs::{Artifact, TTPk};
use indexmap::IndexMap;
use tt_core::ctx_oracles::CtxOracles;
use tt_core::irs::nodes::IsNode;
use tt_core::irs::nodes::hints::configure_constraint_metadata_from_parquet_paths;
use tt_core::irs::shared_ir::EmptyIr;
use tt_core::prover::passes::{
    arithmetization::{ArithmetizationPass, FingerprintColumns, RankColumns, SideColumns},
    gadget_planning::GadgetPlanningPass,
    materialization::MaterializationPass,
    output_planning::OutputPlanningPass,
};
use tt_core::prover::payloads::ArithPayload;
use tt_core::session::session_context;
use tt_exec::backend::BenchBackend;
use tt_exec::setup::DEFAULT_TEST_LOG_SIZE;
use tt_exec::test_utils::{resolve_key_paths, resolve_oracle_path, resolve_parquet_path};

type B = BenchBackend;
type F = <B as SnarkBackend>::F;

/// The query's IR after the planning the prover and the verifier share.
/// Each `(name, table)` of `copies` registers `table`'s data as table `name`.
async fn initial_ir(sql: &str, tables: &[&str], copies: &[(&str, &str)]) -> EmptyIr<B> {
    let ctx = session_context();
    let mut paths = Vec::new();
    let registrations = tables.iter().map(|table| (*table, *table));
    for (name, table) in registrations.chain(copies.iter().copied()) {
        let path = resolve_parquet_path(table).expect("test parquet for table");
        ctx.register_parquet(
            name,
            path.to_str().expect("parquet path must be valid UTF-8"),
            ParquetReadOptions::default(),
        )
        .await
        .expect("register parquet table");
        paths.push(path);
    }
    configure_constraint_metadata_from_parquet_paths(&paths);
    let shared = TTSharedConfig::<B>::with_defaults(ctx);
    let lp = shared.query_to_lp(sql).await;
    let lp = shared.analyze_lp(lp).await;
    let lp = shared.optimize_lp(lp).await;
    shared
        .pp_optimizer()
        .optimize(EmptyIr::<B>::from_logical_plan(&lp))
}

/// No benchmark TPC-H query (`_tt` and `_pgn` variants) without a string
/// ORDER BY key, nor a string filter, join or GROUP BY, loads a rank.
#[tokio::test]
async fn queries_without_a_string_sort_load_no_rank() {
    // The benchmark queries (benches/tpch/mod.rs) whose ORDER BY keys are
    // all numeric or that have none.
    let tt_queries: &[u8] = &[3, 5, 6, 8, 10, 14, 15, 17, 18, 19];
    let pgn_queries: &[u8] = &[3, 5, 8, 18];
    for &(numbers, poneglyph) in &[(tt_queries, false), (pgn_queries, true)] {
        for &number in numbers {
            let spec = tpch_data::query_spec(number, poneglyph);
            let ranks = initial_ir(spec.sql, spec.tables, &[])
                .await
                .tree()
                .required_rank_columns();
            assert!(
                ranks.is_empty(),
                "TPC-H q{number} (poneglyph={poneglyph}) would load ranks {ranks:?}"
            );
        }
    }
    for sql in [
        "SELECT n_nationkey FROM nation WHERE n_name = 'FRANCE'",
        "SELECT n_name FROM nation WHERE n_comment LIKE '%haggle%'",
        "SELECT n_name, COUNT(*) FROM nation GROUP BY n_name",
        "SELECT n.n_name, r.r_name FROM nation n JOIN region r ON n.n_regionkey = r.r_regionkey",
        "SELECT n_name FROM nation ORDER BY n_nationkey",
    ] {
        let ranks = initial_ir(sql, &["nation", "region"], &[])
            .await
            .tree()
            .required_rank_columns();
        assert!(ranks.is_empty(), "{sql} would load ranks {ranks:?}");
    }
}

/// A rank is owner data: a scan whose table has no oracle would take it
/// from the prover, so it is refused before any pass.
#[tokio::test]
async fn a_rank_over_a_scan_without_an_oracle_is_refused() {
    let ir = initial_ir("SELECT n_name, n_nationkey FROM nation", &["nation"], &[]).await;
    let refused = CtxOracles::<B>::default()
        .ensure_rank_columns(
            ir.tree(),
            &BTreeSet::from([("nation".to_string(), "n_name".to_string())]),
        )
        .expect_err("no oracle commits the rank of n_name");
    assert!(
        refused
            .to_string()
            .contains("column n_name of table nation needs its committed rank"),
        "{refused}"
    );
}

/// A rank belongs to its table: a sort on one table's string column needs
/// no rank of a same-named column of another table, which may be committed
/// without ranks or have no oracle at all.
#[tokio::test]
async fn a_rank_is_required_of_the_sorted_table_only() {
    let ir = initial_ir(
        "SELECT a.n_name, b.n_name AS other FROM nation a \
         JOIN nation_copy b ON a.n_nationkey = b.n_nationkey ORDER BY a.n_name",
        &["nation"],
        &[("nation_copy", "nation")],
    )
    .await;
    let required = ir.tree().required_rank_columns();
    assert_eq!(
        required,
        BTreeSet::from([("nation".to_string(), "n_name".to_string())])
    );
    let (pk_path, _) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("test keys");
    let parquet = resolve_parquet_path("nation").expect("test parquet");
    let oracle_path = resolve_oracle_path(&parquet, &pk_path)
        .await
        .expect("committed oracle");
    let oracle = ArithTableOracle::<B>::deserialize_compressed(BufReader::new(
        File::open(&oracle_path).expect("open oracle"),
    ))
    .expect("read oracle");
    CtxOracles::<B>::with_named_oracles(
        IndexMap::new(),
        IndexMap::from([("nation".to_string(), oracle)]),
    )
    .ensure_rank_columns(ir.tree(), &required)
    .expect("only nation's rank is needed, and its oracle commits it");
}

/// The rank segments a table scan of `sql` encodes when it loads the ranks
/// of `columns`, by segment name.
async fn scan_ranks(sql: &str, table: &str, columns: &[&str]) -> IndexMap<String, Arc<MLE<F>>> {
    let ir = initial_ir(sql, &[table], &[]).await;
    let output_planned = ir.apply_local_pass_parallel(&OutputPlanningPass::new());
    let gadget_planned =
        output_planned.apply_local_pass_sequential(&GadgetPlanningPass::new(&output_planned));
    let materialized = gadget_planned.apply_local_pass_parallel(&MaterializationPass::new());
    let arithmetized = materialized.apply_local_pass_parallel(&ArithmetizationPass::<B>::new(
        SideColumns::Only(BTreeSet::new()),
        FingerprintColumns::Only(Default::default()),
        RankColumns::Only(
            columns
                .iter()
                .map(|c| (table.to_string(), c.to_string()))
                .collect(),
        ),
    ));
    let (scan_id, _) = arithmetized
        .tree()
        .arena()
        .iter()
        .find(|(_, node)| node.name() == "TableScan")
        .expect("the query scans its table");
    let Some(Some(ArithPayload::PlanPayload(scan))) = arithmetized.payloads().get(scan_id) else {
        panic!("the scan has a plan payload");
    };
    scan.polynomials()
        .iter()
        .filter(|(field, _)| field.name().ends_with(STRING_RANK_SUFFIX))
        .map(|(field, mle)| (field.name().clone(), mle.clone()))
        .collect()
}

/// The rank a table scan encodes is the one the data owner committed. The
/// prover tracks its own polynomial under the owner's commitment, so a
/// difference would surface only as a failed opening, naming no gadget.
#[tokio::test]
async fn scan_ranks_are_the_committed_ranks() {
    let (pk_path, _) = resolve_key_paths(DEFAULT_TEST_LOG_SIZE).expect("test keys");
    let pk = TTPk::<B>::load(&pk_path).expect("load proving key");
    let prover = ArgProver::<B>::new_from_pk(pk.into_inner());
    let tables: [(&str, &[&str]); 3] = [
        ("nation", &["n_name", "n_comment"]),
        ("region", &["r_name", "r_comment"]),
        ("supplier", &["s_name", "s_address", "s_phone", "s_comment"]),
    ];
    for (table, columns) in tables {
        let parquet = resolve_parquet_path(table).expect("test parquet");
        let oracle_path = resolve_oracle_path(&parquet, &pk_path)
            .await
            .expect("committed oracle");
        let oracle = ArithTableOracle::<B>::deserialize_compressed(BufReader::new(
            File::open(&oracle_path).expect("open oracle"),
        ))
        .expect("read oracle");
        let sql = format!("SELECT {} FROM {table}", columns.join(", "));
        let scanned = scan_ranks(&sql, table, columns).await;
        assert_eq!(scanned.len(), columns.len(), "{table}: {scanned:?}");
        for column in columns {
            let rank = format!("{column}{STRING_RANK_SUFFIX}");
            let committed = oracle
                .commitments()
                .iter()
                .find(|(field, _)| *field.name() == rank)
                .map(|(_, commitment)| commitment)
                .unwrap_or_else(|| panic!("the oracle of {table} commits {rank}"));
            let recommitted =
                <B as SnarkBackend>::MvPCS::commit(prover.mv_pcs_prover_param(), &scanned[&rank])
                    .expect("commit the scan's rank");
            assert!(
                &recommitted == committed,
                "{table}.{column}: the scan's rank is not the committed one"
            );
        }
    }
}
