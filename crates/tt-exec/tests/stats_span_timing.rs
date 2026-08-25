//! End-to-end pin for the span-derived prover timings.
//!
//! `snark_prover_piop_time_s` / `_mv_pcs_` / `_uv_pcs_` used to be measured
//! by ark-piop's `compile_proof` with its own `Instant` and shipped as a
//! `snark_prover_times` event. They are now derived by
//! [`BenchStatsJsonlLayer`] from the open→close lifetime of the
//! `bench_stats`-targeted spans on the three subproof functions.
//!
//! The same is true of the per-bucket sumcheck breakdown: ark-piop emits
//! only each bucket's claim shape, and the layer splices in the `timing`
//! object and wall-clock boundaries it derived from the `sc_bucket` /
//! `SC_REGION_SPANS` spans.
//!
//! That path crosses a crate boundary, a tracing target, a level filter,
//! and a span-scope lookup — none of which any type checks. ark-piop's
//! `snark_prover_timed_spans_are_instrumented` covers its half (the spans
//! open, on the right target and level); this covers the rest: that the
//! layer attributes them to the enclosing `bench_query` and writes them
//! under the keys the dashboard reads.

use ark_piop::{SnarkBackend, arithmetic::mat_poly::mle::MLE};
use serde_json::Value;
use tracing_subscriber::layer::SubscriberExt;
use tt_exec::stats_jsonl::{BenchStatsJsonlLayer, query_stats_span};

type Backend = ark_piop::DefaultSnarkBackend;
type F = <Backend as SnarkBackend>::F;

const QUERY: &str = "SELECT 1";

/// Run `body` inside a `bench_query` span with a fresh JSONL layer, then
/// return the aggregate record written at span close.
fn record_from<F: FnOnce()>(body: F) -> Value {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bench_stats.jsonl");
    let layer = BenchStatsJsonlLayer::new(path.clone()).unwrap();
    let subscriber = tracing_subscriber::registry().with(layer);

    tracing::subscriber::with_default(subscriber, || {
        let span = query_stats_span(QUERY);
        let _guard = span.enter();
        body();
    });
    // `with_default` returned, so the bench_query span is closed and its
    // record has been flushed.

    let contents = std::fs::read_to_string(&path).unwrap();
    contents
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        // mem_sample / tracker_snapshot lines stream out during the run; the
        // aggregate record is written at span close and is the only one
        // carrying a "query" key at the top level alongside "prover".
        .find(|entry| entry.get("prover").is_some())
        .unwrap_or_else(|| panic!("no aggregate bench_query record in {}", path.display()))
}

/// [`record_from`] with a prover built and compiled for you.
fn record_for<P>(prove: P) -> Value
where
    P: FnOnce(&mut ark_piop::prover::ArgProver<Backend>),
{
    record_from(|| {
        // nv=4 keeps key generation off the critical path of these tests.
        let (mut prover, _verifier) =
            ark_piop::test_utils::prelude_with_vars::<Backend>(4).unwrap();
        prove(&mut prover);
        prover.build_proof().unwrap();
    })
}

/// Parse a stringified duration the layer filed into the record.
fn seconds(raw: &Value, what: &str) -> f64 {
    raw.as_str()
        .unwrap_or_else(|| panic!("`{what}` should be a string, got {raw}"))
        .parse()
        .unwrap_or_else(|err| panic!("`{what}` is not a number: {err}"))
}

#[test]
fn prover_subproof_spans_become_jsonl_timings() {
    // A claim-free compile is enough here: all three subproof spans open
    // before their bodies decide they have nothing to do.
    let record = record_for(|_| {});

    assert_eq!(record["query"], Value::String(QUERY.to_string()));

    let snark_prover = record["snark prover"]
        .as_object()
        .expect("`snark prover` must be an object");

    for (span_name, key) in ark_piop::prover::tracker::SNARK_PROVER_TIMED_SPANS {
        let raw = snark_prover.get(*key).unwrap_or_else(|| {
            panic!(
                "`{key}` missing — the `{span_name}` span did not reach the layer. \
                 Present keys: {:?}",
                snark_prover.keys().collect::<Vec<_>>()
            )
        });
        // Recorded as a string, matching how FieldValueVisitor stringified
        // the f64 on the old event path — the dashboard parses it as such.
        // Strictly positive: a zero would mean the clock was read once
        // rather than at both span open and close. An empty nv=4 compile
        // still measures on the order of 10 µs.
        let elapsed = seconds(raw, key);
        assert!(
            elapsed.is_finite() && elapsed > 0.0,
            "`{key}` should be a positive duration, got {elapsed}"
        );
    }
}

/// With a real claim the compile actually runs a bucket, so the `sc_bucket`
/// and region spans fire. Checks both destinations the layer feeds: the
/// `timing` object spliced into each bucket entry, and the cross-bucket
/// `snark_prover_piop_<region>_time_s` totals.
#[test]
fn bucket_region_spans_become_per_bucket_and_aggregate_timings() {
    let record = record_for(|prover| {
        let evals: Vec<F> = (0..16).map(|i| F::from(i as u64)).collect();
        let sum = evals.iter().copied().reduce(|a, b| a + b).unwrap();
        let poly = MLE::from_evaluations_vec(4, evals);
        let tracked = prover.track_and_commit_mat_mv_poly(&poly).unwrap();
        prover.add_mv_sumcheck_claim(tracked.id(), sum).unwrap();
    });

    let buckets = record["sc_buckets"]["buckets"]
        .as_array()
        .expect("`sc_buckets.buckets` must be an array");
    assert!(!buckets.is_empty(), "expected at least one bucket");

    for bucket in buckets {
        let index = bucket["index"].as_u64().expect("bucket needs an index");
        let timing = bucket["timing"]
            .as_object()
            .unwrap_or_else(|| panic!("bucket {index} has no spliced `timing` object: {bucket}"));

        // Every region key must be present even when its stage never ran —
        // the old fixed-struct breakdown always emitted all of them.
        let mut summed = 0.0;
        for region in ark_piop::prover::tracker::SC_REGION_SPANS {
            let key = format!("{region}_time_s");
            let value = timing
                .get(&key)
                .unwrap_or_else(|| panic!("bucket {index} missing `{key}`"))
                .as_f64()
                .unwrap_or_else(|| panic!("`{key}` should be a number"));
            assert!(value >= 0.0, "`{key}` should be non-negative, got {value}");
            summed += value;
        }
        let total = timing["total_time_s"].as_f64().expect("total_time_s");
        assert!(
            (total - summed).abs() < 1e-9,
            "bucket {index}: total_time_s {total} != sum of regions {summed}"
        );
        assert!(total > 0.0, "bucket {index} took no measurable time");

        // Wall-clock boundaries for the dashboard's RSS overlay.
        let start = bucket["wall_start_ms"].as_u64().expect("wall_start_ms");
        let end = bucket["wall_end_ms"].as_u64().expect("wall_end_ms");
        assert!(start > 0, "bucket {index} has no wall_start_ms");
        assert!(
            end >= start,
            "bucket {index}: wall_end_ms {end} precedes wall_start_ms {start}"
        );
    }

    // The aggregate the dashboard's piop-breakdown pie reads. Every region
    // key must be present once any bucket has run, even for a stage that
    // never executed — the old fixed-struct event always emitted all eight,
    // and an absent key reads as null rather than zero downstream.
    let snark_prover = record["snark prover"].as_object().unwrap();
    let mut total = 0.0;
    for region in ark_piop::prover::tracker::SC_REGION_SPANS {
        let key = format!("snark_prover_piop_{region}_time_s");
        let raw = snark_prover.get(&key).unwrap_or_else(|| {
            panic!(
                "`{key}` missing: {:?}",
                snark_prover.keys().collect::<Vec<_>>()
            )
        });
        let value = seconds(raw, &key);
        assert!(value >= 0.0, "`{key}` should be non-negative, got {value}");
        total += value;
    }
    // `sumcheck` is the one region guaranteed to run for a claim that
    // reaches a bucket, so the aggregate can't be all zeros.
    assert!(total > 0.0, "every region aggregate was zero");
}

/// A prover pass span feeds two destinations that used to be two hand-rolled
/// events: the `prover_time_<pass>_s` entry and the `prover_pass_spans`
/// timeline marker. Uses tt-front-end's own [`front_end::prover::pass_span`]
/// constructor, so the span name, target, and field name are the real ones.
#[test]
fn prover_pass_spans_become_timings_and_markers() {
    let record = record_from(|| {
        let _pass = front_end::prover::pass_span("arithmetization").entered();
        std::thread::sleep(std::time::Duration::from_millis(5));
    });

    let key = "prover_time_arithmetization_s";
    let prover = record["prover"]
        .as_object()
        .expect("`prover` must be object");
    let elapsed = seconds(
        prover
            .get(key)
            .unwrap_or_else(|| panic!("`{key}` missing: {:?}", prover.keys().collect::<Vec<_>>())),
        key,
    );
    assert!(elapsed >= 0.005, "expected >=5ms, got {elapsed}");

    let markers = record["prover_pass_spans"]
        .as_array()
        .expect("`prover_pass_spans` must be an array");
    let marker = markers
        .iter()
        .find(|m| m["pass"] == "arithmetization")
        .unwrap_or_else(|| panic!("no marker for the pass: {markers:?}"));

    // Both endpoints are measured now. The old event pair back-derived the
    // start as `end - duration`; here the span's two ends are independent
    // stamps, so the elapsed wall span must agree with the monotonic
    // duration rather than equalling it by construction.
    let start = marker["wall_start_ms"].as_u64().expect("wall_start_ms");
    let end = marker["wall_end_ms"].as_u64().expect("wall_end_ms");
    assert!(
        start > 0 && end >= start,
        "bad marker window {start}..{end}"
    );
    let wall_ms = (end - start) as f64;
    let duration_ms = marker["duration_s"].as_f64().expect("duration_s") * 1000.0;
    assert!(
        (wall_ms - duration_ms).abs() <= 2.0,
        "wall window {wall_ms}ms disagrees with measured {duration_ms}ms"
    );
}
