use std::{
    collections::BTreeMap,
    fmt,
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use chrono::Utc;
use datafusion::{datasource::{MemTable, TableProvider}, prelude::SessionContext};
use front_end::structs::SizeBreakdown;
use serde_json::{Map, Value, json};
use tracing::{
    Event, Subscriber, Span,
    field::{Field, Visit},
    span::{Attributes, Id},
};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

pub const JSONL_STATS_TARGET: &str = "bench_stats";
pub const JSONL_STATS_ENV: &str = "TT_JSONL_STATS";
pub const JSONL_STATS_PATH_ENV: &str = "TT_JSONL_STATS_PATH";

pub fn jsonl_stats_enabled_from_env() -> bool {
    std::env::var(JSONL_STATS_ENV)
        .map(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

pub fn default_jsonl_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("tt-exec crate should live inside truth-table/crates")
        .join("tt-results")
        .join("raw")
        .join("bench_stats.jsonl")
}

pub fn configured_jsonl_path() -> PathBuf {
    std::env::var(JSONL_STATS_PATH_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| default_jsonl_path())
}

pub fn query_stats_span(query: &str) -> Span {
    tracing::info_span!(target: JSONL_STATS_TARGET, "bench_query", query = %query)
}

/// How often the memory sampler reads `/proc/self/status` while a
/// `bench_query` span is open. 10 ms gives fine-grained curves on short
/// queries (~17 samples on a 170 ms LIKE run) and is still cheap on long
/// queries (~5000 samples over 50 s ≈ 40 KB of JSON). Total sampler CPU
/// cost is on the order of `interval / 10ms * 5μs`, well under 0.1% for
/// any realistic bench.
const MEMORY_SAMPLE_INTERVAL_MS: u64 = 10;

/// Read current process resident-set-size from `/proc/self/status` VmRSS
/// field (kB → bytes). Returns None on non-Linux or read/parse failure.
/// Prefers VmRSS over `/proc/self/statm` so we avoid hardcoding a page
/// size (which is 4 KB on x86-64 but 16 KB/64 KB on some ARM/PowerPC
/// hosts). Parse cost is a few μs — still negligible at 10 ms intervals.
#[cfg(target_os = "linux")]
fn read_rss_bytes() -> Option<u64> {
    let content = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in content.lines() {
        let Some(rest) = line.strip_prefix("VmRSS:") else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let n: u64 = parts.next()?.parse().ok()?;
        let unit = parts.next()?;
        return match unit {
            "kB" | "KB" => Some(n * 1024),
            _ => None,
        };
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn read_rss_bytes() -> Option<u64> {
    None
}

fn wall_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Background RSS sampler attached to each `bench_query` span. Spawns one
/// thread on span open that sleeps `MEMORY_SAMPLE_INTERVAL_MS` between
/// reads and appends `(wall_clock_ms, rss_bytes)` to a shared buffer.
/// The buffer is drained on span close and stored as `memory_samples` in
/// the JSONL record. The sampler thread is a no-op on non-Linux — the
/// stat file simply returns None and no samples accumulate.
struct MemorySampler {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    samples: Arc<Mutex<Vec<(u64, u64)>>>,
}

impl MemorySampler {
    /// Each sample also gets streamed to `sink` immediately as a
    /// `{"kind":"mem_sample",...}` line and flushed. This is what
    /// survives an OOM kill: even though the aggregate bench_query
    /// record is only written on span close (which never runs if the
    /// process gets SIGKILL'd), the individual mem_sample lines are
    /// already on disk by the time the killer fires. The dashboard
    /// reconstructs the RSS curve for killed queries from those lines.
    fn start(sink: Arc<Mutex<JsonlSink>>, query: String) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let samples: Arc<Mutex<Vec<(u64, u64)>>> = Arc::new(Mutex::new(Vec::new()));
        let stop_thread = stop.clone();
        let samples_thread = samples.clone();
        let handle = std::thread::Builder::new()
            .name("tt-mem-sampler".to_string())
            .spawn(move || {
                let interval = Duration::from_millis(MEMORY_SAMPLE_INTERVAL_MS);
                while !stop_thread.load(Ordering::Relaxed) {
                    if let Some(rss) = read_rss_bytes() {
                        let ms = wall_clock_ms();
                        if let Ok(mut v) = samples_thread.lock() {
                            v.push((ms, rss));
                        }
                        let entry = json!({
                            "kind": "mem_sample",
                            "query": query,
                            "wall_ms": ms,
                            "rss_bytes": rss,
                        });
                        if let Ok(mut s) = sink.lock() {
                            let _ = s.write_entry(&entry);
                        }
                    }
                    std::thread::sleep(interval);
                }
            })
            .ok();
        Self { stop, handle, samples }
    }

    fn stop_and_take(&mut self) -> Vec<(u64, u64)> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        self.samples
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default()
    }
}

pub struct BenchStatsJsonlLayer {
    sink: Arc<Mutex<JsonlSink>>,
    pending_records: Arc<Mutex<BTreeMap<String, PendingBenchRecord>>>,
}

#[derive(Clone)]
struct QueryLabel(String);

impl BenchStatsJsonlLayer {
    pub fn new_default() -> std::io::Result<Self> {
        Self::new(configured_jsonl_path())
    }

    pub fn new(path: PathBuf) -> std::io::Result<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        Ok(Self {
            sink: Arc::new(Mutex::new(JsonlSink {
                writer: BufWriter::new(file),
                path,
            })),
            pending_records: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }
}

impl<S> Layer<S> for BenchStatsJsonlLayer
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut visitor = FieldValueVisitor::default();
        attrs.record(&mut visitor);
        let query = visitor.fields.remove("query");
        if let (Some(span), Some(query)) = (ctx.span(id), query)
            && !query.is_empty()
        {
            let mut ext = span.extensions_mut();
            ext.insert(QueryLabel(query.clone()));
            // One sampler thread per bench_query span; joined on close.
            // Streams samples to sink so they survive an OOM kill.
            ext.insert(MemorySampler::start(self.sink.clone(), query));
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        if event.metadata().target() != JSONL_STATS_TARGET {
            return;
        }

        let mut visitor = FieldValueVisitor::default();
        event.record(&mut visitor);
        let mut fields = visitor.fields;

        // Tracker snapshots stream immediately (like mem_sample) so they
        // survive OOM.
        if let Some(payload) = fields.remove("tracker_snapshot_json") {
            let q = fields
                .get("query")
                .cloned()
                .or_else(|| query_from_scope(&ctx, event))
                .unwrap_or_default();
            let parsed: Value =
                serde_json::from_str(&payload).unwrap_or_else(|_| Value::String(payload));
            let entry = json!({
                "kind": "tracker_snapshot",
                "query": q,
                "snapshot": parsed,
            });
            if let Ok(mut sink) = self.sink.lock() {
                let _ = sink.write_entry(&entry);
            }
            return;
        }

        // Sumcheck stream-policy decisions: one event per `prover_init`
        // call. Streamed to its own JSONL line for OOM survival AND
        // aggregated into the pending bench_query record so multiple
        // runs of the same query can be told apart in the dashboard
        // (streamed lines only carry the query name, not the run's
        // timestamp, so they'd merge across runs otherwise).
        if let Some(payload) = fields.remove("sumcheck_stream_decision_json") {
            let q = fields
                .get("query")
                .cloned()
                .or_else(|| query_from_scope(&ctx, event))
                .unwrap_or_default();
            let parsed: Value =
                serde_json::from_str(&payload).unwrap_or_else(|_| Value::String(payload));
            let entry = json!({
                "kind": "sumcheck_stream_decision",
                "query": q.clone(),
                "decision": parsed.clone(),
            });
            if let Ok(mut sink) = self.sink.lock() {
                let _ = sink.write_entry(&entry);
            }
            if !q.is_empty()
                && let Ok(mut pending_records) = self.pending_records.lock()
            {
                let record = pending_records
                    .entry(q.clone())
                    .or_insert_with(|| PendingBenchRecord::new(q));
                record.stream_decisions.push(parsed);
            }
            return;
        }

        if let Some(benchmark) = fields.remove("benchmark") {
            let case = fields.remove("case").unwrap_or_default();
            let timestamp = now_utc_rfc3339_ms();
            let entry = json!({
                "timestamp": timestamp,
                "timestamp_utc": timestamp,
                "kind": "benchmark_summary",
                "benchmark": benchmark,
                "case": case,
            });
            if let Ok(mut sink) = self.sink.lock()
                && let Err(err) = sink.write_entry(&entry)
            {
                eprintln!(
                    "failed to append bench stats entry to {}: {}",
                    sink.path.display(),
                    err
                );
            }
            return;
        }

        let query = fields
            .remove("query")
            .filter(|q| !q.is_empty())
            .or_else(|| query_from_scope(&ctx, event));

        let Some(query) = query else {
            return;
        };

        let mut payload = Map::new();
        for (key, value) in fields {
            if !value.is_empty() {
                payload.insert(key, Value::String(value));
            }
        }

        if payload.is_empty() {
            return;
        }

        if let Ok(mut pending_records) = self.pending_records.lock() {
            let record = pending_records
                .entry(query.clone())
                .or_insert_with(|| PendingBenchRecord::new(query));
            record.merge(payload);
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else {
            return;
        };
        let query;
        let memory_samples;
        {
            let mut extensions = span.extensions_mut();
            let Some(label) = extensions.get_mut::<QueryLabel>() else {
                return;
            };
            query = label.0.clone();
            // Stop the sampler and drain its buffer before we lose the span.
            memory_samples = extensions
                .get_mut::<MemorySampler>()
                .map(|s| s.stop_and_take())
                .unwrap_or_default();
        }

        let record = self
            .pending_records
            .lock()
            .ok()
            .and_then(|mut pending_records| pending_records.remove(&query));

        if let Some(mut record) = record {
            record.memory_samples = memory_samples;
            let entry = record.into_json();
            if let Ok(mut sink) = self.sink.lock()
                && let Err(err) = sink.write_entry(&entry)
            {
                eprintln!(
                    "failed to append bench stats entry to {}: {}",
                    sink.path.display(),
                    err
                );
            }
        }
    }
}

fn query_from_scope<S>(ctx: &Context<'_, S>, event: &Event<'_>) -> Option<String>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    let scope = ctx.event_scope(event)?;
    let mut query = None;
    for span in scope.from_root() {
        if let Some(label) = span.extensions().get::<QueryLabel>() {
            query = Some(label.0.clone());
        }
    }
    query
}

struct JsonlSink {
    writer: BufWriter<File>,
    path: PathBuf,
}

impl JsonlSink {
    fn write_entry(&mut self, entry: &Value) -> std::io::Result<()> {
        serde_json::to_writer(&mut self.writer, entry)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }
}

struct PendingBenchRecord {
    timestamp_utc: String,
    query: String,
    claims: Map<String, Value>,
    plans: Map<String, Value>,
    results: Map<String, Value>,
    prover: Map<String, Value>,
    snark_prover: Map<String, Value>,
    proof_size_fields: Map<String, Value>,
    proof_size_crypto_breakdown: Map<String, Value>,
    proof_size_non_crypto_breakdown: Map<String, Value>,
    buckets: Option<Value>,
    memory_samples: Vec<(u64, u64)>,
    stream_decisions: Vec<Value>,
    extra: Map<String, Value>,
}

impl PendingBenchRecord {
    fn new(query: String) -> Self {
        Self {
            timestamp_utc: now_utc_rfc3339_ms(),
            query,
            claims: Map::new(),
            plans: Map::new(),
            results: Map::new(),
            prover: Map::new(),
            snark_prover: Map::new(),
            proof_size_fields: Map::new(),
            proof_size_crypto_breakdown: Map::new(),
            proof_size_non_crypto_breakdown: Map::new(),
            buckets: None,
            memory_samples: Vec::new(),
            stream_decisions: Vec::new(),
            extra: Map::new(),
        }
    }

    fn merge(&mut self, fields: Map<String, Value>) {
        let mut fields = fields;

        // Per-bucket sumcheck stats arrive as a JSON blob in one field.
        // Parse and hoist it into `self.buckets`; last write wins if the
        // prover somehow emits multiple (it shouldn't).
        if let Some(Value::String(blob)) = fields.remove("sc_buckets_json") {
            match serde_json::from_str::<Value>(&blob) {
                Ok(parsed) => self.buckets = Some(parsed),
                Err(err) => eprintln!("failed to parse sc_buckets_json: {err}"),
            }
        }

        if let (Some(Value::String(plan_name)), Some(plan_graphviz)) =
            (fields.remove("plan_name"), fields.remove("plan_graphviz"))
        {
            self.plans.insert(plan_name, plan_graphviz);
        }

        if let (Some(Value::String(pass_name)), Some(pass_seconds)) = (
            fields.remove("prover_time_pass"),
            fields.remove("prover_time_seconds"),
        ) {
            self.prover
                .insert(format!("prover_time_{pass_name}_s"), pass_seconds);
        }

        for (key, value) in fields {
            match key.as_str() {
                _ if key.starts_with("claims_") => {
                    self.claims.insert(key, value);
                }
                _ if key.starts_with("plan_") => {
                    let normalized = key.strip_prefix("plan_").unwrap_or(&key).to_string();
                    self.plans.insert(normalized, value);
                }
                "results_rows_count" | "results_schema" | "results_size_bytes" => {
                    let normalized = key.strip_prefix("results_").unwrap_or(&key).to_string();
                    self.results.insert(normalized, value);
                }
                _ if key.starts_with("prover_time_") => {
                    self.prover.insert(key, value);
                }
                _ if key.starts_with("snark_prover_") => {
                    self.snark_prover.insert(key, value);
                }
                "cryptographic_proof_size_bytes"
                | "non_cryptographic_proof_size_bytes"
                | "full_proof_size_bytes"
                | "full_compressed_proof_size_bytes" => {
                    self.proof_size_fields.insert(key, value);
                }
                "crypto_breakdown_sc_subproof"
                | "crypto_breakdown_mv_pcs_subproof"
                | "crypto_breakdown_mv_pcs_subproof_opening_proof"
                | "crypto_breakdown_mv_pcs_subproof_commitments"
                | "crypto_breakdown_mv_pcs_subproof_commitments_count"
                | "crypto_breakdown_mv_pcs_subproof_query_map"
                | "crypto_breakdown_uv_pcs_subproof"
                | "crypto_breakdown_uv_pcs_subproof_opening_proof"
                | "crypto_breakdown_uv_pcs_subproof_commitments"
                | "crypto_breakdown_uv_pcs_subproof_commitments_count"
                | "crypto_breakdown_uv_pcs_subproof_query_map"
                | "crypto_breakdown_miscellaneous_field_elements" => {
                    self.proof_size_crypto_breakdown.insert(key, value);
                }
                _ => {
                    self.extra.insert(key, value);
                }
            }
        }
    }

    fn into_json(self) -> Value {
        let claims = claims_json(&self.claims);
        let proof_size = proof_size_json(
            &self.proof_size_fields,
            &self.proof_size_crypto_breakdown,
            &self.proof_size_non_crypto_breakdown,
        );
        let timestamp = self.timestamp_utc.clone();

        let mut root = json!({
            "timestamp": timestamp,
            "timestamp_utc": self.timestamp_utc,
            "kind": "bench_query",
            "query": self.query,
            "claims": claims,
            "results": Value::Object(self.results),
            "prover": Value::Object(self.prover),
            "snark prover": Value::Object(self.snark_prover),
            "proof_size": proof_size,
            "plans": Value::Object(self.plans),
            "extra": Value::Object(self.extra),
        });
        if let Some(buckets) = self.buckets
            && let Value::Object(ref mut map) = root
        {
            map.insert("sc_buckets".to_string(), buckets);
        }
        if !self.memory_samples.is_empty()
            && let Value::Object(ref mut map) = root
        {
            let peak = self.memory_samples.iter().map(|(_, r)| *r).max().unwrap_or(0);
            let samples_json: Vec<Value> = self
                .memory_samples
                .iter()
                .map(|(t, r)| json!([*t, *r]))
                .collect();
            map.insert(
                "memory".to_string(),
                json!({
                    "peak_rss_bytes": peak,
                    "sample_count": samples_json.len(),
                    "sample_interval_ms": MEMORY_SAMPLE_INTERVAL_MS,
                    // Each entry: [wall_clock_ms_epoch, rss_bytes]
                    "samples": samples_json,
                }),
            );
        }
        if !self.stream_decisions.is_empty()
            && let Value::Object(ref mut map) = root
        {
            map.insert(
                "stream_decisions".to_string(),
                Value::Array(self.stream_decisions),
            );
        }
        root
    }
}

fn claims_json(claims: &Map<String, Value>) -> Value {
    let before = degree_reduction_claims_json(claims, "before_degree_reduction");
    let after = degree_reduction_claims_json(claims, "after_degree_reduction");
    json!({
        "before-degree-reduction": before,
        "after-degree-reduction": after,
    })
}

fn degree_reduction_claims_json(claims: &Map<String, Value>, prefix: &str) -> Value {
    let stages = if prefix == "before_degree_reduction" {
        [
            ("initial", "initial"),
            ("after-nozero-batching", "after_nozero_batching"),
            ("after-zero-batching", "after_zero_batching"),
            ("after-sum-batching", "after_sum_batching"),
        ]
    } else {
        [
            ("initial", "initial"),
            ("after-zero-batching", "after_zero_batching"),
            ("after-sum-batching", "after_sum_batching"),
            ("unused", "unused"),
        ]
    };

    let mut object = Map::new();
    for (label, suffix) in stages {
        if label == "unused" {
            continue;
        }
        object.insert(
            label.to_string(),
            claim_stage_json(claims, &format!("claims_{prefix}_{suffix}")),
        );
    }
    Value::Object(object)
}

fn claim_stage_json(claims: &Map<String, Value>, prefix: &str) -> Value {
    json!({
        "non-zero-checks": claim_bucket_json(claims, &format!("{prefix}_non_zero_checks")),
        "zero-checks": claim_bucket_json(claims, &format!("{prefix}_zero_checks")),
        "sum-checks": claim_bucket_json(claims, &format!("{prefix}_sum_checks")),
    })
}

fn claim_bucket_json(claims: &Map<String, Value>, prefix: &str) -> Value {
    let count = claims
        .get(&format!("{prefix}_count"))
        .cloned()
        .unwrap_or(Value::Null);
    let degree_distribution = claims
        .get(&format!("{prefix}_degree_distribution"))
        .cloned()
        .unwrap_or(Value::Null);
    json!({
        "count": count,
        "degree_distribution": degree_distribution,
    })
}

fn proof_size_json(
    proof_size_fields: &Map<String, Value>,
    crypto_breakdown: &Map<String, Value>,
    non_crypto_breakdown: &Map<String, Value>,
) -> Value {
    json!({
        "full": {
            "size": proof_size_fields.get("full_proof_size_bytes").cloned().unwrap_or(Value::Null),
            "compressed size": proof_size_fields.get("full_compressed_proof_size_bytes").cloned().unwrap_or(Value::Null),
        },
        "crypto": {
            "size": proof_size_fields.get("cryptographic_proof_size_bytes").cloned().unwrap_or(Value::Null),
            "breakdown": crypto_breakdown_json(crypto_breakdown),
        },
        "non_crypto": {
            "size": proof_size_fields.get("non_cryptographic_proof_size_bytes").cloned().unwrap_or(Value::Null),
            "breakdown": Value::Object(non_crypto_breakdown.clone()),
        },
    })
}

fn crypto_breakdown_json(fields: &Map<String, Value>) -> Value {
    json!({
        "sc_subproof": fields.get("crypto_breakdown_sc_subproof").cloned().unwrap_or(Value::Null),
        "mv_pcs_subproof": {
            "size": fields.get("crypto_breakdown_mv_pcs_subproof").cloned().unwrap_or(Value::Null),
            "breakdown": {
                "opening_proof": fields.get("crypto_breakdown_mv_pcs_subproof_opening_proof").cloned().unwrap_or(Value::Null),
                "commitments": {
                    "size": fields.get("crypto_breakdown_mv_pcs_subproof_commitments").cloned().unwrap_or(Value::Null),
                    "count": fields.get("crypto_breakdown_mv_pcs_subproof_commitments_count").cloned().unwrap_or(Value::Null),
                },
                "query_map": fields.get("crypto_breakdown_mv_pcs_subproof_query_map").cloned().unwrap_or(Value::Null),
            }
        },
        "uv_pcs_subproof": {
            "size": fields.get("crypto_breakdown_uv_pcs_subproof").cloned().unwrap_or(Value::Null),
            "breakdown": {
                "opening_proof": fields.get("crypto_breakdown_uv_pcs_subproof_opening_proof").cloned().unwrap_or(Value::Null),
                "commitments": {
                    "size": fields.get("crypto_breakdown_uv_pcs_subproof_commitments").cloned().unwrap_or(Value::Null),
                    "count": fields.get("crypto_breakdown_uv_pcs_subproof_commitments_count").cloned().unwrap_or(Value::Null),
                },
                "query_map": fields.get("crypto_breakdown_uv_pcs_subproof_query_map").cloned().unwrap_or(Value::Null),
            }
        },
        "miscellaneous_field_elements": fields.get("crypto_breakdown_miscellaneous_field_elements").cloned().unwrap_or(Value::Null),
    })
}

fn now_utc_rfc3339_ms() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[derive(Default)]
struct FieldValueVisitor {
    fields: BTreeMap<String, String>,
}

impl FieldValueVisitor {
    fn record_kv(&mut self, field: &Field, value: String) {
        self.fields.insert(field.name().to_string(), value);
    }
}

impl Visit for FieldValueVisitor {
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_kv(field, value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_kv(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_kv(field, value.to_string());
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        self.record_kv(field, value.to_string());
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        self.record_kv(field, value.to_string());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.record_kv(field, value.to_string());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_kv(field, value.to_string());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.record_kv(field, value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.record_kv(field, format!("{value:?}"));
    }
}

pub fn emit_benchmark_stats_row(benchmark: &'static str, case: &str) {
    let _ = (benchmark, case);
}

pub fn emit_proof_size_bytes(
    query: &str,
    cryptographic_proof_size_bytes: usize,
    non_cryptographic_proof_size_bytes: usize,
    full_proof_size_bytes: usize,
    full_compressed_proof_size_bytes: usize,
    crypto_breakdown_sc_subproof: usize,
    crypto_breakdown_mv_pcs_subproof: usize,
    crypto_breakdown_mv_pcs_subproof_opening_proof: usize,
    crypto_breakdown_mv_pcs_subproof_commitments: usize,
    crypto_breakdown_mv_pcs_subproof_commitments_count: usize,
    crypto_breakdown_mv_pcs_subproof_query_map: usize,
    crypto_breakdown_uv_pcs_subproof: usize,
    crypto_breakdown_uv_pcs_subproof_opening_proof: usize,
    crypto_breakdown_uv_pcs_subproof_commitments: usize,
    crypto_breakdown_uv_pcs_subproof_commitments_count: usize,
    crypto_breakdown_uv_pcs_subproof_query_map: usize,
    crypto_breakdown_miscellaneous_field_elements: usize,
) {
    tracing::info!(
        target: JSONL_STATS_TARGET,
        query,
        cryptographic_proof_size_bytes,
        non_cryptographic_proof_size_bytes,
        full_proof_size_bytes,
        full_compressed_proof_size_bytes,
        crypto_breakdown_sc_subproof,
        crypto_breakdown_mv_pcs_subproof,
        crypto_breakdown_mv_pcs_subproof_opening_proof,
        crypto_breakdown_mv_pcs_subproof_commitments,
        crypto_breakdown_mv_pcs_subproof_commitments_count,
        crypto_breakdown_mv_pcs_subproof_query_map,
        crypto_breakdown_uv_pcs_subproof,
        crypto_breakdown_uv_pcs_subproof_opening_proof,
        crypto_breakdown_uv_pcs_subproof_commitments,
        crypto_breakdown_uv_pcs_subproof_commitments_count,
        crypto_breakdown_uv_pcs_subproof_query_map,
        crypto_breakdown_miscellaneous_field_elements,
        "proof_sizes"
    );
}

pub fn emit_results_stats(query: &str, rows_count: usize, schema: &str, size_bytes: usize) {
    tracing::info!(
        target: JSONL_STATS_TARGET,
        query,
        results_rows_count = rows_count,
        results_schema = schema,
        results_size_bytes = size_bytes,
        "results"
    );
}

pub fn breakdown_child_size(breakdown: &SizeBreakdown, key: &str) -> usize {
    breakdown.parts.get(key).map(|part| part.size).unwrap_or(0)
}

pub fn breakdown_grandchild_size(breakdown: &SizeBreakdown, key: &str, child_key: &str) -> usize {
    breakdown
        .parts
        .get(key)
        .and_then(|part| part.parts.get(child_key))
        .map(|part| part.size)
        .unwrap_or(0)
}

pub fn result_memtable_stats(mem_table: &Arc<MemTable>) -> anyhow::Result<(usize, String, usize)> {
    use datafusion::arrow::ipc::writer::StreamWriter;

    let ctx = SessionContext::new();
    let batches = crate::runtime::block_on(async {
        let table: Arc<dyn TableProvider> = mem_table.clone();
        let df = ctx.read_table(table)?;
        df.collect().await
    })?;

    let rows_count = batches.iter().map(|batch| batch.num_rows()).sum();
    let schema = mem_table
        .schema()
        .fields()
        .iter()
        .map(|field| format!("{}: {}", field.name(), field.data_type()))
        .collect::<Vec<_>>()
        .join(", ");

    let mut serialized = Vec::new();
    {
        let mut writer = StreamWriter::try_new(&mut serialized, &mem_table.schema())?;
        for batch in &batches {
            writer.write(batch)?;
        }
        writer.finish()?;
    }

    Ok((rows_count, schema, serialized.len()))
}
