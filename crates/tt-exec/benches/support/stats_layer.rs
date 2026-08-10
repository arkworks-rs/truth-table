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
use serde_json::{Map, Value, json};
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id},
};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

const BENCH_STATS_TARGET: &str = "bench_stats";
pub const BENCH_STATS_JSONL_PATH: &str = "../../tt-results/raw/bench_stats.jsonl";

// See stats_jsonl.rs for docs on the memory-sampling design; this is a
// duplicated copy for the bench-only subscriber.
const MEMORY_SAMPLE_INTERVAL_MS: u64 = 10;

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
        self.samples.lock().map(|v| v.clone()).unwrap_or_default()
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
        Self::new(PathBuf::from(BENCH_STATS_JSONL_PATH))
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
            ext.insert(MemorySampler::start(self.sink.clone(), query));
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        if event.metadata().target() != BENCH_STATS_TARGET {
            return;
        }

        let mut visitor = FieldValueVisitor::default();
        event.record(&mut visitor);
        let mut fields = visitor.fields;

        // Tracker snapshots stream to disk immediately as their own JSONL
        // records so they survive an OOM kill (the aggregate bench_query
        // record never gets written if the span doesn't close). The
        // dashboard picks them up via a `kind: "tracker_snapshot"`
        // filter, same pattern as `mem_sample`.
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
    prover_pass_spans: Vec<Value>,
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
            prover_pass_spans: Vec::new(),
            extra: Map::new(),
        }
    }

    fn merge(&mut self, fields: Map<String, Value>) {
        let mut fields = fields;

        // Per-bucket sumcheck stats arrive as a JSON blob in one field.
        // Parse and hoist it into `self.buckets`; last write wins.
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

        // `prover_pass_span` event — see stats_jsonl.rs for the shape
        // and rationale. Accumulate into a per-record Vec that gets
        // embedded in the bench_query JSON at span close.
        if let (
            Some(Value::String(span_name)),
            Some(Value::String(start_ms)),
            Some(Value::String(end_ms)),
            Some(Value::String(duration_s)),
        ) = (
            fields.remove("prover_pass_span_name"),
            fields.remove("prover_pass_span_wall_start_ms"),
            fields.remove("prover_pass_span_wall_end_ms"),
            fields.remove("prover_pass_span_duration_s"),
        ) {
            self.prover_pass_spans.push(json!({
                "pass": span_name,
                "wall_start_ms": start_ms.parse::<u64>().unwrap_or(0),
                "wall_end_ms": end_ms.parse::<u64>().unwrap_or(0),
                "duration_s": duration_s.parse::<f64>().unwrap_or(0.0),
            }));
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
                "results_rows_count"
                | "results_schema"
                | "results_size_bytes"
                | "results_preview_rows"
                | "results_parquet_path" => {
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
                | "crypto_compressed_proof_size_bytes"
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
                    let normalized = key
                        .strip_prefix("crypto_breakdown_")
                        .unwrap_or(&key)
                        .to_string();
                    self.proof_size_crypto_breakdown.insert(normalized, value);
                }
                _ => {
                    self.extra.insert(key, value);
                }
            }
        }
    }

    fn into_json(self) -> Value {
        let mut root = Map::new();
        root.insert(
            "timestamp".to_string(),
            Value::String(self.timestamp_utc.clone()),
        );
        root.insert(
            "timestamp_utc".to_string(),
            Value::String(self.timestamp_utc),
        );
        root.insert("kind".to_string(), Value::String("bench_query".to_string()));
        root.insert("query".to_string(), Value::String(self.query));
        if !self.claims.is_empty() {
            root.insert("claims".to_string(), build_nested_claims(self.claims));
        }
        if !self.plans.is_empty() {
            root.insert("plans".to_string(), Value::Object(self.plans));
        }
        if !self.results.is_empty() {
            root.insert(
                "results".to_string(),
                json!({
                    "Rows Count": self.results.get("rows_count").cloned().unwrap_or(Value::Null),
                    "Schema": self.results.get("schema").cloned().unwrap_or(Value::Null),
                    "Size": self.results.get("size_bytes").cloned().unwrap_or(Value::Null),
                    "preview_rows": self.results.get("preview_rows").cloned().unwrap_or(Value::Null),
                    "parquet_path": self.results.get("parquet_path").cloned().unwrap_or(Value::Null)
                }),
            );
        }
        if !self.prover.is_empty() {
            let mut prover = Map::new();
            prover.insert("time".to_string(), Value::Object(self.prover));
            root.insert("prover".to_string(), Value::Object(prover));
        }
        if !self.snark_prover.is_empty() {
            root.insert(
                "snark prover".to_string(),
                build_snark_prover(self.snark_prover),
            );
        }
        if !self.proof_size_fields.is_empty() {
            let full_size = self
                .proof_size_fields
                .get("full_proof_size_bytes")
                .cloned()
                .unwrap_or(Value::Null);
            let full_compressed_size = self
                .proof_size_fields
                .get("full_compressed_proof_size_bytes")
                .cloned()
                .unwrap_or(Value::Null);
            let crypto_size = self
                .proof_size_fields
                .get("cryptographic_proof_size_bytes")
                .cloned()
                .unwrap_or(Value::Null);
            let crypto_compressed_size = self
                .proof_size_fields
                .get("crypto_compressed_proof_size_bytes")
                .cloned()
                .unwrap_or(Value::Null);
            let non_crypto_size = self
                .proof_size_fields
                .get("non_cryptographic_proof_size_bytes")
                .cloned()
                .unwrap_or(Value::Null);

            root.insert(
                "proof_size".to_string(),
                json!({
                    "full": {
                        "size": full_size,
                        "compressed size": full_compressed_size
                    },
                    "crypto": {
                        "size": crypto_size,
                        "compressed size": crypto_compressed_size,
                        "breakdown": build_crypto_breakdown(self.proof_size_crypto_breakdown)
                    },
                    "non_crypto": {
                        "size": non_crypto_size,
                        "breakdown": self.proof_size_non_crypto_breakdown
                    }
                }),
            );
        }
        if let Some(buckets) = self.buckets {
            root.insert("sc_buckets".to_string(), buckets);
        }
        if !self.memory_samples.is_empty() {
            let peak = self.memory_samples.iter().map(|(_, r)| *r).max().unwrap_or(0);
            let samples_json: Vec<Value> = self
                .memory_samples
                .iter()
                .map(|(t, r)| json!([*t, *r]))
                .collect();
            root.insert(
                "memory".to_string(),
                json!({
                    "peak_rss_bytes": peak,
                    "sample_count": samples_json.len(),
                    "sample_interval_ms": MEMORY_SAMPLE_INTERVAL_MS,
                    "samples": samples_json,
                }),
            );
        }
        if !self.stream_decisions.is_empty() {
            root.insert(
                "stream_decisions".to_string(),
                Value::Array(self.stream_decisions),
            );
        }
        if !self.prover_pass_spans.is_empty() {
            root.insert(
                "prover_pass_spans".to_string(),
                Value::Array(self.prover_pass_spans),
            );
        }
        if !self.extra.is_empty() {
            root.insert("extra".to_string(), Value::Object(self.extra));
        }
        Value::Object(root)
    }
}

fn build_snark_prover(fields: Map<String, Value>) -> Value {
    json!({
        "piop": {
            "time": fields.get("snark_prover_piop_time_s").cloned().unwrap_or(Value::Null),
            "breakdown": {
                "nozerocheck batching time": fields.get("snark_prover_piop_nozerocheck_batching_time_s").cloned().unwrap_or(Value::Null),
                "1st batch zerocheck time": fields.get("snark_prover_piop_first_batch_zerocheck_time_s").cloned().unwrap_or(Value::Null),
                "1st zerocheck to sumcheck time": fields.get("snark_prover_piop_first_zerocheck_to_sumcheck_time_s").cloned().unwrap_or(Value::Null),
                "1st batch sumcheck time": fields.get("snark_prover_piop_first_batch_sumcheck_time_s").cloned().unwrap_or(Value::Null),
                "reduce sumcheck time": fields.get("snark_prover_piop_reduce_sumcheck_time_s").cloned().unwrap_or(Value::Null),
                "2nd batch zerocheck time": fields.get("snark_prover_piop_second_batch_zerocheck_time_s").cloned().unwrap_or(Value::Null),
                "2nd zerocheck to sumcheck time": fields.get("snark_prover_piop_second_zerocheck_to_sumcheck_time_s").cloned().unwrap_or(Value::Null),
                "sumcheck time": fields.get("snark_prover_piop_sumcheck_time_s").cloned().unwrap_or(Value::Null)
            }
        },
        "mv pcs": fields.get("snark_prover_mv_pcs_time_s").cloned().unwrap_or(Value::Null),
        "uv pcs": fields.get("snark_prover_uv_pcs_time_s").cloned().unwrap_or(Value::Null)
    })
}

fn build_nested_claims(claims: Map<String, Value>) -> Value {
    json!({
        "before-degree-reduction": {
            "initial": build_claim_stage(&claims, "claims_before_degree_reduction_initial"),
            "after-nozero-batching": build_claim_stage(&claims, "claims_before_degree_reduction_after_nozero_batching"),
            "after-zero-batching": build_claim_stage(&claims, "claims_before_degree_reduction_after_zero_batching"),
            "after-sum-batching": build_claim_stage(&claims, "claims_before_degree_reduction_after_sum_batching")
        },
        "after-degree-reduction": {
            "initial": build_claim_stage(&claims, "claims_after_degree_reduction_initial"),
            "after-zero-batching": build_claim_stage(&claims, "claims_after_degree_reduction_after_zero_batching"),
            "after-sum-batching": build_claim_stage(&claims, "claims_after_degree_reduction_after_sum_batching")
        },
        "lookups": build_lookup_section(&claims)
    })
}

fn build_lookup_section(claims: &Map<String, Value>) -> Value {
    json!({
        "count": claims.get("claims_lookup_count").cloned().unwrap_or(Value::Null),
        "supersets_count": claims
            .get("claims_lookup_supersets_count")
            .cloned()
            .unwrap_or(Value::Null),
        "subset_counts_per_superset": claims
            .get("claims_lookup_subset_counts_per_superset")
            .cloned()
            .unwrap_or(Value::Null)
    })
}

fn build_crypto_breakdown(fields: Map<String, Value>) -> Value {
    let sc_subproof = fields.get("sc_subproof").cloned().unwrap_or(Value::Null);
    let miscellaneous_field_elements = fields
        .get("miscellaneous_field_elements")
        .cloned()
        .unwrap_or(Value::Null);
    let mv_size = fields
        .get("mv_pcs_subproof")
        .cloned()
        .unwrap_or(Value::Null);
    let uv_size = fields
        .get("uv_pcs_subproof")
        .cloned()
        .unwrap_or(Value::Null);

    json!({
        "sc_subproof": sc_subproof,
        "mv_pcs_subproof": {
            "size": mv_size,
            "breakdown": {
                "opening_proof": fields.get("mv_pcs_subproof_opening_proof").cloned().unwrap_or(Value::Null),
                "commitments": {
                    "size": fields.get("mv_pcs_subproof_commitments").cloned().unwrap_or(Value::Null),
                    "count": fields.get("mv_pcs_subproof_commitments_count").cloned().unwrap_or(Value::Null)
                },
                "query_map": fields.get("mv_pcs_subproof_query_map").cloned().unwrap_or(Value::Null)
            }
        },
        "uv_pcs_subproof": {
            "size": uv_size,
            "breakdown": {
                "opening_proof": fields.get("uv_pcs_subproof_opening_proof").cloned().unwrap_or(Value::Null),
                "commitments": {
                    "size": fields.get("uv_pcs_subproof_commitments").cloned().unwrap_or(Value::Null),
                    "count": fields.get("uv_pcs_subproof_commitments_count").cloned().unwrap_or(Value::Null)
                },
                "query_map": fields.get("uv_pcs_subproof_query_map").cloned().unwrap_or(Value::Null)
            }
        },
        "miscellaneous_field_elements": miscellaneous_field_elements
    })
}

fn build_claim_stage(claims: &Map<String, Value>, prefix: &str) -> Value {
    json!({
        "non-zero-checks": build_claim_metric(claims, prefix, "non_zero_checks"),
        "zero-checks": build_claim_metric(claims, prefix, "zero_checks"),
        "sum-checks": build_claim_metric(claims, prefix, "sum_checks")
    })
}

fn build_claim_metric(claims: &Map<String, Value>, prefix: &str, metric: &str) -> Value {
    let count_key = format!("{prefix}_{metric}_count");
    let degree_distribution_key = format!("{prefix}_{metric}_degree_distribution");
    json!({
        "count": claims.get(&count_key).cloned().unwrap_or(Value::Null),
        "degree_distribution": claims
            .get(&degree_distribution_key)
            .cloned()
            .unwrap_or(Value::Null)
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

pub fn default_jsonl_path() -> &'static Path {
    Path::new(BENCH_STATS_JSONL_PATH)
}

#[allow(clippy::too_many_arguments)]
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
    num_threads: usize,
    crypto_compressed_proof_size_bytes: usize,
) {
    tracing::info!(
        target: BENCH_STATS_TARGET,
        query,
        num_threads,
        cryptographic_proof_size_bytes,
        crypto_compressed_proof_size_bytes,
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

pub fn emit_results_stats(
    query: &str,
    rows_count: usize,
    schema: &str,
    size_bytes: usize,
    preview_rows: &str,
    parquet_path: &str,
) {
    tracing::info!(
        target: BENCH_STATS_TARGET,
        query,
        results_rows_count = rows_count,
        results_schema = schema,
        results_size_bytes = size_bytes,
        results_preview_rows = preview_rows,
        results_parquet_path = parquet_path,
        "results"
    );
}
