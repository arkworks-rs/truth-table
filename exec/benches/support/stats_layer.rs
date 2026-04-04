use std::{
    collections::BTreeMap,
    fmt,
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
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
pub const BENCH_STATS_JSONL_PATH: &str = "target/bench_stats.jsonl";

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
            span.extensions_mut().insert(QueryLabel(query));
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        if event.metadata().target() != BENCH_STATS_TARGET {
            return;
        }

        let mut visitor = FieldValueVisitor::default();
        event.record(&mut visitor);
        let mut fields = visitor.fields;

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
        let extensions = span.extensions();
        let Some(label) = extensions.get::<QueryLabel>() else {
            return;
        };

        let query = label.0.clone();
        let record = self
            .pending_records
            .lock()
            .ok()
            .and_then(|mut pending_records| pending_records.remove(&query));

        if let Some(record) = record {
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
    prover: Map<String, Value>,
    proof_size_fields: Map<String, Value>,
    proof_size_crypto_breakdown: Map<String, Value>,
    proof_size_non_crypto_breakdown: Map<String, Value>,
    extra: Map<String, Value>,
}

impl PendingBenchRecord {
    fn new(query: String) -> Self {
        Self {
            timestamp_utc: now_utc_rfc3339_ms(),
            query,
            claims: Map::new(),
            prover: Map::new(),
            proof_size_fields: Map::new(),
            proof_size_crypto_breakdown: Map::new(),
            proof_size_non_crypto_breakdown: Map::new(),
            extra: Map::new(),
        }
    }

    fn merge(&mut self, fields: Map<String, Value>) {
        for (key, value) in fields {
            match key.as_str() {
                _ if key.starts_with("claims_") => {
                    self.claims.insert(key, value);
                }
                "proof_mv_commitments" | "proof_uv_commitments" => {
                    self.prover.insert(key, value);
                }
                "cryptographic_proof_size_bytes"
                | "non_cryptographic_proof_size_bytes"
                | "full_proof_size_bytes"
                | "full_compressed_proof_size_bytes" => {
                    self.proof_size_fields.insert(key, value);
                }
                "crypto_breakdown_sc_subproof"
                | "crypto_breakdown_mv_pcs_subproof"
                | "crypto_breakdown_uv_pcs_subproof"
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
        root.insert("timestamp".to_string(), Value::String(self.timestamp_utc.clone()));
        root.insert("timestamp_utc".to_string(), Value::String(self.timestamp_utc));
        root.insert("kind".to_string(), Value::String("bench_query".to_string()));
        root.insert("query".to_string(), Value::String(self.query));
        if !self.claims.is_empty() {
            root.insert("claims".to_string(), build_nested_claims(self.claims));
        }
        if !self.prover.is_empty() {
            root.insert("prover".to_string(), Value::Object(self.prover));
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
                        "breakdown": self.proof_size_crypto_breakdown
                    },
                    "non_crypto": {
                        "size": non_crypto_size,
                        "breakdown": self.proof_size_non_crypto_breakdown
                    }
                }),
            );
        }
        if !self.extra.is_empty() {
            root.insert("extra".to_string(), Value::Object(self.extra));
        }
        Value::Object(root)
    }
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
            "after-zero-batching": build_claim_stage(&claims, "claims_after_degree_reduction_after_zero_batching"),
            "after-sum-batching": build_claim_stage(&claims, "claims_after_degree_reduction_after_sum_batching")
        }
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

pub fn emit_proof_commitment_counts(mv_commitments: usize, uv_commitments: usize) {
    tracing::info!(
        target: BENCH_STATS_TARGET,
        proof_mv_commitments = mv_commitments,
        proof_uv_commitments = uv_commitments,
        "proof_commitments"
    );
}

pub fn emit_proof_size_bytes(
    query: &str,
    cryptographic_proof_size_bytes: usize,
    non_cryptographic_proof_size_bytes: usize,
    full_proof_size_bytes: usize,
    full_compressed_proof_size_bytes: usize,
    crypto_breakdown_sc_subproof: usize,
    crypto_breakdown_mv_pcs_subproof: usize,
    crypto_breakdown_uv_pcs_subproof: usize,
    crypto_breakdown_miscellaneous_field_elements: usize,
) {
    tracing::info!(
        target: BENCH_STATS_TARGET,
        query,
        cryptographic_proof_size_bytes,
        non_cryptographic_proof_size_bytes,
        full_proof_size_bytes,
        full_compressed_proof_size_bytes,
        crypto_breakdown_sc_subproof,
        crypto_breakdown_mv_pcs_subproof,
        crypto_breakdown_uv_pcs_subproof,
        crypto_breakdown_miscellaneous_field_elements,
        "proof_sizes"
    );
}
