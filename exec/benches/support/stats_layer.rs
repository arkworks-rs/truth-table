use std::{
    collections::BTreeMap,
    fmt,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use chrono::Utc;
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id},
};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

const BENCH_STATS_TARGET: &str = "bench_stats";
const CSV_HEADER: &str = "timestamp_utc,query,nonzerocheck_claims,nonzerocheck_degree_distribution,zerocheck_claims,zerocheck_degree_distribution,sumcheck_claims,sumcheck_degree_distribution,lookup_claims,reduce_degree::max degree,reduce_degree::num commited,sumcheck::degree,sumcheck::number of terms,sumcheck::prove time s\n";
pub const BENCH_STATS_CSV_PATH: &str = "target/bench_stats.csv";

pub struct BenchStatsCsvLayer {
    sink: Arc<Mutex<CsvSink>>,
}

#[derive(Clone)]
struct QueryLabel(String);

impl BenchStatsCsvLayer {
    pub fn new_default() -> std::io::Result<Self> {
        Self::new(PathBuf::from(BENCH_STATS_CSV_PATH))
    }

    pub fn new(path: PathBuf) -> std::io::Result<Self> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }

        if path.exists() && !has_current_header(&path)? {
            let backup = backup_path_for(&path);
            if backup.exists() {
                std::fs::remove_file(&backup)?;
            }
            std::fs::rename(&path, &backup)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;
        let is_empty = file.metadata()?.len() == 0;

        let mut writer = BufWriter::new(file);
        if is_empty {
            writer.write_all(CSV_HEADER.as_bytes())?;
            writer.flush()?;
        }

        Ok(Self {
            sink: Arc::new(Mutex::new(CsvSink { writer, path })),
        })
    }
}

fn has_current_header(path: &Path) -> std::io::Result<bool> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut first_line = String::new();
    let _ = reader.read_line(&mut first_line)?;
    Ok(first_line.trim_end() == CSV_HEADER.trim_end())
}

fn backup_path_for(path: &Path) -> PathBuf {
    let mut backup = path.to_path_buf();
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) if !ext.is_empty() => backup.set_extension(format!("{ext}.bak")),
        _ => backup.set_extension("bak"),
    };
    backup
}

impl<S> Layer<S> for BenchStatsCsvLayer
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

        let nonzerocheck_claims = fields.remove("nonzerocheck_claims").unwrap_or_default();
        let nonzerocheck_degree_distribution = fields
            .remove("nonzerocheck_degree_distribution")
            .unwrap_or_default();
        let zerocheck_claims = fields.remove("zerocheck_claims").unwrap_or_default();
        let zerocheck_degree_distribution = fields
            .remove("zerocheck_degree_distribution")
            .unwrap_or_default();
        let sumcheck_claims = fields.remove("sumcheck_claims").unwrap_or_default();
        let sumcheck_degree_distribution = fields
            .remove("sumcheck_degree_distribution")
            .unwrap_or_default();
        let lookup_claims = fields.remove("lookup_claims").unwrap_or_default();
        let reduce_degree_max_degree = fields
            .remove("reduce_degree_max_degree")
            .unwrap_or_default();
        let reduce_degree_num_commited = fields
            .remove("reduce_degree_num_commited")
            .unwrap_or_default();
        let sumcheck_degree = fields.remove("sumcheck_degree").unwrap_or_default();
        let sumcheck_num_terms = fields.remove("sumcheck_num_terms").unwrap_or_default();
        let sumcheck_prove_time_s = fields.remove("sumcheck_prove_time_s").unwrap_or_default();

        // Only persist rows for claim-count events.
        if nonzerocheck_claims.is_empty()
            && zerocheck_claims.is_empty()
            && sumcheck_claims.is_empty()
            && lookup_claims.is_empty()
        {
            return;
        }

        let query = fields
            .remove("query")
            .filter(|q| !q.is_empty())
            .or_else(|| query_from_scope(&ctx, event))
            .unwrap_or_default();

        let row = CsvRow {
            timestamp_utc: now_utc_rfc3339_ms(),
            query,
            nonzerocheck_claims,
            nonzerocheck_degree_distribution,
            zerocheck_claims,
            zerocheck_degree_distribution,
            sumcheck_claims,
            sumcheck_degree_distribution,
            lookup_claims,
            reduce_degree_max_degree,
            reduce_degree_num_commited,
            sumcheck_degree,
            sumcheck_num_terms,
            sumcheck_prove_time_s,
        };

        if let Ok(mut sink) = self.sink.lock()
            && let Err(err) = sink.write_row(&row)
        {
            eprintln!(
                "failed to append bench stats row to {}: {}",
                sink.path.display(),
                err
            );
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

struct CsvSink {
    writer: BufWriter<File>,
    path: PathBuf,
}

impl CsvSink {
    fn write_row(&mut self, row: &CsvRow) -> std::io::Result<()> {
        let values = [
            &row.timestamp_utc,
            &row.query,
            &row.nonzerocheck_claims,
            &row.nonzerocheck_degree_distribution,
            &row.zerocheck_claims,
            &row.zerocheck_degree_distribution,
            &row.sumcheck_claims,
            &row.sumcheck_degree_distribution,
            &row.lookup_claims,
            &row.reduce_degree_max_degree,
            &row.reduce_degree_num_commited,
            &row.sumcheck_degree,
            &row.sumcheck_num_terms,
            &row.sumcheck_prove_time_s,
        ];

        for (idx, value) in values.iter().enumerate() {
            if idx > 0 {
                self.writer.write_all(b",")?;
            }
            write_csv_value(&mut self.writer, value)?;
        }
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }
}

struct CsvRow {
    timestamp_utc: String,
    query: String,
    nonzerocheck_claims: String,
    nonzerocheck_degree_distribution: String,
    zerocheck_claims: String,
    zerocheck_degree_distribution: String,
    sumcheck_claims: String,
    sumcheck_degree_distribution: String,
    lookup_claims: String,
    reduce_degree_max_degree: String,
    reduce_degree_num_commited: String,
    sumcheck_degree: String,
    sumcheck_num_terms: String,
    sumcheck_prove_time_s: String,
}

fn now_utc_rfc3339_ms() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn write_csv_value(writer: &mut BufWriter<File>, value: &str) -> std::io::Result<()> {
    let needs_quotes = value.contains(',') || value.contains('"') || value.contains('\n');
    if !needs_quotes {
        writer.write_all(value.as_bytes())?;
        return Ok(());
    }

    writer.write_all(b"\"")?;
    for ch in value.chars() {
        if ch == '"' {
            writer.write_all(b"\"\"")?;
        } else {
            let mut buf = [0u8; 4];
            writer.write_all(ch.encode_utf8(&mut buf).as_bytes())?;
        }
    }
    writer.write_all(b"\"")?;
    Ok(())
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

// Kept for compatibility with existing callsites; rows are emitted by claim-count events.
pub fn emit_benchmark_stats_row(_benchmark: &'static str, _case: &str) {}

pub fn default_csv_path() -> &'static Path {
    Path::new(BENCH_STATS_CSV_PATH)
}
