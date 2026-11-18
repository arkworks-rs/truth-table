//! The micro-benchmark queries and their tables, shared by every system's bench.
//!
//! A table is a pure function of its name and row count, so a bench that builds
//! its own tables (PoSQL through its column override, QEDB) sees the same data as
//! one that reads the parquet files written here (TruthTable, the baseline).
//! Every column is `BIGINT` and non-negative.

use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
};

use arrow::{
    array::{ArrayRef, Int64Array},
    datatypes::{DataType, Field, Schema},
    record_batch::RecordBatch,
};
use parquet::arrow::ArrowWriter;

/// Table sizes, as powers of two: `MICRO_POWS` (comma-separated) or 15 to 20.
pub fn table_pows() -> Vec<u32> {
    std::env::var("MICRO_POWS").map_or_else(
        |_| (15..=20).collect(),
        |v| {
            v.split(',')
                .map(|p| p.trim().parse().expect("MICRO_POWS"))
                .collect()
        },
    )
}

/// Whether `MICRO_QUERIES` (comma-separated names, default all) includes `query`.
pub fn selected(query: &MicroQuery) -> bool {
    std::env::var("MICRO_QUERIES").map_or(true, |v| v.split(',').any(|q| q.trim() == query.name))
}

pub struct MicroQuery {
    pub name: &'static str,
    /// `{t}` and, in a join, `{t2}` stand for the table names.
    pub sql: &'static str,
    pub tables: &'static [&'static str],
    /// In a join, the second table's `a` is a foreign key into the first's, and
    /// the first's `a` is its primary key.
    pub pk_fk: bool,
    pub posql: bool,
    pub qedb: bool,
}

/// The constants the queries use, for the benches that build a query by hand.
pub const FILTER_A: i64 = 1;
pub const FILTER_B: i64 = 2;
pub const AGG_B: i64 = 1;
pub const RANGE: (i64, i64) = (100, 199);
pub const ARITH_C: i64 = 1;
pub const IN_VALUES: [i64; 16] = [
    0, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200, 1300, 1400, 1500,
];

pub const QUERIES: &[MicroQuery] = &[
    MicroQuery {
        name: "filter_0p1",
        sql: "SELECT a, b, c, d FROM {t} WHERE a = 1 AND b = 2",
        tables: &["filter_0p1"],
        pk_fk: false,
        posql: true,
        qedb: true,
    },
    MicroQuery {
        name: "filter_1",
        sql: "SELECT a, b, c, d FROM {t} WHERE a = 1 AND b = 2",
        tables: &["filter_1"],
        pk_fk: false,
        posql: true,
        qedb: true,
    },
    MicroQuery {
        name: "filter_10",
        sql: "SELECT a, b, c, d FROM {t} WHERE a = 1 AND b = 2",
        tables: &["filter_10"],
        pk_fk: false,
        posql: true,
        qedb: true,
    },
    MicroQuery {
        name: "aggregate",
        sql: "SELECT SUM(a) AS sum_a, COUNT(*) AS cnt FROM {t} WHERE b = 1",
        tables: &["aggregate"],
        pk_fk: false,
        posql: true,
        qedb: true,
    },
    MicroQuery {
        name: "range",
        sql: "SELECT a, b FROM {t} WHERE a >= 100 AND a <= 199",
        tables: &["range"],
        pk_fk: false,
        posql: true,
        qedb: true,
    },
    MicroQuery {
        name: "in_list",
        sql: "SELECT a, b, c, d FROM {t} WHERE a IN (0, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200, 1300, 1400, 1500)",
        tables: &["in_list"],
        pk_fk: false,
        posql: true,
        qedb: true,
    },
    MicroQuery {
        name: "arithmetic",
        sql: "SELECT SUM(a * b) AS s FROM {t} WHERE c = 1",
        tables: &["arithmetic"],
        pk_fk: false,
        posql: true,
        qedb: false,
    },
    MicroQuery {
        name: "group_by",
        sql: "SELECT b, SUM(a) AS sum_a, COUNT(*) AS cnt FROM {t} GROUP BY b",
        tables: &["group_by"],
        pk_fk: false,
        posql: true,
        qedb: false,
    },
    MicroQuery {
        name: "join_pk_fk",
        sql: "SELECT {t}.a AS a1, {t2}.a AS a2 FROM {t}, {t2} WHERE {t}.a = {t2}.a",
        tables: &["join_pk_fk_l", "join_pk_fk_r"],
        pk_fk: true,
        posql: true,
        qedb: false,
    },
    MicroQuery {
        name: "join_m2m",
        sql: "SELECT {t}.a AS a1, {t2}.a AS a2 FROM {t}, {t2} WHERE {t}.a = {t2}.a",
        tables: &["join_m2m_l", "join_m2m_r"],
        pk_fk: false,
        posql: true,
        qedb: false,
    },
    MicroQuery {
        name: "order_by",
        sql: "SELECT a, b FROM {t} ORDER BY a LIMIT 10",
        tables: &["order_by"],
        pk_fk: false,
        posql: false,
        qedb: false,
    },
];

/// The query's SQL over the given table names, in the order of `tables`.
pub fn sql(query: &MicroQuery, names: &[&str]) -> String {
    let mut sql = query.sql.to_string();
    if let Some(t2) = names.get(1) {
        sql = sql.replace("{t2}", t2);
    }
    sql.replace("{t}", names[0])
}

/// SplitMix64, seeded by the table name, so tables do not depend on a crate's RNG.
struct Rng(u64);

impl Rng {
    fn new(table: &str) -> Self {
        Rng(table.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
            (h ^ b as u64).wrapping_mul(0x100_0000_01b3)
        }))
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u64) -> i64 {
        (self.next() % bound) as i64
    }

    fn uniform(&mut self, rows: usize, bound: u64) -> Vec<i64> {
        (0..rows).map(|_| self.below(bound)).collect()
    }

    fn permutation(&mut self, rows: usize) -> Vec<i64> {
        let mut values: Vec<i64> = (0..rows as i64).collect();
        for i in (1..rows).rev() {
            values.swap(i, self.below(i as u64 + 1) as usize);
        }
        values
    }

    /// `count` distinct rows out of `rows`, at random positions.
    fn rows(&mut self, rows: usize, count: usize) -> Vec<usize> {
        let mut order = self.permutation(rows);
        order.truncate(count);
        order.into_iter().map(|r| r as usize).collect()
    }
}

/// The columns of `table` with `rows` rows.
pub fn table(table: &str, rows: usize) -> Vec<(&'static str, Vec<i64>)> {
    let rng = &mut Rng::new(table);
    match table {
        // Exactly `rows * selectivity` rows have a = 1 AND b = 2; the others have
        // a and b in [0, 100), never both.
        "filter_0p1" | "filter_1" | "filter_10" => {
            let per_mille = match table {
                "filter_0p1" => 1,
                "filter_1" => 10,
                _ => 100,
            };
            let (mut a, mut b) = (Vec::with_capacity(rows), Vec::with_capacity(rows));
            for _ in 0..rows {
                let (x, y) = loop {
                    let (x, y) = (rng.below(100), rng.below(100));
                    if (x, y) != (FILTER_A, FILTER_B) {
                        break (x, y);
                    }
                };
                a.push(x);
                b.push(y);
            }
            for r in rng.rows(rows, rows * per_mille / 1000) {
                a[r] = FILTER_A;
                b[r] = FILTER_B;
            }
            let c = rng.uniform(rows, 1_000_000);
            let d = rng.uniform(rows, 1_000_000);
            vec![("a", a), ("b", b), ("c", c), ("d", d)]
        }
        // b = 1 on a tenth of the rows.
        "aggregate" => {
            let a = rng.uniform(rows, 1000);
            let mut b: Vec<i64> = (0..rows).map(|_| 2 + rng.below(98)).collect();
            for r in rng.rows(rows, rows / 10) {
                b[r] = AGG_B;
            }
            vec![("a", a), ("b", b)]
        }
        // a in [100, 199] on about a tenth of the rows.
        "range" => vec![
            ("a", rng.uniform(rows, 1000)),
            ("b", rng.uniform(rows, 1000)),
        ],
        // a in the 16 listed values on about 1% of the rows.
        "in_list" => vec![
            ("a", rng.uniform(rows, 1600)),
            ("b", rng.uniform(rows, 1_000_000)),
            ("c", rng.uniform(rows, 1_000_000)),
            ("d", rng.uniform(rows, 1_000_000)),
        ],
        // c = 1 on a tenth of the rows.
        "arithmetic" => {
            let a = rng.uniform(rows, 1000);
            let b = rng.uniform(rows, 1000);
            let mut c: Vec<i64> = (0..rows).map(|_| 2 + rng.below(98)).collect();
            for r in rng.rows(rows, rows / 10) {
                c[r] = ARITH_C;
            }
            vec![("a", a), ("b", b), ("c", c)]
        }
        // 100 groups.
        "group_by" => vec![
            ("a", rng.uniform(rows, 1000)),
            ("b", rng.uniform(rows, 100)),
        ],
        "join_pk_fk_l" => vec![("a", rng.permutation(rows))],
        "join_pk_fk_r" => vec![("a", rng.uniform(rows, rows as u64))],
        // Keys repeat on both sides; the join has about `rows` rows.
        "join_m2m_l" | "join_m2m_r" => vec![("a", rng.uniform(rows, rows as u64))],
        // Unique sort keys, so the first ten rows are well defined.
        "order_by" => vec![
            ("a", rng.permutation(rows)),
            ("b", rng.uniform(rows, 1_000_000)),
        ],
        other => panic!("unknown micro table {other}"),
    }
}

/// One column of [`table`], in the shape PoSQL's column override takes.
pub fn column(table_name: &str, column: &str, rows: usize) -> Option<Vec<i64>> {
    table(table_name, rows)
        .into_iter()
        .find(|(name, _)| *name == column)
        .map(|(_, values)| values)
}

pub fn query_dir(bench_root: &Path, pow: u32, query: &MicroQuery) -> PathBuf {
    bench_root
        .join("artifact/micro")
        .join(format!("size_{pow}"))
        .join(query.name)
}

/// `<table>_<pow>.parquet` for each of the query's tables, written on first use,
/// and for a PK/FK join the `constraints.json` naming its keys on the tables
/// `<table>_<pow><suffix>` (TruthTable reads its preprocessed copies).
pub fn ensure_parquets(
    bench_root: &Path,
    pow: u32,
    query: &MicroQuery,
    suffix: &str,
) -> Vec<PathBuf> {
    let dir = query_dir(bench_root, pow, query);
    std::fs::create_dir_all(&dir).expect("create micro dir");
    let paths: Vec<PathBuf> = query
        .tables
        .iter()
        .map(|name| {
            let path = dir.join(format!("{name}_{pow}.parquet"));
            if !path.exists() {
                write_parquet(&path, &table(name, 1 << pow));
            }
            path
        })
        .collect();
    if query.pk_fk {
        let [pk, fk] = query.tables else {
            panic!("a PK/FK join has two tables")
        };
        let constraints = serde_json::json!({
            "format_version": 1,
            "source": "third-party-bench-micro",
            "tables": [
                {
                    "table": format!("{pk}_{pow}{suffix}"),
                    "primary_key": ["a"],
                    "unique_keys": [],
                    "foreign_keys": [],
                },
                {
                    "table": format!("{fk}_{pow}{suffix}"),
                    "primary_key": [],
                    "unique_keys": [],
                    "foreign_keys": [{
                        "columns": ["a"],
                        "ref_table": format!("{pk}_{pow}{suffix}"),
                        "ref_columns": ["a"],
                    }],
                },
            ],
        });
        std::fs::write(
            dir.join("constraints.json"),
            serde_json::to_string_pretty(&constraints).expect("constraints json"),
        )
        .expect("write constraints");
    }
    paths
}

fn write_parquet(path: &Path, columns: &[(&str, Vec<i64>)]) {
    let schema = Arc::new(Schema::new(
        columns
            .iter()
            .map(|(name, _)| Field::new(*name, DataType::Int64, false))
            .collect::<Vec<_>>(),
    ));
    let arrays = columns
        .iter()
        .map(|(_, values)| Arc::new(Int64Array::from(values.clone())) as ArrayRef)
        .collect();
    let batch = RecordBatch::try_new(Arc::clone(&schema), arrays).expect("record batch");
    let mut writer =
        ArrowWriter::try_new(File::create(path).expect("create parquet"), schema, None)
            .expect("parquet writer");
    writer.write(&batch).expect("write parquet");
    writer.close().expect("close parquet");
}

/// Runs `verify` for up to a second (at least once) and returns the median
/// time in milliseconds. Provers run once; verifiers, often far faster, are
/// repeated to steady the measurement.
pub fn verify_median_ms(mut verify: impl FnMut()) -> f64 {
    let budget = std::time::Duration::from_secs(1);
    let mut times = Vec::new();
    let mut total = std::time::Duration::ZERO;
    while times.is_empty() || total < budget {
        let start = std::time::Instant::now();
        verify();
        let elapsed = start.elapsed();
        total += elapsed;
        times.push(elapsed);
    }
    times.sort();
    times[times.len() / 2].as_secs_f64() * 1e3
}
