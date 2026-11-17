//! The host side of the SP1 zkVM baseline: the data owner's commitment, and
//! proving and verifying one query in each proof mode.
//!
//! `SP1_PROVER` picks the prover (`cpu`, or `cuda` with `--features cuda`).
//! `ZKVM_MODES` (comma-separated, default `compressed,groth16`) picks the
//! proof modes; `ZKVM_EXECUTE_ONLY=1` only counts the guest's instructions.
//! Every run prints one line:
//!   query <label> mode=<m> commit_ms=<ms> commitment_bytes=<b> cycles=<n>
//!     prove_ms=<ms> proof_bytes=<b> raw_proof_bytes=<b> verify_ms=<ms>
//!     result_rows=<n>
//! `proof_bytes` is the saved proof the verifier loads; `raw_proof_bytes` is
//! the Groth16 proof alone (0 for a compressed proof).

use std::{
    fs::File,
    io::{BufReader, BufWriter},
    path::{Path, PathBuf},
    time::Instant,
};

use arrow::{
    array::{
        Array, AsArray, Date32Array, Decimal128Array, Int32Array, Int64Array, RecordBatchReader,
        UInt8Array,
    },
    datatypes::DataType,
};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use sp1_sdk::{
    blocking::{EnvProver, EnvProvingKey, ProveRequest, Prover, ProverClient},
    include_elf, Elf, ProvingKey, SP1ProofMode, SP1ProofWithPublicValues, SP1Stdin,
};
use tt_zkvm_lib::{hash, result_hash, Column, Hash, PublicValues, Query};

const ELF: Elf = include_elf!("tt-zkvm-program");

/// A table's published commitment: its row count and every column's hash.
#[derive(serde::Serialize, serde::Deserialize)]
struct TableCommitment {
    num_rows: u64,
    columns: Vec<(String, Hash)>,
}

pub struct Table {
    pub name: String,
    pub columns: Vec<(String, Column)>,
}

impl Table {
    fn column(&self, name: &str) -> &Column {
        &self
            .columns
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("no column {name} in {}", self.name))
            .1
    }
}

/// Loads every column of a parquet file the zkVM layout supports; other
/// columns are skipped, so no query may read them. With `strip_padding`, keeps
/// the rows whose `__activator__` is set and drops the `__` system columns
/// (the `_poneglyph` tables exist only padded).
pub fn load_table(name: &str, path: &Path, strip_padding: bool) -> Table {
    let file =
        File::open(path).unwrap_or_else(|err| panic!("missing parquet {}: {err}", path.display()));
    let reader = ParquetRecordBatchReaderBuilder::try_new(file)
        .expect("parquet reader")
        .build()
        .expect("parquet reader");
    let schema = reader.schema();
    let mut batches: Vec<_> = reader.collect::<Result<_, _>>().expect("read parquet");
    if strip_padding {
        let activator = schema.index_of("__activator__").expect("activator column");
        batches = batches
            .iter()
            .map(|b| {
                arrow::compute::filter_record_batch(b, b.column(activator).as_boolean())
                    .expect("filter active rows")
            })
            .collect();
    }
    let columns = schema
        .fields()
        .iter()
        .enumerate()
        .filter(|(_, field)| !field.name().starts_with("__"))
        .filter_map(|(i, field)| {
            let arrays: Vec<&dyn Array> = batches.iter().map(|b| b.column(i).as_ref()).collect();
            let column = match field.data_type() {
                DataType::Int64 => Column::I64(
                    arrays
                        .iter()
                        .flat_map(|a| {
                            a.as_any()
                                .downcast_ref::<Int64Array>()
                                .unwrap()
                                .values()
                                .to_vec()
                        })
                        .collect(),
                ),
                DataType::Int32 => Column::I32(
                    arrays
                        .iter()
                        .flat_map(|a| {
                            a.as_any()
                                .downcast_ref::<Int32Array>()
                                .unwrap()
                                .values()
                                .to_vec()
                        })
                        .collect(),
                ),
                DataType::Date32 => Column::I32(
                    arrays
                        .iter()
                        .flat_map(|a| {
                            a.as_any()
                                .downcast_ref::<Date32Array>()
                                .unwrap()
                                .values()
                                .to_vec()
                        })
                        .collect(),
                ),
                DataType::UInt64 => Column::I64(
                    arrays
                        .iter()
                        .flat_map(|a| {
                            a.as_primitive::<arrow::datatypes::UInt64Type>()
                                .values()
                                .iter()
                                .map(|&v| i64::try_from(v).expect("u64 fits i64"))
                                .collect::<Vec<_>>()
                        })
                        .collect(),
                ),
                DataType::UInt8 => Column::U8(
                    arrays
                        .iter()
                        .flat_map(|a| {
                            a.as_any()
                                .downcast_ref::<UInt8Array>()
                                .unwrap()
                                .values()
                                .to_vec()
                        })
                        .collect(),
                ),
                // TPC-H decimals are DECIMAL(15, 2): cents fit an i64.
                DataType::Decimal128(_, 2) => Column::I64(
                    arrays
                        .iter()
                        .flat_map(|a| {
                            a.as_any()
                                .downcast_ref::<Decimal128Array>()
                                .unwrap()
                                .values()
                                .iter()
                                .map(|&v| i64::try_from(v).expect("decimal fits i64"))
                                .collect::<Vec<_>>()
                        })
                        .collect(),
                ),
                DataType::Utf8 | DataType::Utf8View | DataType::LargeUtf8 => {
                    let mut strings = Vec::new();
                    for a in &arrays {
                        match a.data_type() {
                            DataType::Utf8View => strings.extend(
                                a.as_string_view()
                                    .iter()
                                    .map(|s| s.unwrap_or("").to_string()),
                            ),
                            DataType::LargeUtf8 => strings.extend(
                                a.as_string::<i64>()
                                    .iter()
                                    .map(|s| s.unwrap_or("").to_string()),
                            ),
                            _ => strings.extend(
                                a.as_string::<i32>()
                                    .iter()
                                    .map(|s| s.unwrap_or("").to_string()),
                            ),
                        }
                    }
                    Column::from_strings(strings.iter().map(String::as_str))
                }
                _ => return None,
            };
            Some((field.name().clone(), column))
        })
        .collect();
    Table {
        name: name.to_string(),
        columns,
    }
}

/// A result as text rows, in the format of DataFusion's CSV writer.
pub fn result_rows(result: &[Column]) -> Vec<Vec<String>> {
    let rows = result.first().map_or(0, Column::len);
    (0..rows)
        .map(|r| {
            result
                .iter()
                .map(|column| match column {
                    Column::I64(v) => v[r].to_string(),
                    Column::U8(v) => v[r].to_string(),
                    Column::I32(v) => v[r].to_string(),
                    Column::Date(v) => civil(v[r]),
                    Column::Str { .. } => String::from_utf8_lossy(column.str_at(r)).into_owned(),
                    Column::Dec { scale, values } => {
                        let (v, s) = (values[r], *scale as u32);
                        let p = 10i128.pow(s);
                        let sign = if v < 0 { "-" } else { "" };
                        if s == 0 {
                            v.to_string()
                        } else {
                            format!("{sign}{}.{:0w$}", v.abs() / p, v.abs() % p, w = s as usize)
                        }
                    }
                })
                .collect()
        })
        .collect()
}

/// The civil date (YYYY-MM-DD) of days since 1970-01-01.
fn civil(days: i32) -> String {
    let z = days as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Compares a result with DataFusion's CSV of the same query, up to row order
/// (ORDER BY ties and LIMIT boundaries are not unique) and to 0.01 in numbers
/// (AVG and decimal division round differently). DataFusion writes a NULL
/// aggregate as an empty row; a hand-written query returns no row.
pub fn check_against(result: &[Column], reference: &Path) -> Result<(), String> {
    let mut reader = csv::Reader::from_path(reference).map_err(|e| e.to_string())?;
    let mut expected: Vec<Vec<String>> = reader
        .records()
        .map(|r| r.map(|r| r.iter().map(str::to_string).collect()))
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    expected.retain(|row| row.iter().any(|cell| !cell.is_empty()));
    let mut actual = result_rows(result);
    let key = |row: &Vec<String>| -> Vec<String> {
        row.iter()
            .map(|c| {
                c.parse::<f64>()
                    .map_or(c.clone(), |x| format!("{:020.1}", x))
            })
            .collect()
    };
    expected.sort_by_key(key);
    actual.sort_by_key(key);
    if expected.len() != actual.len() {
        return Err(format!(
            "{} rows, DataFusion has {}",
            actual.len(),
            expected.len()
        ));
    }
    for (a, e) in actual.iter().zip(&expected) {
        let same = a.len() == e.len()
            && a.iter()
                .zip(e)
                .all(|(x, y)| match (x.parse::<f64>(), y.parse::<f64>()) {
                    (Ok(x), Ok(y)) => (x - y).abs() <= 0.01 + 1e-9 * y.abs(),
                    _ => x == y,
                });
        if !same {
            return Err(format!("row {a:?}, DataFusion has {e:?}"));
        }
    }
    Ok(())
}

pub fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

pub fn env_list(name: &str) -> Option<Vec<String>> {
    std::env::var(name).ok().map(|v| {
        v.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    })
}

pub struct Bench {
    // Options so `Drop` can drop them inside a tokio runtime.
    client: Option<EnvProver>,
    pk: Option<EnvProvingKey>,
    modes: Vec<(&'static str, SP1ProofMode)>,
    execute_only: bool,
}

impl Bench {
    pub fn new() -> Self {
        let client = ProverClient::from_env();
        let modes = env_list("ZKVM_MODES")
            .unwrap_or_else(|| vec!["compressed".into(), "groth16".into()])
            .iter()
            .map(|m| match m.as_str() {
                "compressed" => ("compressed", SP1ProofMode::Compressed),
                "groth16" => ("groth16", SP1ProofMode::Groth16),
                other => panic!("unknown ZKVM_MODES entry {other}"),
            })
            .collect();
        println!(
            "prover: {}",
            std::env::var("SP1_PROVER").unwrap_or_else(|_| "cpu".into())
        );
        println!(
            "threads: {}",
            std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "all".into())
        );
        let start = Instant::now();
        let pk = client.setup(ELF).expect("setup");
        println!("setup_ms: {:.1}", start.elapsed().as_secs_f64() * 1e3);
        Bench {
            client: Some(client),
            pk: Some(pk),
            modes,
            execute_only: std::env::var("ZKVM_EXECUTE_ONLY").is_ok_and(|v| v == "1"),
        }
    }

    /// Data owner: hashes every column of every table into `<dir>/<table>.sp1hash`.
    /// Returns the commitment paths, the time and the total size.
    pub fn commit(&self, dir: &Path, tables: &[&Table]) -> (Vec<PathBuf>, f64, u64) {
        let start = Instant::now();
        let paths: Vec<PathBuf> = tables
            .iter()
            .map(|table| {
                let commitment = TableCommitment {
                    num_rows: table.columns.first().map_or(0, |(_, c)| c.len() as u64),
                    columns: table
                        .columns
                        .iter()
                        .map(|(name, column)| (name.clone(), hash(&column.encode())))
                        .collect(),
                };
                let path = dir.join(format!("{}.sp1hash", table.name));
                bincode::serialize_into(
                    BufWriter::new(File::create(&path).expect("create commitment")),
                    &commitment,
                )
                .expect("write commitment");
                path
            })
            .collect();
        let commit_ms = start.elapsed().as_secs_f64() * 1e3;
        let bytes = paths.iter().map(|p| file_len(p)).sum();
        (paths, commit_ms, bytes)
    }

    /// Proves `query` over `tables` (in the order its inputs index them) in
    /// every mode, verifies each proof against the commitments, and prints
    /// one line per mode. `commit` is [`Bench::commit`]'s time and size,
    /// reported on each line.
    pub fn run(
        &self,
        label: &str,
        query: Query,
        tables: &[&Table],
        commitment_paths: &[PathBuf],
        commit: (f64, u64),
        dir: &Path,
    ) {
        let (client, pk) = (self.client.as_ref().unwrap(), self.pk.as_ref().unwrap());
        let inputs: Vec<&Column> = query
            .inputs()
            .iter()
            .map(|&(t, col)| tables[t].column(col))
            .collect();
        // The result the verifier is handed, outside the proof.
        let claimed = query.run(&inputs.iter().map(|c| (*c).clone()).collect::<Vec<_>>());
        let stdin = || {
            let mut stdin = SP1Stdin::new();
            stdin.write(&query);
            for column in &inputs {
                stdin.write_vec(column.encode());
            }
            stdin
        };

        let (_, report) = client.execute(ELF, stdin()).run().expect("execute");
        let cycles = report.total_instruction_count();
        if self.execute_only {
            println!("execute {label} cycles={cycles}");
            return;
        }

        for &(mode_name, mode) in &self.modes {
            let proof_path = dir.join(format!("sp1_{mode_name}.proof"));
            let start = Instant::now();
            let proof = client.prove(pk, stdin()).mode(mode).run().expect("prove");
            proof.save(&proof_path).expect("save proof");
            let prove_ms = start.elapsed().as_secs_f64() * 1e3;
            let raw_proof_bytes = if mode == SP1ProofMode::Groth16 {
                proof.bytes().len()
            } else {
                0
            };

            let start = Instant::now();
            let proof = SP1ProofWithPublicValues::load(&proof_path).expect("load proof");
            client
                .verify(&proof, pk.verifying_key(), None)
                .expect("verify proof");
            let public: PublicValues = proof.public_values.clone().read();
            assert_eq!(public.query, query, "proof is for another query");
            let commitments: Vec<TableCommitment> = commitment_paths
                .iter()
                .map(|p| {
                    bincode::deserialize_from(BufReader::new(
                        File::open(p).expect("open commitment"),
                    ))
                    .expect("read commitment")
                })
                .collect();
            for (&(t, col), proven) in query.inputs().iter().zip(&public.input_hashes) {
                let published = commitments[t]
                    .columns
                    .iter()
                    .find(|(name, _)| name == col)
                    .expect("committed column");
                assert_eq!(
                    &published.1, proven,
                    "input {col} is not the committed column"
                );
            }
            assert_eq!(
                public.result_hash,
                result_hash(&claimed),
                "result does not match the proof"
            );
            let verify_ms = start.elapsed().as_secs_f64() * 1e3;

            println!(
                "query {label} mode={mode_name} commit_ms={:.4} commitment_bytes={} cycles={cycles} prove_ms={prove_ms:.1} proof_bytes={} raw_proof_bytes={raw_proof_bytes} verify_ms={verify_ms:.4} result_rows={}",
                commit.0,
                commit.1,
                file_len(&proof_path),
                claimed.first().map_or(0, Column::len)
            );
        }
    }

    /// The result of `query` on the host, for checking it against SQL.
    pub fn result(query: Query, tables: &[&Table]) -> Vec<Column> {
        let inputs: Vec<Column> = query
            .inputs()
            .iter()
            .map(|&(t, col)| tables[t].column(col).clone())
            .collect();
        query.run(&inputs)
    }
}

impl Default for Bench {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        // The CUDA prover's key and client spawn tokio tasks when dropped,
        // which panics outside a runtime.
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let _guard = rt.enter();
        self.pk.take();
        self.client.take();
    }
}
