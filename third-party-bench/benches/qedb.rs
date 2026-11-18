//! QEDB on the micro queries it supports, built from `qedb-primitives`' tests the
//! way its own benchmark builds its queries (App. E of the QEDB paper):
//!
//! - `col = v`: the set of rows holding `v`, from an inverted index committed at
//!   preprocessing; an AND of equalities is the intersection of those sets, and an
//!   IN list their union;
//! - `lo <= col <= hi`: the prover sends the rows in, below and above the range;
//!   two complement tests check they partition the table, and sign checks put
//!   each row on its side of `lo` and `hi`;
//! - a projection reads each column on the selected set; SUM and COUNT are sum
//!   checks of the column and of the all-ones slice.
//!
//! Preprocessing commits the columns and the inverted indices the query needs; it
//! is the data owner's commitment time.

use std::{collections::HashMap, time::Instant};

use ark_serialize_06::CanonicalSerialize;
use ark_std_06::rand::{SeedableRng, rngs::StdRng};
use qedb_primitives::{
    Error,
    basic::{
        complement::ComplementProof, intersection::IntersectionProof, read::ReadProof,
        union::UnionProof,
    },
    curve::Fr,
    derived::{sign_check::SignCheckProof, sum_check::SumCheckProof},
    handle::{
        CommittedSet, CommittedSlice, Set, SetHandle, Slice, SliceHandle, Universe, UniverseHandle,
    },
    setup::{Srs, VerifierKey},
    transcript::Transcript,
};
use tt_third_party_bench::micro;

/// Bits of the sign checks: every value and constant is below 2^32.
const ELL: usize = 32;

/// For each value of a column, the set of rows holding it.
struct Index {
    sets: HashMap<u64, CommittedSet>,
    empty: CommittedSet,
}

impl Index {
    fn build(srs: &Srs, column: &[u64]) -> Self {
        let mut rows: HashMap<u64, Vec<usize>> = HashMap::new();
        for (row, &value) in column.iter().enumerate() {
            rows.entry(value).or_default().push(row);
        }
        Self {
            sets: rows
                .into_iter()
                .map(|(value, rows)| (value, Set::new(rows).commit(srs).unwrap()))
                .collect(),
            empty: Set::new([]).commit(srs).unwrap(),
        }
    }

    fn get(&self, value: i64) -> &CommittedSet {
        self.sets.get(&(value as u64)).unwrap_or(&self.empty)
    }

    fn handle(&self, value: i64) -> SetHandle {
        self.get(value).handle()
    }
}

/// The data owner's commitment: every column, and an index on `indexed`.
struct Database {
    values: HashMap<&'static str, Vec<u64>>,
    universe: Universe,
    columns: HashMap<&'static str, CommittedSlice>,
    indices: HashMap<&'static str, Index>,
}

impl Database {
    fn preprocess(srs: &Srs, table: &str, rows: usize, indexed: &[&str]) -> Self {
        let values: HashMap<_, _> = micro::table(table, rows)
            .into_iter()
            .map(|(name, column)| {
                (
                    name,
                    column.into_iter().map(|v| v as u64).collect::<Vec<_>>(),
                )
            })
            .collect();
        let columns = values
            .iter()
            .map(|(&name, column)| {
                let slice = Slice::new(column.iter().map(|&v| Fr::from(v)).collect());
                (name, slice.commit(srs).unwrap())
            })
            .collect();
        let indices = indexed
            .iter()
            .map(|&name| {
                let (&name, column) = values.get_key_value(name).expect("indexed column");
                (name, Index::build(srs, column))
            })
            .collect();
        Self {
            universe: Universe::new(srs, rows).unwrap(),
            values,
            columns,
            indices,
        }
    }

    fn slice(&self, column: &str) -> &CommittedSlice {
        &self.columns[column]
    }

    fn handle(&self, column: &str) -> SliceHandle {
        self.columns[column].handle()
    }

    fn universe(&self) -> UniverseHandle {
        self.universe.handle()
    }

    /// The size of what the verifier holds: the handles of the universe, of
    /// every column and of every index set.
    fn digest_size(&self) -> usize {
        self.universe.handle().compressed_size()
            + self
                .columns
                .values()
                .map(|c| c.handle().compressed_size())
                .sum::<usize>()
            + self
                .indices
                .values()
                .flat_map(|i| i.sets.values().chain([&i.empty]))
                .map(|s| s.handle().compressed_size())
                .sum::<usize>()
    }
}

/// The answer the verifier is handed: the selected rows and the values read on
/// them, or the aggregates.
#[derive(Debug, PartialEq)]
enum Answer {
    Rows {
        rows: Vec<usize>,
        columns: Vec<Vec<Fr>>,
    },
    Aggregates(Vec<Fr>),
}

enum Selection {
    /// An AND of equalities.
    Intersection(SetHandle, IntersectionProof),
    /// An IN list.
    Union(SetHandle, UnionProof),
    /// A range.
    Range {
        selection: SetHandle,
        below: SetHandle,
        above: SetHandle,
        outside: SetHandle,
        complement: ComplementProof,
        split: ComplementProof,
        lower: SignCheckProof,
        upper: SignCheckProof,
    },
}

enum Proof {
    Read {
        selection: Selection,
        reads: Vec<ReadProof>,
    },
    Sums(Vec<SumCheckProof>),
}

impl Selection {
    fn handle(&self) -> SetHandle {
        match self {
            Selection::Intersection(set, _) | Selection::Union(set, _) => *set,
            Selection::Range { selection, .. } => *selection,
        }
    }

    /// Serialized size: the handles and tests it holds.
    fn size(&self) -> usize {
        match self {
            Selection::Intersection(set, proof) => set.compressed_size() + proof.compressed_size(),
            Selection::Union(set, proof) => set.compressed_size() + proof.compressed_size(),
            Selection::Range {
                selection,
                below,
                above,
                outside,
                complement,
                split,
                lower,
                upper,
            } => {
                [selection, below, above, outside]
                    .iter()
                    .map(|h| h.compressed_size())
                    .sum::<usize>()
                    + complement.compressed_size()
                    + split.compressed_size()
                    + lower.compressed_size()
                    + upper.compressed_size()
            }
        }
    }
}

impl Proof {
    fn size(&self) -> usize {
        match self {
            Proof::Read { selection, reads } => selection.size() + reads.compressed_size(),
            Proof::Sums(sums) => sums.compressed_size(),
        }
    }
}

/// The projected columns of a query that returns rows.
const PROJECTED: &[(&str, &[&str])] = &[
    ("filter_0p1", &["a", "b", "c", "d"]),
    ("filter_1", &["a", "b", "c", "d"]),
    ("filter_10", &["a", "b", "c", "d"]),
    ("in_list", &["a", "b", "c", "d"]),
    ("range", &["a", "b"]),
];

fn indexed(query: &str) -> &'static [&'static str] {
    match query {
        "filter_0p1" | "filter_1" | "filter_10" => &["a", "b"],
        "in_list" => &["a"],
        "aggregate" => &["b"],
        _ => &[],
    }
}

fn transcript(query: &str) -> Transcript {
    let mut transcript = Transcript::new("micro");
    transcript.append("query", query.as_bytes());
    transcript
}

fn rows_where(db: &Database, column: &str, keep: impl Fn(u64) -> bool) -> Set {
    Set::new((0..db.values[column].len()).filter(|&r| keep(db.values[column][r])))
}

fn prove_selection(
    srs: &Srs,
    db: &Database,
    query: &str,
    t: &mut Transcript,
) -> (CommittedSet, Selection) {
    match query {
        "filter_0p1" | "filter_1" | "filter_10" => {
            let (a, b) = (
                db.indices["a"].get(micro::FILTER_A),
                db.indices["b"].get(micro::FILTER_B),
            );
            let both = a
                .set()
                .difference(&a.set().difference(b.set()))
                .commit(srs)
                .unwrap();
            let proof = IntersectionProof::prove(srs, &[a, b], &both, t).unwrap();
            let handle = both.handle();
            (both, Selection::Intersection(handle, proof))
        }
        "in_list" => {
            let sets: Vec<&CommittedSet> = micro::IN_VALUES
                .iter()
                .map(|&v| db.indices["a"].get(v))
                .collect();
            let union = Set::new(sets.iter().flat_map(|s| s.set().rows()).copied())
                .commit(srs)
                .unwrap();
            let proof = UnionProof::prove(srs, &sets, &union, t).unwrap();
            let handle = union.handle();
            (union, Selection::Union(handle, proof))
        }
        "range" => {
            let (lo, hi) = (micro::RANGE.0 as u64, micro::RANGE.1 as u64);
            let (u, ones, v) = (&db.universe, db.universe.ones(), db.slice("a"));
            let constant = |c: u64| ones * Fr::from(c);
            let commit = |set: Set| set.commit(srs).unwrap();
            let selection = commit(rows_where(db, "a", |x| (lo..=hi).contains(&x)));
            let below = commit(rows_where(db, "a", |x| x < lo));
            let above = commit(rows_where(db, "a", |x| x > hi));
            let outside = commit(u.rows().set().difference(selection.set()));
            let complement =
                ComplementProof::prove(srs, u.rows(), &selection, &outside, t).unwrap();
            let split = ComplementProof::prove(srs, &outside, &below, &above, t).unwrap();
            let lower = SignCheckProof::prove(
                srs,
                &[
                    (&(v - &constant(lo)), &selection),
                    (&(&constant(lo - 1) - v), &below),
                    (&(v - &constant(hi + 1)), &above),
                ],
                ELL,
                t,
            )
            .unwrap();
            let upper =
                SignCheckProof::prove(srs, &[(&(&constant(hi) - v), &selection)], ELL, t).unwrap();
            let proof = Selection::Range {
                selection: selection.handle(),
                below: below.handle(),
                above: above.handle(),
                outside: outside.handle(),
                complement,
                split,
                lower,
                upper,
            };
            (selection, proof)
        }
        other => panic!("{other} does not select rows"),
    }
}

fn verify_selection(
    vk: &VerifierKey,
    db: &Database,
    proof: &Selection,
    t: &mut Transcript,
) -> Result<(), Error> {
    match proof {
        Selection::Intersection(both, intersection) => {
            let sets = [
                db.indices["a"].handle(micro::FILTER_A),
                db.indices["b"].handle(micro::FILTER_B),
            ];
            intersection.verify(&sets, *both, t)
        }
        Selection::Union(union, proof) => {
            let sets: Vec<SetHandle> = micro::IN_VALUES
                .iter()
                .map(|&v| db.indices["a"].handle(v))
                .collect();
            proof.verify(&sets, *union, t)
        }
        Selection::Range {
            selection,
            below,
            above,
            outside,
            complement,
            split,
            lower,
            upper,
        } => {
            let (lo, hi) = (micro::RANGE.0 as u64, micro::RANGE.1 as u64);
            let (u, v) = (db.universe(), db.handle("a"));
            let constant = |c: u64| u.ones * Fr::from(c);
            complement.verify(u.rows, *selection, *outside, t)?;
            split.verify(*outside, *below, *above, t)?;
            let parts = [
                (v - constant(lo), *selection),
                (constant(lo - 1) - v, *below),
                (v - constant(hi + 1), *above),
            ];
            lower.verify(vk, &parts, ELL, t)?;
            upper.verify(vk, &[(constant(hi) - v, *selection)], ELL, t)
        }
    }
}

fn prove(srs: &Srs, db: &Database, query: &str) -> (Answer, Proof) {
    let t = &mut transcript(query);
    if query == "aggregate" {
        let set = db.indices["b"].get(micro::AGG_B);
        let rows = set.set().rows();
        let sum: u64 = rows.iter().map(|&r| db.values["a"][r]).sum();
        let count = rows.len() as u64;
        let sum_proof = SumCheckProof::prove(srs, db.slice("a"), set, Fr::from(sum), t).unwrap();
        let count_proof =
            SumCheckProof::prove(srs, db.universe.ones(), set, Fr::from(count), t).unwrap();
        let answer = Answer::Aggregates(vec![Fr::from(sum), Fr::from(count)]);
        return (answer, Proof::Sums(vec![sum_proof, count_proof]));
    }
    let (selected, selection) = prove_selection(srs, db, query, t);
    let projected = PROJECTED
        .iter()
        .find(|(q, _)| *q == query)
        .expect("projection")
        .1;
    let (columns, reads): (Vec<_>, Vec<_>) = projected
        .iter()
        .map(|&c| ReadProof::prove(srs, db.slice(c), &selected, t).unwrap())
        .unzip();
    let answer = Answer::Rows {
        rows: selected.set().rows().to_vec(),
        columns,
    };
    (answer, Proof::Read { selection, reads })
}

fn verify(
    vk: &VerifierKey,
    db: &Database,
    query: &str,
    answer: &Answer,
    proof: &Proof,
) -> Result<(), Error> {
    let t = &mut transcript(query);
    match (answer, proof) {
        (Answer::Aggregates(values), Proof::Sums(sums)) => {
            let set = db.indices["b"].handle(micro::AGG_B);
            sums[0].verify(vk, db.handle("a"), set, values[0], t)?;
            sums[1].verify(vk, db.universe().ones, set, values[1], t)
        }
        (Answer::Rows { rows, columns }, Proof::Read { selection, reads }) => {
            verify_selection(vk, db, selection, t)?;
            let projected = PROJECTED
                .iter()
                .find(|(q, _)| *q == query)
                .expect("projection")
                .1;
            for ((column, values), read) in projected.iter().zip(columns).zip(reads) {
                read.verify(vk, db.handle(column), selection.handle(), rows, values, t)?;
            }
            Ok(())
        }
        _ => Err(Error::Rejected("answer and proof do not match")),
    }
}

/// The answer computed in the clear, to check the proved one against.
fn expected(db: &Database, query: &str) -> Answer {
    let v = |c: &str| &db.values[c];
    let keep: Box<dyn Fn(usize) -> bool> = match query {
        "aggregate" => {
            let rows: Vec<usize> = (0..v("b").len())
                .filter(|&r| v("b")[r] == micro::AGG_B as u64)
                .collect();
            let sum: u64 = rows.iter().map(|&r| v("a")[r]).sum();
            return Answer::Aggregates(vec![Fr::from(sum), Fr::from(rows.len() as u64)]);
        }
        "range" => {
            Box::new(|r| (micro::RANGE.0 as u64..=micro::RANGE.1 as u64).contains(&v("a")[r]))
        }
        "in_list" => Box::new(|r| micro::IN_VALUES.contains(&(v("a")[r] as i64))),
        _ => {
            Box::new(|r| v("a")[r] == micro::FILTER_A as u64 && v("b")[r] == micro::FILTER_B as u64)
        }
    };
    let rows: Vec<usize> = (0..v("a").len()).filter(|&r| keep(r)).collect();
    let projected = PROJECTED
        .iter()
        .find(|(q, _)| *q == query)
        .expect("projection")
        .1;
    let columns = projected
        .iter()
        .map(|c| rows.iter().map(|&r| Fr::from(v(c)[r])).collect())
        .collect();
    Answer::Rows { rows, columns }
}

fn main() {
    let pows = micro::table_pows();
    println!("table_sizes: {pows:?}");
    for pow in pows {
        let rows = 1usize << pow;
        let start = Instant::now();
        let srs = Srs::setup(rows, &mut StdRng::seed_from_u64(pow.into())).unwrap();
        let setup_ms = start.elapsed().as_secs_f64() * 1e3;
        let vk = srs.verifier_key();
        // The prover's key is the whole structured reference string.
        let pk_bytes = srs.g1().iter().map(|p| p.compressed_size()).sum::<usize>()
            + srs.g2().iter().map(|p| p.compressed_size()).sum::<usize>()
            + srs
                .lagrange()
                .iter()
                .map(|p| p.compressed_size())
                .sum::<usize>();
        for query in micro::QUERIES
            .iter()
            .filter(|q| q.qedb && micro::selected(q))
        {
            println!("pow: {pow} query: {}", query.name);
            println!("setup_ms: {setup_ms:.3}");
            println!("pk_bytes: {pk_bytes}");
            println!("vk_bytes: {}", vk.compressed_size());
            let start = Instant::now();
            let db = Database::preprocess(&srs, query.tables[0], rows, indexed(query.name));
            println!("commit_ms: {:.3}", start.elapsed().as_secs_f64() * 1e3);
            println!("commitment_bytes: {}", db.digest_size());

            let start = Instant::now();
            let (answer, proof) = prove(&srs, &db, query.name);
            println!("prove_ms: {:.3}", start.elapsed().as_secs_f64() * 1e3);
            println!("proof_bytes: {}", proof.size());

            let verify_ms = micro::verify_median_ms(|| {
                verify(&vk, &db, query.name, &answer, &proof).expect("proof verifies")
            });
            println!("verify_ms: {verify_ms:.3}");
            assert_eq!(
                answer,
                expected(&db, query.name),
                "{}: wrong answer",
                query.name
            );
            let result_rows = match &answer {
                Answer::Rows { rows, .. } => rows.len(),
                Answer::Aggregates(_) => 1,
            };
            println!("result_rows: {result_rows}");
            println!("----------------------------------------");
        }
    }
}
