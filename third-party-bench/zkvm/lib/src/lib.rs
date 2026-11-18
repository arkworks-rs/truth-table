//! Shared by the SP1 guest and the host: the column layout the data owner
//! hashes, the queries, and the public values a proof commits to.
//!
//! The data owner publishes the SHA-256 hash of every column in [`Column`]'s
//! encoding. The guest reads the encoded columns a query needs, hashes them,
//! runs the query and commits [`PublicValues`]: the query, the input hashes
//! and the hash of the result. The verifier checks the proof, compares the
//! input hashes with the published ones and hashes the result it was given.

use std::{
    collections::HashMap,
    hash::{BuildHasherDefault, Hasher},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod tpch;

pub type Hash = [u8; 32];

pub fn hash(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

/// A column. Encoded as a type tag, the row count (u64, little endian) and
/// the values, little endian: a string column as `len + 1` u32 offsets and
/// then the bytes, a decimal as its scale byte and then i128 values.
#[derive(Clone, Debug, PartialEq)]
pub enum Column {
    I64(Vec<i64>),
    U8(Vec<u8>),
    I32(Vec<i32>),
    /// Days since 1970-01-01.
    Date(Vec<i32>),
    Str {
        offsets: Vec<u32>,
        bytes: Vec<u8>,
    },
    /// Exact decimals: `values[i] / 10^scale`.
    Dec {
        scale: u8,
        values: Vec<i128>,
    },
}

const TAG_I64: u8 = 0;
const TAG_U8: u8 = 1;
const TAG_I32: u8 = 2;
const TAG_DATE: u8 = 3;
const TAG_STR: u8 = 4;
const TAG_DEC: u8 = 5;

impl Column {
    pub fn len(&self) -> usize {
        match self {
            Column::I64(v) => v.len(),
            Column::U8(v) => v.len(),
            Column::I32(v) | Column::Date(v) => v.len(),
            Column::Str { offsets, .. } => offsets.len() - 1,
            Column::Dec { values, .. } => values.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn from_strings<'a>(strings: impl IntoIterator<Item = &'a str>) -> Column {
        let mut offsets = vec![0u32];
        let mut bytes = Vec::new();
        for s in strings {
            bytes.extend_from_slice(s.as_bytes());
            offsets.push(bytes.len() as u32);
        }
        Column::Str { offsets, bytes }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let header = |out: &mut Vec<u8>, tag: u8, len: usize| {
            out.push(tag);
            out.extend_from_slice(&(len as u64).to_le_bytes());
        };
        match self {
            Column::I64(v) => {
                header(&mut out, TAG_I64, v.len());
                v.iter()
                    .for_each(|x| out.extend_from_slice(&x.to_le_bytes()));
            }
            Column::U8(v) => {
                header(&mut out, TAG_U8, v.len());
                out.extend_from_slice(v);
            }
            Column::I32(v) | Column::Date(v) => {
                let tag = if matches!(self, Column::I32(_)) {
                    TAG_I32
                } else {
                    TAG_DATE
                };
                header(&mut out, tag, v.len());
                v.iter()
                    .for_each(|x| out.extend_from_slice(&x.to_le_bytes()));
            }
            Column::Str { offsets, bytes } => {
                header(&mut out, TAG_STR, offsets.len() - 1);
                offsets
                    .iter()
                    .for_each(|x| out.extend_from_slice(&x.to_le_bytes()));
                out.extend_from_slice(bytes);
            }
            Column::Dec { scale, values } => {
                header(&mut out, TAG_DEC, values.len());
                out.push(*scale);
                values
                    .iter()
                    .for_each(|x| out.extend_from_slice(&x.to_le_bytes()));
            }
        }
        out
    }

    /// Panics on a malformed encoding; in the guest that fails the proof.
    pub fn decode(bytes: &[u8]) -> Column {
        let len = u64::from_le_bytes(bytes[1..9].try_into().unwrap()) as usize;
        let body = &bytes[9..];
        fn words<const N: usize, T>(body: &[u8], len: usize, f: impl Fn([u8; N]) -> T) -> Vec<T> {
            assert!(body.len() >= len * N, "malformed column");
            body[..len * N]
                .chunks_exact(N)
                .map(|c| f(c.try_into().unwrap()))
                .collect()
        }
        let (column, used) = match bytes[0] {
            TAG_I64 => (Column::I64(words(body, len, i64::from_le_bytes)), len * 8),
            TAG_U8 => (Column::U8(body[..len].to_vec()), len),
            TAG_I32 => (Column::I32(words(body, len, i32::from_le_bytes)), len * 4),
            TAG_DATE => (Column::Date(words(body, len, i32::from_le_bytes)), len * 4),
            TAG_STR => {
                let offsets = words(body, len + 1, u32::from_le_bytes);
                let data = &body[(len + 1) * 4..];
                assert!(
                    offsets.windows(2).all(|w| w[0] <= w[1])
                        && *offsets.last().unwrap() as usize == data.len(),
                    "malformed string column"
                );
                let used = (len + 1) * 4 + data.len();
                (
                    Column::Str {
                        offsets,
                        bytes: data.to_vec(),
                    },
                    used,
                )
            }
            TAG_DEC => (
                Column::Dec {
                    scale: body[0],
                    values: words(&body[1..], len, i128::from_le_bytes),
                },
                1 + len * 16,
            ),
            tag => panic!("unknown column tag {tag}"),
        };
        assert_eq!(body.len(), used, "trailing bytes in column");
        column
    }

    pub fn i64s(&self) -> &[i64] {
        match self {
            Column::I64(v) => v,
            _ => panic!("expected an i64 column"),
        }
    }

    pub fn i32s(&self) -> &[i32] {
        match self {
            Column::I32(v) | Column::Date(v) => v,
            _ => panic!("expected an i32 or date column"),
        }
    }

    /// The `i`-th string of a string column.
    pub fn str_at(&self, i: usize) -> &[u8] {
        match self {
            Column::Str { offsets, bytes } => &bytes[offsets[i] as usize..offsets[i + 1] as usize],
            _ => panic!("expected a string column"),
        }
    }
}

/// The hash of a result: of its columns' encodings, in order.
pub fn result_hash(result: &[Column]) -> Hash {
    let mut hasher = Sha256::new();
    for column in result {
        hasher.update(column.encode());
    }
    hasher.finalize().into()
}

/// The micro queries of `third-party-bench/benches/truth_table.rs`, and the
/// TPC-H queries of [`tpch`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Query {
    /// `SELECT a, b, c, d FROM t WHERE a = 1 AND b = 2`
    Filter,
    /// `SELECT count(b) FROM t`
    AggregateCount,
    /// `SELECT t1.a, t2.a FROM t1, t2 WHERE t1.a = t2.a`
    Join,
    /// `SELECT t1.a, t2.a_fk FROM t1, t2 WHERE t1.a = t2.a_fk`
    JoinPkFk,
    /// `SELECT "column" FROM t LIMIT 10`
    Limit,
    /// TPC-H query `q`: its `_tt` variant, or its `_pgn` one over the
    /// `_poneglyph` tables.
    Tpch { q: u8, pgn: bool },
}

impl Query {
    /// The input columns, as (table index, column name), in the order the
    /// guest reads them.
    pub fn inputs(self) -> &'static [(usize, &'static str)] {
        match self {
            Query::Filter => &[(0, "a"), (0, "b"), (0, "c"), (0, "d")],
            Query::AggregateCount => &[(0, "b")],
            Query::Join => &[(0, "a"), (1, "a")],
            Query::JoinPkFk => &[(0, "a"), (1, "a_fk")],
            Query::Limit => &[(0, "column")],
            Query::Tpch { q, pgn } => tpch::inputs(q, pgn),
        }
    }

    /// The query on its input columns. Row order is fixed by the inputs, so
    /// the host and the guest produce the same result and hash.
    pub fn run(self, inputs: &[Column]) -> Vec<Column> {
        match self {
            Query::Filter => {
                let (a, b, c, d) = (
                    inputs[0].i64s(),
                    inputs[1].i64s(),
                    inputs[2].i64s(),
                    inputs[3].i64s(),
                );
                let mut out = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
                for i in 0..a.len() {
                    if a[i] == 1 && b[i] == 2 {
                        out[0].push(a[i]);
                        out[1].push(b[i]);
                        out[2].push(c[i]);
                        out[3].push(d[i]);
                    }
                }
                out.into_iter().map(Column::I64).collect()
            }
            // The column is non-nullable, so every row counts.
            Query::AggregateCount => vec![Column::I64(vec![inputs[0].len() as i64])],
            Query::Join | Query::JoinPkFk => {
                let (left, right) = (inputs[0].i64s(), inputs[1].i64s());
                let index = MultiIndex::new(left);
                let (mut a1, mut a2) = (Vec::new(), Vec::new());
                for &key in right {
                    for row in index.rows(key) {
                        a1.push(left[row]);
                        a2.push(key);
                    }
                }
                vec![Column::I64(a1), Column::I64(a2)]
            }
            Query::Limit => match &inputs[0] {
                Column::U8(v) => vec![Column::U8(v[..v.len().min(10)].to_vec())],
                Column::I64(v) => vec![Column::I64(v[..v.len().min(10)].to_vec())],
                _ => panic!("unsupported LIMIT column"),
            },
            Query::Tpch { q, pgn } => tpch::run(q, pgn, inputs),
        }
    }
}

/// A fixed-seed multiplicative hasher: the guest has no randomness to seed
/// std's, and SipHash costs more cycles.
#[derive(Default)]
pub struct Fx(u64);

impl Hasher for Fx {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(b as u64);
        }
    }

    fn write_u64(&mut self, x: u64) {
        self.0 = (self.0.rotate_left(5) ^ x).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    }

    fn write_i64(&mut self, x: i64) {
        self.write_u64(x as u64);
    }

    fn write_i32(&mut self, x: i32) {
        self.write_u64(x as u32 as u64);
    }

    fn write_usize(&mut self, x: usize) {
        self.write_u64(x as u64);
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

pub type FxMap<K, V> = HashMap<K, V, BuildHasherDefault<Fx>>;

/// A hash index from a key column to the rows holding each key: `head` maps
/// a key to its last row and `next` links each row to the previous one with
/// the same key, so building allocates nothing per row.
pub struct MultiIndex {
    head: FxMap<i64, u32>,
    next: Vec<u32>,
}

impl MultiIndex {
    pub fn new(keys: &[i64]) -> Self {
        let mut head = FxMap::with_capacity_and_hasher(keys.len(), Default::default());
        let mut next = vec![u32::MAX; keys.len()];
        for (i, &key) in keys.iter().enumerate() {
            if let Some(prev) = head.insert(key, i as u32) {
                next[i] = prev;
            }
        }
        MultiIndex { head, next }
    }

    pub fn rows(&self, key: i64) -> impl Iterator<Item = usize> + '_ {
        let mut row = self.head.get(&key).copied().unwrap_or(u32::MAX);
        std::iter::from_fn(move || {
            (row != u32::MAX).then(|| {
                let current = row as usize;
                row = self.next[current];
                current
            })
        })
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct PublicValues {
    pub query: Query,
    pub input_hashes: Vec<Hash>,
    pub result_hash: Hash,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_round_trips() {
        for c in [
            Column::I64(vec![-1, 0, 7]),
            Column::U8(vec![3, 4]),
            Column::I32(vec![5, -6]),
            Column::Date(vec![9000]),
            Column::from_strings(["ab", "", "cde"]),
            Column::Dec {
                scale: 4,
                values: vec![-12345, 6],
            },
        ] {
            assert_eq!(Column::decode(&c.encode()), c);
        }
    }

    #[test]
    fn micro_queries_match_their_sql() {
        let t = [
            Column::I64(vec![1, 1, 2]),
            Column::I64(vec![2, 3, 2]),
            Column::I64(vec![5, 6, 7]),
            Column::I64(vec![8, 9, 10]),
        ];
        assert_eq!(
            Query::Filter.run(&t),
            vec![
                Column::I64(vec![1]),
                Column::I64(vec![2]),
                Column::I64(vec![5]),
                Column::I64(vec![8])
            ]
        );
        assert_eq!(
            Query::AggregateCount.run(&t[1..2]),
            vec![Column::I64(vec![3])]
        );
        let joined = Query::Join.run(&[Column::I64(vec![1, 2, 2]), Column::I64(vec![2, 3, 1])]);
        assert_eq!(
            joined,
            vec![Column::I64(vec![2, 2, 1]), Column::I64(vec![2, 2, 1])]
        );
        let limited = Query::Limit.run(&[Column::U8((0..20).collect())]);
        assert_eq!(limited, vec![Column::U8((0..10).collect())]);
    }
}
