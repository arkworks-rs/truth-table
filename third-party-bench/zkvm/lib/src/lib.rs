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

pub mod micro;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Query {
    /// TPC-H query `q`: its `_tt` variant, or with `pgn` its `_pgn` one over
    /// the `_poneglyph` tables.
    Tpch { q: u8, pgn: bool },
    /// A micro query.
    Micro(micro::Micro),
}

impl Query {
    /// The input columns, as (table index, column name), in the order the
    /// guest reads them.
    pub fn inputs(self) -> &'static [(usize, &'static str)] {
        match self {
            Query::Tpch { q, pgn } => tpch::inputs(q, pgn),
            Query::Micro(m) => m.inputs(),
        }
    }

    /// The query on its input columns. Row order is fixed by the inputs, so
    /// the host and the guest produce the same result and hash.
    pub fn run(self, inputs: &[Column]) -> Vec<Column> {
        match self {
            Query::Tpch { q, pgn } => tpch::run(q, pgn, inputs),
            Query::Micro(m) => m.run(inputs),
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
}
