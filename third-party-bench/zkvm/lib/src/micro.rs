//! The micro queries of `third-party-bench/src/micro.rs`, over its tables'
//! `BIGINT` columns. The host and the guest run the same code, so they agree
//! on the result's row order and hash.

use serde::{Deserialize, Serialize};

use crate::{Column, FxMap};

/// The constants of `micro.rs`.
const FILTER: (i64, i64) = (1, 2);
const AGG_B: i64 = 1;
const RANGE: (i64, i64) = (100, 199);
const ARITH_C: i64 = 1;
const IN_VALUES: [i64; 16] = [
    0, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200, 1300, 1400, 1500,
];
const ORDER_LIMIT: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Micro {
    /// `SELECT a, b, c, d WHERE a = 1 AND b = 2`, on any of the three filter tables.
    Filter,
    /// `SELECT SUM(a), COUNT(*) WHERE b = 1`
    Aggregate,
    /// `SELECT a, b WHERE a >= 100 AND a <= 199`
    Range,
    /// `SELECT a, b, c, d WHERE a IN (16 values)`
    InList,
    /// `SELECT SUM(a * b) WHERE c = 1`
    Arithmetic,
    /// `SELECT b, SUM(a), COUNT(*) GROUP BY b`
    GroupBy,
    /// `SELECT l.a, r.a FROM l, r WHERE l.a = r.a`, either join's tables.
    Join,
    /// `SELECT a, b ORDER BY a LIMIT 10`
    OrderBy,
}

impl Micro {
    /// The query of a `micro.rs` name.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "filter_0p1" | "filter_1" | "filter_10" => Micro::Filter,
            "aggregate" => Micro::Aggregate,
            "range" => Micro::Range,
            "in_list" => Micro::InList,
            "arithmetic" => Micro::Arithmetic,
            "group_by" => Micro::GroupBy,
            "join_pk_fk" | "join_m2m" => Micro::Join,
            "order_by" => Micro::OrderBy,
            _ => return None,
        })
    }

    pub fn inputs(self) -> &'static [(usize, &'static str)] {
        match self {
            Micro::Filter | Micro::InList => &[(0, "a"), (0, "b"), (0, "c"), (0, "d")],
            Micro::Aggregate | Micro::Range | Micro::GroupBy | Micro::OrderBy => {
                &[(0, "a"), (0, "b")]
            }
            Micro::Arithmetic => &[(0, "a"), (0, "b"), (0, "c")],
            Micro::Join => &[(0, "a"), (1, "a")],
        }
    }

    pub fn run(self, inputs: &[Column]) -> Vec<Column> {
        let cols: Vec<&[i64]> = inputs.iter().map(Column::i64s).collect();
        let rows = cols[0].len();
        let select = |keep: &dyn Fn(usize) -> bool| -> Vec<Column> {
            let kept: Vec<usize> = (0..rows).filter(|&r| keep(r)).collect();
            cols.iter()
                .map(|c| Column::I64(kept.iter().map(|&r| c[r]).collect()))
                .collect()
        };
        match self {
            Micro::Filter => select(&|r| (cols[0][r], cols[1][r]) == FILTER),
            Micro::Range => select(&|r| (RANGE.0..=RANGE.1).contains(&cols[0][r])),
            Micro::InList => select(&|r| IN_VALUES.contains(&cols[0][r])),
            Micro::Aggregate => {
                let (mut sum, mut count) = (0, 0);
                for r in 0..rows {
                    if cols[1][r] == AGG_B {
                        sum += cols[0][r];
                        count += 1;
                    }
                }
                vec![Column::I64(vec![sum]), Column::I64(vec![count])]
            }
            Micro::Arithmetic => {
                let sum = (0..rows)
                    .filter(|&r| cols[2][r] == ARITH_C)
                    .map(|r| cols[0][r] * cols[1][r])
                    .sum();
                vec![Column::I64(vec![sum])]
            }
            Micro::GroupBy => {
                let mut groups: FxMap<i64, (i64, i64)> = FxMap::default();
                for r in 0..rows {
                    let g = groups.entry(cols[1][r]).or_default();
                    g.0 += cols[0][r];
                    g.1 += 1;
                }
                let mut groups: Vec<_> = groups.into_iter().collect();
                groups.sort_unstable_by_key(|&(b, _)| b);
                vec![
                    Column::I64(groups.iter().map(|&(b, _)| b).collect()),
                    Column::I64(groups.iter().map(|&(_, (s, _))| s).collect()),
                    Column::I64(groups.iter().map(|&(_, (_, c))| c).collect()),
                ]
            }
            Micro::Join => {
                let (left, right) = (cols[0], cols[1]);
                let mut counts: FxMap<i64, u32> = FxMap::default();
                for &k in right {
                    *counts.entry(k).or_default() += 1;
                }
                let keys: Vec<i64> = left
                    .iter()
                    .flat_map(|k| {
                        std::iter::repeat_n(*k, counts.get(k).copied().unwrap_or(0) as usize)
                    })
                    .collect();
                vec![Column::I64(keys.clone()), Column::I64(keys)]
            }
            Micro::OrderBy => {
                let mut order: Vec<usize> = (0..rows).collect();
                order.sort_unstable_by_key(|&r| cols[0][r]);
                order.truncate(ORDER_LIMIT);
                cols.iter()
                    .map(|c| Column::I64(order.iter().map(|&r| c[r]).collect()))
                    .collect()
            }
        }
    }
}
