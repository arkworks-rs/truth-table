//! The TPC-H queries TruthTable is benchmarked on (`tpch_data::query_spec`),
//! hand-written over columns: the `_tt` variants over the TPC-H tables and
//! the `_pgn` variants over the `_poneglyph` tables.
//!
//! Decimals arrive as integers: DECIMAL(15, 2) columns as cents, so a product
//! of two has scale 4; the `_poneglyph` tables store their prices, discounts
//! and taxes as plain integers (cents), and their SQL does integer
//! arithmetic on them (`1 - l_discount` is `1 - 4`), so the `_pgn` results
//! have scale 0. Groups are kept in `BTreeMap`s so that output order is
//! deterministic; ties an ORDER BY leaves open are broken by key.

use std::collections::{BTreeMap, BTreeSet};

use crate::{Column, FxMap};

/// Days since 1970-01-01 of a civil date.
pub const fn days(y: i32, m: u32, d: u32) -> i32 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i32 - 719468
}

/// The tables of query `q`, in the order its inputs index them. A `_pgn`
/// query reads `<table>_poneglyph`.
pub fn tables(q: u8) -> &'static [&'static str] {
    match q {
        1 | 6 => &["lineitem"],
        2 => &["part", "supplier", "partsupp", "nation", "region"],
        3 | 18 => &["customer", "orders", "lineitem"],
        4 | 12 => &["orders", "lineitem"],
        5 => &[
            "customer", "orders", "lineitem", "nation", "region", "supplier",
        ],
        7 => &["customer", "orders", "lineitem", "nation", "supplier"],
        8 => &[
            "customer", "orders", "lineitem", "nation", "region", "part", "supplier",
        ],
        9 => &[
            "nation", "orders", "lineitem", "part", "supplier", "partsupp",
        ],
        10 => &["customer", "orders", "lineitem", "nation"],
        14 => &["lineitem", "part"],
        15 => &["lineitem", "supplier"],
        17 | 19 => &["part", "lineitem"],
        20 => &["supplier", "nation", "partsupp", "lineitem", "part"],
        _ => panic!("no TPC-H Q{q}"),
    }
}

pub fn inputs(q: u8, pgn: bool) -> &'static [(usize, &'static str)] {
    match (q, pgn) {
        (1, false) => &[
            (0, "l_returnflag"),
            (0, "l_linestatus"),
            (0, "l_quantity"),
            (0, "l_extendedprice"),
            (0, "l_discount"),
            (0, "l_tax"),
            (0, "l_shipdate"),
        ],
        (1, true) => &[
            (0, "l_returnflag"),
            (0, "l_quantity"),
            (0, "l_extendedprice"),
            (0, "l_discount"),
            (0, "l_tax"),
            (0, "l_shipdate"),
        ],
        (2, false) => &[
            (0, "p_partkey"),
            (0, "p_mfgr"),
            (0, "p_size"),
            (1, "s_suppkey"),
            (1, "s_name"),
            (1, "s_address"),
            (1, "s_nationkey"),
            (1, "s_phone"),
            (1, "s_acctbal"),
            (1, "s_comment"),
            (2, "ps_partkey"),
            (2, "ps_suppkey"),
            (2, "ps_supplycost"),
            (3, "n_nationkey"),
            (3, "n_name"),
            (3, "n_regionkey"),
            (4, "r_regionkey"),
            (4, "r_name"),
        ],
        (3, _) => &[
            (0, "c_custkey"),
            (0, "c_mktsegment"),
            (1, "o_orderkey"),
            (1, "o_custkey"),
            (1, "o_orderdate"),
            (1, "o_shippriority"),
            (2, "l_orderkey"),
            (2, "l_extendedprice"),
            (2, "l_discount"),
            (2, "l_shipdate"),
        ],
        (4, false) => &[
            (0, "o_orderkey"),
            (0, "o_orderdate"),
            (0, "o_orderpriority"),
            (1, "l_orderkey"),
            (1, "l_commitdate"),
            (1, "l_receiptdate"),
        ],
        (5, _) => &[
            (0, "c_custkey"),
            (0, "c_nationkey"),
            (1, "o_orderkey"),
            (1, "o_custkey"),
            (1, "o_orderdate"),
            (2, "l_orderkey"),
            (2, "l_suppkey"),
            (2, "l_extendedprice"),
            (2, "l_discount"),
            (3, "n_nationkey"),
            (3, "n_name"),
            (3, "n_regionkey"),
            (4, "r_regionkey"),
            (4, "r_name"),
            (5, "s_suppkey"),
            (5, "s_nationkey"),
        ],
        (6, false) => &[
            (0, "l_shipdate"),
            (0, "l_discount"),
            (0, "l_quantity"),
            (0, "l_extendedprice"),
        ],
        (7, false) => &[
            (0, "c_custkey"),
            (0, "c_nationkey"),
            (1, "o_orderkey"),
            (1, "o_custkey"),
            (2, "l_orderkey"),
            (2, "l_suppkey"),
            (2, "l_extendedprice"),
            (2, "l_discount"),
            (2, "l_shipdate"),
            (2, "l_shipdate_year"),
            (3, "n_nationkey"),
            (3, "n_name"),
            (4, "s_suppkey"),
            (4, "s_nationkey"),
        ],
        (8, _) => &[
            (0, "c_custkey"),
            (0, "c_nationkey"),
            (1, "o_orderkey"),
            (1, "o_custkey"),
            (1, "o_orderdate"),
            (1, "o_orderdate_year"),
            (2, "l_orderkey"),
            (2, "l_partkey"),
            (2, "l_suppkey"),
            (2, "l_extendedprice"),
            (2, "l_discount"),
            (3, "n_nationkey"),
            (3, "n_name"),
            (3, "n_regionkey"),
            (4, "r_regionkey"),
            (4, "r_name"),
            (5, "p_partkey"),
            (5, "p_type"),
            (6, "s_suppkey"),
            (6, "s_nationkey"),
        ],
        (9, _) => &[
            (0, "n_nationkey"),
            (0, "n_name"),
            (1, "o_orderkey"),
            (1, "o_orderdate_year"),
            (2, "l_orderkey"),
            (2, "l_partkey"),
            (2, "l_suppkey"),
            (2, "l_quantity"),
            (2, "l_extendedprice"),
            (2, "l_discount"),
            (3, "p_partkey"),
            (4, "s_suppkey"),
            (4, "s_nationkey"),
            (5, "ps_partkey"),
            (5, "ps_suppkey"),
            (5, "ps_supplycost"),
        ],
        (10, false) => &[
            (0, "c_custkey"),
            (0, "c_name"),
            (0, "c_address"),
            (0, "c_nationkey"),
            (0, "c_phone"),
            (0, "c_acctbal"),
            (0, "c_comment"),
            (1, "o_orderkey"),
            (1, "o_custkey"),
            (1, "o_orderdate"),
            (2, "l_orderkey"),
            (2, "l_extendedprice"),
            (2, "l_discount"),
            (2, "l_returnflag"),
            (3, "n_nationkey"),
            (3, "n_name"),
        ],
        (12, false) => &[
            (0, "o_orderkey"),
            (0, "o_orderpriority"),
            (1, "l_orderkey"),
            (1, "l_shipmode"),
            (1, "l_commitdate"),
            (1, "l_receiptdate"),
            (1, "l_shipdate"),
        ],
        (14, false) => &[
            (0, "l_partkey"),
            (0, "l_extendedprice"),
            (0, "l_discount"),
            (0, "l_shipdate"),
            (1, "p_partkey"),
        ],
        (15, false) => &[
            (0, "l_suppkey"),
            (0, "l_extendedprice"),
            (0, "l_discount"),
            (0, "l_shipdate"),
            (1, "s_suppkey"),
            (1, "s_name"),
            (1, "s_address"),
            (1, "s_phone"),
        ],
        (17, false) => &[
            (0, "p_partkey"),
            (0, "p_brand"),
            (0, "p_container"),
            (1, "l_partkey"),
            (1, "l_quantity"),
            (1, "l_extendedprice"),
        ],
        (18, false) => &[
            (0, "c_custkey"),
            (0, "c_name"),
            (1, "o_orderkey"),
            (1, "o_custkey"),
            (1, "o_orderdate"),
            (1, "o_totalprice"),
            (2, "l_orderkey"),
            (2, "l_quantity"),
        ],
        (18, true) => &[
            (0, "c_custkey"),
            (0, "c_name"),
            (1, "o_orderkey"),
            (1, "o_custkey"),
            (1, "o_orderdate"),
            (1, "o_totalprice"),
            (2, "l_orderkey"),
            (2, "l_quantity"),
        ],
        (19, false) => &[
            (0, "p_partkey"),
            (0, "p_brand"),
            (0, "p_container"),
            (0, "p_size"),
            (1, "l_partkey"),
            (1, "l_quantity"),
            (1, "l_extendedprice"),
            (1, "l_discount"),
            (1, "l_shipmode"),
            (1, "l_shipinstruct"),
        ],
        (20, false) => &[
            (0, "s_suppkey"),
            (0, "s_name"),
            (0, "s_address"),
            (0, "s_nationkey"),
            (1, "n_nationkey"),
            (1, "n_name"),
            (2, "ps_partkey"),
            (2, "ps_suppkey"),
            (2, "ps_availqty"),
            (3, "l_partkey"),
            (3, "l_suppkey"),
            (3, "l_quantity"),
            (3, "l_shipdate"),
            (4, "p_partkey"),
        ],
        _ => panic!("no TPC-H Q{q} (pgn: {pgn})"),
    }
}

/// `l_extendedprice * (1 - l_discount)`.
fn disc_price(price: i64, discount: i64, pgn: bool) -> i128 {
    let one = if pgn { 1 } else { 100 };
    price as i128 * (one - discount as i128)
}

/// The scale of a sum of [`disc_price`]s.
fn revenue_scale(pgn: bool) -> u8 {
    if pgn {
        0
    } else {
        4
    }
}

fn dec(scale: u8, values: Vec<i128>) -> Column {
    Column::Dec { scale, values }
}

fn strs<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> Column {
    let mut offsets = vec![0u32];
    let mut bytes = Vec::new();
    for v in values {
        bytes.extend_from_slice(v);
        offsets.push(bytes.len() as u32);
    }
    Column::Str { offsets, bytes }
}

/// A key column's value to row index.
fn unique_index(keys: &[i64]) -> FxMap<i64, usize> {
    let mut map = FxMap::with_capacity_and_hasher(keys.len(), Default::default());
    for (i, &k) in keys.iter().enumerate() {
        map.insert(k, i);
    }
    map
}

/// The rows of a table column equal to `value`.
fn rows_eq(column: &Column, value: &[u8]) -> Vec<usize> {
    (0..column.len())
        .filter(|&i| column.str_at(i) == value)
        .collect()
}

pub fn run(q: u8, pgn: bool, c: &[Column]) -> Vec<Column> {
    match q {
        1 => q1(pgn, c),
        2 => q2(c),
        3 => q3(pgn, c),
        4 => q4(c),
        5 => q5(pgn, c),
        6 => q6(c),
        7 => q7(c),
        8 => q8(pgn, c),
        9 => q9(pgn, c),
        10 => q10(c),
        12 => q12(c),
        14 => q14(c),
        15 => q15(c),
        17 => q17(c),
        18 => q18(pgn, c),
        19 => q19(c),
        20 => q20(c),
        _ => panic!("no TPC-H Q{q}"),
    }
}

#[derive(Default)]
struct Q1Acc {
    qty: i128,
    price: i128,
    disc_price: i128,
    charge: i128,
    disc: i128,
    count: i64,
}

fn q1(pgn: bool, c: &[Column]) -> Vec<Column> {
    // `_pgn` groups by l_returnflag alone and has no linestatus input.
    let (flag, status) = (&c[0], (!pgn).then(|| &c[1]));
    let base = if pgn { 1 } else { 2 };
    let (qty, price, disc, tax, ship) = (
        c[base].i64s(),
        c[base + 1].i64s(),
        c[base + 2].i64s(),
        c[base + 3].i64s(),
        c[base + 4].i32s(),
    );
    let cutoff = days(1998, 9, 2);
    let one = if pgn { 1 } else { 100 };
    let mut groups: BTreeMap<(&[u8], &[u8]), Q1Acc> = BTreeMap::new();
    for i in 0..qty.len() {
        if ship[i] > cutoff {
            continue;
        }
        let key = (flag.str_at(i), status.map_or(&[][..], |s| s.str_at(i)));
        let acc = groups.entry(key).or_default();
        let dp = disc_price(price[i], disc[i], pgn);
        acc.qty += qty[i] as i128;
        acc.price += price[i] as i128;
        acc.disc_price += dp;
        acc.charge += dp * (one + tax[i] as i128);
        acc.disc += disc[i] as i128;
        acc.count += 1;
    }
    let values = |f: fn(&Q1Acc) -> i128| groups.values().map(f).collect::<Vec<_>>();
    if pgn {
        return vec![
            strs(groups.keys().map(|k| k.0)),
            dec(0, values(|a| a.qty)),
            dec(0, values(|a| a.price)),
            dec(0, values(|a| a.disc_price)),
            dec(0, values(|a| a.charge)),
            Column::I64(groups.values().map(|a| a.count).collect()),
        ];
    }
    // AVG of DECIMAL(15, 2) has scale 6: sum (scale 2) * 10^4 / count.
    let avg = |f: fn(&Q1Acc) -> i128| {
        groups
            .values()
            .map(|a| f(a) * 10_000 / a.count as i128)
            .collect::<Vec<_>>()
    };
    vec![
        strs(groups.keys().map(|k| k.0)),
        strs(groups.keys().map(|k| k.1)),
        dec(2, values(|a| a.qty)),
        dec(2, values(|a| a.price)),
        dec(4, values(|a| a.disc_price)),
        dec(6, values(|a| a.charge)),
        dec(6, avg(|a| a.qty)),
        dec(6, avg(|a| a.price)),
        dec(6, avg(|a| a.disc)),
        Column::I64(groups.values().map(|a| a.count).collect()),
    ]
}

fn q2(c: &[Column]) -> Vec<Column> {
    let (p_partkey, p_mfgr, p_size) = (c[0].i64s(), &c[1], c[2].i32s());
    let (s_suppkey, s_name, s_address, s_nationkey, s_phone, s_acctbal, s_comment) = (
        c[3].i64s(),
        &c[4],
        &c[5],
        c[6].i64s(),
        &c[7],
        c[8].i64s(),
        &c[9],
    );
    let (ps_partkey, ps_suppkey, ps_supplycost) = (c[10].i64s(), c[11].i64s(), c[12].i64s());
    let (n_nationkey, n_name, n_regionkey) = (c[13].i64s(), &c[14], c[15].i64s());
    let (r_regionkey, r_name) = (c[16].i64s(), &c[17]);

    let europe: BTreeSet<i64> = rows_eq(r_name, b"EUROPE")
        .into_iter()
        .map(|i| r_regionkey[i])
        .collect();
    let nations: FxMap<i64, usize> = (0..n_nationkey.len())
        .filter(|&i| europe.contains(&n_regionkey[i]))
        .map(|i| (n_nationkey[i], i))
        .collect();
    // European suppliers: suppkey -> (supplier row, nation row).
    let suppliers: FxMap<i64, (usize, usize)> = (0..s_suppkey.len())
        .filter_map(|i| {
            nations
                .get(&s_nationkey[i])
                .map(|&n| (s_suppkey[i], (i, n)))
        })
        .collect();
    let mut min_cost: FxMap<i64, i64> = FxMap::default();
    for i in 0..ps_partkey.len() {
        if suppliers.contains_key(&ps_suppkey[i]) {
            let m = min_cost.entry(ps_partkey[i]).or_insert(i64::MAX);
            *m = (*m).min(ps_supplycost[i]);
        }
    }
    let parts: FxMap<i64, usize> = (0..p_partkey.len())
        .filter(|&i| p_size[i] == 15)
        .map(|i| (p_partkey[i], i))
        .collect();
    let mut rows: Vec<(usize, usize, usize)> = Vec::new();
    for i in 0..ps_partkey.len() {
        if let (Some(&p), Some(&(s, n))) =
            (parts.get(&ps_partkey[i]), suppliers.get(&ps_suppkey[i]))
        {
            if min_cost.get(&ps_partkey[i]) == Some(&ps_supplycost[i]) {
                rows.push((p, s, n));
            }
        }
    }
    rows.sort_by(|a, b| {
        s_acctbal[b.1]
            .cmp(&s_acctbal[a.1])
            .then(p_partkey[a.0].cmp(&p_partkey[b.0]))
            .then(s_suppkey[a.1].cmp(&s_suppkey[b.1]))
    });
    rows.truncate(100);
    vec![
        dec(2, rows.iter().map(|r| s_acctbal[r.1] as i128).collect()),
        strs(rows.iter().map(|r| s_name.str_at(r.1))),
        strs(rows.iter().map(|r| n_name.str_at(r.2))),
        Column::I64(rows.iter().map(|r| p_partkey[r.0]).collect()),
        strs(rows.iter().map(|r| p_mfgr.str_at(r.0))),
        strs(rows.iter().map(|r| s_address.str_at(r.1))),
        strs(rows.iter().map(|r| s_phone.str_at(r.1))),
        strs(rows.iter().map(|r| s_comment.str_at(r.1))),
    ]
}

fn q3(pgn: bool, c: &[Column]) -> Vec<Column> {
    let (c_custkey, c_mktsegment) = (c[0].i64s(), &c[1]);
    let (o_orderkey, o_custkey, o_orderdate, o_shippriority) =
        (c[2].i64s(), c[3].i64s(), c[4].i32s(), c[5].i32s());
    let (l_orderkey, l_price, l_disc, l_shipdate) =
        (c[6].i64s(), c[7].i64s(), c[8].i64s(), c[9].i32s());
    let cutoff = days(1995, 3, 15);
    let building: BTreeSet<i64> = rows_eq(c_mktsegment, b"BUILDING")
        .into_iter()
        .map(|i| c_custkey[i])
        .collect();
    let orders: FxMap<i64, usize> = (0..o_orderkey.len())
        .filter(|&i| o_orderdate[i] < cutoff && building.contains(&o_custkey[i]))
        .map(|i| (o_orderkey[i], i))
        .collect();
    let mut revenue: BTreeMap<i64, (usize, i128)> = BTreeMap::new();
    for i in 0..l_orderkey.len() {
        if l_shipdate[i] > cutoff {
            if let Some(&o) = orders.get(&l_orderkey[i]) {
                revenue.entry(l_orderkey[i]).or_insert((o, 0)).1 +=
                    disc_price(l_price[i], l_disc[i], pgn);
            }
        }
    }
    let mut rows: Vec<(i64, usize, i128)> =
        revenue.into_iter().map(|(k, (o, r))| (k, o, r)).collect();
    rows.sort_by(|a, b| {
        b.2.cmp(&a.2)
            .then(o_orderdate[a.1].cmp(&o_orderdate[b.1]))
            .then(a.0.cmp(&b.0))
    });
    if !pgn {
        rows.truncate(10);
    }
    vec![
        Column::I64(rows.iter().map(|r| r.0).collect()),
        dec(revenue_scale(pgn), rows.iter().map(|r| r.2).collect()),
        Column::Date(rows.iter().map(|r| o_orderdate[r.1]).collect()),
        Column::I32(rows.iter().map(|r| o_shippriority[r.1]).collect()),
    ]
}

fn q4(c: &[Column]) -> Vec<Column> {
    let (o_orderkey, o_orderdate, o_orderpriority) = (c[0].i64s(), c[1].i32s(), &c[2]);
    let (l_orderkey, l_commitdate, l_receiptdate) = (c[3].i64s(), c[4].i32s(), c[5].i32s());
    let late: BTreeSet<i64> = (0..l_orderkey.len())
        .filter(|&i| l_receiptdate[i] > l_commitdate[i])
        .map(|i| l_orderkey[i])
        .collect();
    let (lo, hi) = (days(1993, 7, 1), days(1993, 10, 1));
    let mut counts: BTreeMap<&[u8], i64> = BTreeMap::new();
    for i in 0..o_orderkey.len() {
        if o_orderdate[i] >= lo && o_orderdate[i] < hi && late.contains(&o_orderkey[i]) {
            *counts.entry(o_orderpriority.str_at(i)).or_default() += 1;
        }
    }
    vec![
        strs(counts.keys().copied()),
        Column::I64(counts.values().copied().collect()),
    ]
}

fn q5(pgn: bool, c: &[Column]) -> Vec<Column> {
    let (c_custkey, c_nationkey) = (c[0].i64s(), c[1].i64s());
    let (o_orderkey, o_custkey, o_orderdate) = (c[2].i64s(), c[3].i64s(), c[4].i32s());
    let (l_orderkey, l_suppkey, l_price, l_disc) =
        (c[5].i64s(), c[6].i64s(), c[7].i64s(), c[8].i64s());
    let (n_nationkey, n_name, n_regionkey) = (c[9].i64s(), &c[10], c[11].i64s());
    let (r_regionkey, r_name) = (c[12].i64s(), &c[13]);
    let (s_suppkey, s_nationkey) = (c[14].i64s(), c[15].i64s());

    let asia: BTreeSet<i64> = rows_eq(r_name, b"ASIA")
        .into_iter()
        .map(|i| r_regionkey[i])
        .collect();
    let nations: FxMap<i64, usize> = (0..n_nationkey.len())
        .filter(|&i| asia.contains(&n_regionkey[i]))
        .map(|i| (n_nationkey[i], i))
        .collect();
    let customer_nation: FxMap<i64, i64> = c_custkey
        .iter()
        .copied()
        .zip(c_nationkey.iter().copied())
        .collect();
    let (lo, hi) = (days(1994, 1, 1), days(1995, 1, 1));
    let orders: FxMap<i64, i64> = (0..o_orderkey.len())
        .filter(|&i| o_orderdate[i] >= lo && o_orderdate[i] < hi)
        .filter_map(|i| {
            customer_nation
                .get(&o_custkey[i])
                .map(|&n| (o_orderkey[i], n))
        })
        .collect();
    let supplier_nation: FxMap<i64, i64> = s_suppkey
        .iter()
        .copied()
        .zip(s_nationkey.iter().copied())
        .collect();
    let mut revenue: BTreeMap<&[u8], i128> = BTreeMap::new();
    for i in 0..l_orderkey.len() {
        let (Some(&cn), Some(&sn)) = (
            orders.get(&l_orderkey[i]),
            supplier_nation.get(&l_suppkey[i]),
        ) else {
            continue;
        };
        if cn == sn {
            if let Some(&n) = nations.get(&sn) {
                *revenue.entry(n_name.str_at(n)).or_default() +=
                    disc_price(l_price[i], l_disc[i], pgn);
            }
        }
    }
    let mut rows: Vec<(&[u8], i128)> = revenue.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    vec![
        strs(rows.iter().map(|r| r.0)),
        dec(revenue_scale(pgn), rows.iter().map(|r| r.1).collect()),
    ]
}

fn q6(c: &[Column]) -> Vec<Column> {
    let (ship, disc, qty, price) = (c[0].i32s(), c[1].i64s(), c[2].i64s(), c[3].i64s());
    let (lo, hi) = (days(1994, 1, 1), days(1995, 1, 1));
    let mut sum = None;
    for i in 0..ship.len() {
        if ship[i] >= lo && ship[i] < hi && (5..=7).contains(&disc[i]) && qty[i] < 2400 {
            *sum.get_or_insert(0i128) += price[i] as i128 * disc[i] as i128;
        }
    }
    // SUM over no rows is NULL: an empty result.
    vec![dec(4, sum.into_iter().collect())]
}

fn q7(c: &[Column]) -> Vec<Column> {
    let (c_custkey, c_nationkey) = (c[0].i64s(), c[1].i64s());
    let (o_orderkey, o_custkey) = (c[2].i64s(), c[3].i64s());
    let (l_orderkey, l_suppkey, l_price, l_disc, l_shipdate, l_year) = (
        c[4].i64s(),
        c[5].i64s(),
        c[6].i64s(),
        c[7].i64s(),
        c[8].i32s(),
        c[9].i32s(),
    );
    let (n_nationkey, n_name) = (c[10].i64s(), &c[11]);
    let (s_suppkey, s_nationkey) = (c[12].i64s(), c[13].i64s());

    // FRANCE and GERMANY: nationkey -> name.
    let pair: FxMap<i64, &[u8]> = (0..n_nationkey.len())
        .filter(|&i| matches!(n_name.str_at(i), b"FRANCE" | b"GERMANY"))
        .map(|i| (n_nationkey[i], n_name.str_at(i)))
        .collect();
    let customers: FxMap<i64, &[u8]> = (0..c_custkey.len())
        .filter_map(|i| pair.get(&c_nationkey[i]).map(|&n| (c_custkey[i], n)))
        .collect();
    let orders: FxMap<i64, &[u8]> = (0..o_orderkey.len())
        .filter_map(|i| customers.get(&o_custkey[i]).map(|&n| (o_orderkey[i], n)))
        .collect();
    let suppliers: FxMap<i64, &[u8]> = (0..s_suppkey.len())
        .filter_map(|i| pair.get(&s_nationkey[i]).map(|&n| (s_suppkey[i], n)))
        .collect();
    let (lo, hi) = (days(1995, 1, 1), days(1996, 12, 31));
    let mut revenue: BTreeMap<(i32, &[u8], &[u8]), i128> = BTreeMap::new();
    for i in 0..l_orderkey.len() {
        if l_shipdate[i] < lo || l_shipdate[i] > hi {
            continue;
        }
        let (Some(&sn), Some(&cn)) = (suppliers.get(&l_suppkey[i]), orders.get(&l_orderkey[i]))
        else {
            continue;
        };
        if sn != cn {
            *revenue.entry((l_year[i], sn, cn)).or_default() +=
                disc_price(l_price[i], l_disc[i], false);
        }
    }
    vec![
        strs(revenue.keys().map(|k| k.1)),
        strs(revenue.keys().map(|k| k.2)),
        Column::I32(revenue.keys().map(|k| k.0).collect()),
        dec(4, revenue.values().copied().collect()),
    ]
}

fn q8(pgn: bool, c: &[Column]) -> Vec<Column> {
    let (c_custkey, c_nationkey) = (c[0].i64s(), c[1].i64s());
    let (o_orderkey, o_custkey, o_orderdate, o_year) =
        (c[2].i64s(), c[3].i64s(), c[4].i32s(), c[5].i32s());
    let (l_orderkey, l_partkey, l_suppkey, l_price, l_disc) = (
        c[6].i64s(),
        c[7].i64s(),
        c[8].i64s(),
        c[9].i64s(),
        c[10].i64s(),
    );
    let (n_nationkey, n_name, n_regionkey) = (c[11].i64s(), &c[12], c[13].i64s());
    let (r_regionkey, r_name) = (c[14].i64s(), &c[15]);
    let (p_partkey, p_type) = (c[16].i64s(), &c[17]);
    let (s_suppkey, s_nationkey) = (c[18].i64s(), c[19].i64s());

    let america: BTreeSet<i64> = rows_eq(r_name, b"AMERICA")
        .into_iter()
        .map(|i| r_regionkey[i])
        .collect();
    let american_nations: BTreeSet<i64> = (0..n_nationkey.len())
        .filter(|&i| america.contains(&n_regionkey[i]))
        .map(|i| n_nationkey[i])
        .collect();
    let customers: BTreeSet<i64> = (0..c_custkey.len())
        .filter(|&i| american_nations.contains(&c_nationkey[i]))
        .map(|i| c_custkey[i])
        .collect();
    let (lo, hi) = (days(1995, 1, 1), days(1996, 12, 31));
    let orders: FxMap<i64, i32> = (0..o_orderkey.len())
        .filter(|&i| {
            o_orderdate[i] >= lo && o_orderdate[i] <= hi && customers.contains(&o_custkey[i])
        })
        .map(|i| (o_orderkey[i], o_year[i]))
        .collect();
    let parts: BTreeSet<i64> = rows_eq(p_type, b"ECONOMY ANODIZED STEEL")
        .into_iter()
        .map(|i| p_partkey[i])
        .collect();
    let nation_names: FxMap<i64, &[u8]> = (0..n_nationkey.len())
        .map(|i| (n_nationkey[i], n_name.str_at(i)))
        .collect();
    let supplier_brazil: FxMap<i64, bool> = (0..s_suppkey.len())
        .filter_map(|i| {
            nation_names
                .get(&s_nationkey[i])
                .map(|&n| (s_suppkey[i], n == b"BRAZIL"))
        })
        .collect();
    let mut shares: BTreeMap<i32, (i128, i128)> = BTreeMap::new();
    for i in 0..l_orderkey.len() {
        let (Some(&year), Some(&brazil)) = (
            orders.get(&l_orderkey[i]),
            supplier_brazil.get(&l_suppkey[i]),
        ) else {
            continue;
        };
        if parts.contains(&l_partkey[i]) {
            let volume = disc_price(l_price[i], l_disc[i], pgn);
            let share = shares.entry(year).or_default();
            if brazil {
                share.0 += volume;
            }
            share.1 += volume;
        }
    }
    vec![
        Column::I32(shares.keys().copied().collect()),
        dec(revenue_scale(pgn), shares.values().map(|s| s.0).collect()),
        dec(revenue_scale(pgn), shares.values().map(|s| s.1).collect()),
    ]
}

fn q9(pgn: bool, c: &[Column]) -> Vec<Column> {
    let (n_nationkey, n_name) = (c[0].i64s(), &c[1]);
    let (o_orderkey, o_year) = (c[2].i64s(), c[3].i32s());
    let (l_orderkey, l_partkey, l_suppkey, l_qty, l_price, l_disc) = (
        c[4].i64s(),
        c[5].i64s(),
        c[6].i64s(),
        c[7].i64s(),
        c[8].i64s(),
        c[9].i64s(),
    );
    let p_partkey = c[10].i64s();
    let (s_suppkey, s_nationkey) = (c[11].i64s(), c[12].i64s());
    let (ps_partkey, ps_suppkey, ps_supplycost) = (c[13].i64s(), c[14].i64s(), c[15].i64s());

    let parts: BTreeSet<i64> = p_partkey.iter().copied().collect();
    let nation_names: FxMap<i64, &[u8]> = (0..n_nationkey.len())
        .map(|i| (n_nationkey[i], n_name.str_at(i)))
        .collect();
    let supplier_nation: FxMap<i64, &[u8]> = (0..s_suppkey.len())
        .filter_map(|i| {
            nation_names
                .get(&s_nationkey[i])
                .map(|&n| (s_suppkey[i], n))
        })
        .collect();
    let costs: FxMap<(i64, i64), i64> = (0..ps_partkey.len())
        .map(|i| ((ps_partkey[i], ps_suppkey[i]), ps_supplycost[i]))
        .collect();
    let years: FxMap<i64, i32> = o_orderkey
        .iter()
        .copied()
        .zip(o_year.iter().copied())
        .collect();
    let mut profit: BTreeMap<(&[u8], i32), i128> = BTreeMap::new();
    for i in 0..l_orderkey.len() {
        let (Some(&nation), Some(&cost), Some(&year)) = (
            supplier_nation.get(&l_suppkey[i]),
            costs.get(&(l_partkey[i], l_suppkey[i])),
            years.get(&l_orderkey[i]),
        ) else {
            continue;
        };
        if parts.contains(&l_partkey[i]) {
            *profit.entry((nation, year)).or_default() +=
                disc_price(l_price[i], l_disc[i], pgn) - cost as i128 * l_qty[i] as i128;
        }
    }
    let mut rows: Vec<((&[u8], i32), i128)> = profit.into_iter().collect();
    // `_tt` orders by year descending; `_pgn` by nation, then year descending.
    if pgn {
        rows.sort_by(|a, b| a.0 .0.cmp(b.0 .0).then(b.0 .1.cmp(&a.0 .1)));
    } else {
        rows.sort_by(|a, b| b.0 .1.cmp(&a.0 .1).then(a.0 .0.cmp(b.0 .0)));
    }
    vec![
        strs(rows.iter().map(|r| r.0 .0)),
        Column::I32(rows.iter().map(|r| r.0 .1).collect()),
        dec(revenue_scale(pgn), rows.iter().map(|r| r.1).collect()),
    ]
}

fn q10(c: &[Column]) -> Vec<Column> {
    let (c_custkey, c_name, c_address, c_nationkey, c_phone, c_acctbal, c_comment) = (
        c[0].i64s(),
        &c[1],
        &c[2],
        c[3].i64s(),
        &c[4],
        c[5].i64s(),
        &c[6],
    );
    let (o_orderkey, o_custkey, o_orderdate) = (c[7].i64s(), c[8].i64s(), c[9].i32s());
    let (l_orderkey, l_price, l_disc, l_returnflag) =
        (c[10].i64s(), c[11].i64s(), c[12].i64s(), &c[13]);
    let (n_nationkey, n_name) = (c[14].i64s(), &c[15]);

    let (lo, hi) = (days(1993, 10, 1), days(1994, 1, 1));
    let orders: FxMap<i64, i64> = (0..o_orderkey.len())
        .filter(|&i| o_orderdate[i] >= lo && o_orderdate[i] < hi)
        .map(|i| (o_orderkey[i], o_custkey[i]))
        .collect();
    let mut revenue: FxMap<i64, i128> = FxMap::default();
    for i in 0..l_orderkey.len() {
        if l_returnflag.str_at(i) == b"R" {
            if let Some(&cust) = orders.get(&l_orderkey[i]) {
                *revenue.entry(cust).or_default() += disc_price(l_price[i], l_disc[i], false);
            }
        }
    }
    let customers = unique_index(c_custkey);
    let nations = unique_index(n_nationkey);
    let mut rows: Vec<(usize, usize, i128)> = revenue
        .into_iter()
        .filter_map(|(cust, r)| {
            let ci = *customers.get(&cust)?;
            let ni = *nations.get(&c_nationkey[ci])?;
            Some((ci, ni, r))
        })
        .collect();
    rows.sort_by(|a, b| b.2.cmp(&a.2).then(c_custkey[a.0].cmp(&c_custkey[b.0])));
    rows.truncate(20);
    vec![
        Column::I64(rows.iter().map(|r| c_custkey[r.0]).collect()),
        strs(rows.iter().map(|r| c_name.str_at(r.0))),
        dec(4, rows.iter().map(|r| r.2).collect()),
        dec(2, rows.iter().map(|r| c_acctbal[r.0] as i128).collect()),
        strs(rows.iter().map(|r| n_name.str_at(r.1))),
        strs(rows.iter().map(|r| c_address.str_at(r.0))),
        strs(rows.iter().map(|r| c_phone.str_at(r.0))),
        strs(rows.iter().map(|r| c_comment.str_at(r.0))),
    ]
}

fn q12(c: &[Column]) -> Vec<Column> {
    let (o_orderkey, o_orderpriority) = (c[0].i64s(), &c[1]);
    let (l_orderkey, l_shipmode, l_commitdate, l_receiptdate, l_shipdate) =
        (c[2].i64s(), &c[3], c[4].i32s(), c[5].i32s(), c[6].i32s());
    let high: FxMap<i64, bool> = (0..o_orderkey.len())
        .map(|i| {
            (
                o_orderkey[i],
                matches!(o_orderpriority.str_at(i), b"1-URGENT" | b"2-HIGH"),
            )
        })
        .collect();
    let (lo, hi) = (days(1994, 1, 1), days(1995, 1, 1));
    let mut counts: BTreeMap<&[u8], (i64, i64)> = BTreeMap::new();
    for i in 0..l_orderkey.len() {
        let mode = l_shipmode.str_at(i);
        if !matches!(mode, b"MAIL" | b"SHIP")
            || l_commitdate[i] >= l_receiptdate[i]
            || l_shipdate[i] >= l_commitdate[i]
            || l_receiptdate[i] < lo
            || l_receiptdate[i] >= hi
        {
            continue;
        }
        if let Some(&is_high) = high.get(&l_orderkey[i]) {
            let count = counts.entry(mode).or_default();
            if is_high {
                count.0 += 1;
            } else {
                count.1 += 1;
            }
        }
    }
    vec![
        strs(counts.keys().copied()),
        Column::I64(counts.values().map(|c| c.0).collect()),
        Column::I64(counts.values().map(|c| c.1).collect()),
    ]
}

fn q14(c: &[Column]) -> Vec<Column> {
    let (l_partkey, l_price, l_disc, l_shipdate) =
        (c[0].i64s(), c[1].i64s(), c[2].i64s(), c[3].i32s());
    let parts: BTreeSet<i64> = c[4].i64s().iter().copied().collect();
    let (lo, hi) = (days(1995, 9, 1), days(1995, 10, 1));
    let mut sum = 0i128;
    for i in 0..l_partkey.len() {
        if l_shipdate[i] >= lo && l_shipdate[i] < hi && parts.contains(&l_partkey[i]) {
            sum += disc_price(l_price[i], l_disc[i], false);
        }
    }
    // 100.00 * sum / sum, at scale 2; NULL (no row) when nothing matches.
    vec![dec(
        2,
        (sum != 0).then(|| 10_000 * sum / sum).into_iter().collect(),
    )]
}

fn q15(c: &[Column]) -> Vec<Column> {
    let (l_suppkey, l_price, l_disc, l_shipdate) =
        (c[0].i64s(), c[1].i64s(), c[2].i64s(), c[3].i32s());
    let (s_suppkey, s_name, s_address, s_phone) = (c[4].i64s(), &c[5], &c[6], &c[7]);
    let (lo, hi) = (days(1996, 1, 1), days(1996, 4, 1));
    let mut revenue: FxMap<i64, i128> = FxMap::default();
    for i in 0..l_suppkey.len() {
        if l_shipdate[i] >= lo && l_shipdate[i] < hi {
            *revenue.entry(l_suppkey[i]).or_default() += disc_price(l_price[i], l_disc[i], false);
        }
    }
    let max = revenue.values().copied().max();
    let mut rows: Vec<(usize, i128)> = (0..s_suppkey.len())
        .filter_map(|i| {
            let r = *revenue.get(&s_suppkey[i])?;
            (Some(r) == max).then_some((i, r))
        })
        .collect();
    rows.sort_by_key(|r| s_suppkey[r.0]);
    vec![
        Column::I64(rows.iter().map(|r| s_suppkey[r.0]).collect()),
        strs(rows.iter().map(|r| s_name.str_at(r.0))),
        strs(rows.iter().map(|r| s_address.str_at(r.0))),
        strs(rows.iter().map(|r| s_phone.str_at(r.0))),
        dec(4, rows.iter().map(|r| r.1).collect()),
    ]
}

fn q17(c: &[Column]) -> Vec<Column> {
    let (p_partkey, p_brand, p_container) = (c[0].i64s(), &c[1], &c[2]);
    let (l_partkey, l_qty, l_price) = (c[3].i64s(), c[4].i64s(), c[5].i64s());
    let parts: BTreeSet<i64> = (0..p_partkey.len())
        .filter(|&i| p_brand.str_at(i) == b"Brand#23" && p_container.str_at(i) == b"MED BOX")
        .map(|i| p_partkey[i])
        .collect();
    // Per part: (sum of quantities, count).
    let mut stats: FxMap<i64, (i128, i128)> = FxMap::default();
    for i in 0..l_partkey.len() {
        if parts.contains(&l_partkey[i]) {
            let s = stats.entry(l_partkey[i]).or_default();
            s.0 += l_qty[i] as i128;
            s.1 += 1;
        }
    }
    // l_quantity < 0.2 * avg(l_quantity)  <=>  5 * l_quantity * count < sum.
    let mut sum = None;
    for i in 0..l_partkey.len() {
        if let Some(&(total, count)) = stats.get(&l_partkey[i]) {
            if 5 * l_qty[i] as i128 * count < total {
                *sum.get_or_insert(0i128) += l_price[i] as i128;
            }
        }
    }
    // sum / 7.0 at scale 6.
    vec![dec(6, sum.map(|s| s * 10_000 / 7).into_iter().collect())]
}

fn q18(pgn: bool, c: &[Column]) -> Vec<Column> {
    let (c_custkey, c_name) = (c[0].i64s(), &c[1]);
    let (o_orderkey, o_custkey, o_orderdate, o_totalprice) =
        (c[2].i64s(), c[3].i64s(), c[4].i32s(), c[5].i64s());
    let (l_orderkey, l_qty) = (c[6].i64s(), c[7].i64s());
    let mut quantity: FxMap<i64, i128> = FxMap::default();
    for i in 0..l_orderkey.len() {
        *quantity.entry(l_orderkey[i]).or_default() += l_qty[i] as i128;
    }
    let customers = unique_index(c_custkey);
    // `_tt` keeps orders over 300 units (30000 cents); `_pgn` keeps all.
    let mut rows: Vec<(usize, usize, i128)> = (0..o_orderkey.len())
        .filter_map(|o| {
            let q = *quantity.get(&o_orderkey[o])?;
            let cust = *customers.get(&o_custkey[o])?;
            (pgn || q > 30_000).then_some((cust, o, q))
        })
        .collect();
    rows.sort_by(|a, b| {
        o_totalprice[b.1]
            .cmp(&o_totalprice[a.1])
            .then(o_orderdate[a.1].cmp(&o_orderdate[b.1]))
            .then(o_orderkey[a.1].cmp(&o_orderkey[b.1]))
    });
    if !pgn {
        rows.truncate(100);
    }
    let scale = if pgn { 0 } else { 2 };
    vec![
        strs(rows.iter().map(|r| c_name.str_at(r.0))),
        Column::I64(rows.iter().map(|r| c_custkey[r.0]).collect()),
        Column::I64(rows.iter().map(|r| o_orderkey[r.1]).collect()),
        Column::Date(rows.iter().map(|r| o_orderdate[r.1]).collect()),
        dec(
            scale,
            rows.iter().map(|r| o_totalprice[r.1] as i128).collect(),
        ),
        dec(scale, rows.iter().map(|r| r.2).collect()),
    ]
}

fn q19(c: &[Column]) -> Vec<Column> {
    let (p_partkey, p_brand, p_container, p_size) = (c[0].i64s(), &c[1], &c[2], c[3].i32s());
    let (l_partkey, l_qty, l_price, l_disc, l_shipmode, l_shipinstruct) = (
        c[4].i64s(),
        c[5].i64s(),
        c[6].i64s(),
        c[7].i64s(),
        &c[8],
        &c[9],
    );
    let parts = unique_index(p_partkey);
    // (brand, containers, quantity range in cents, max size).
    let branches: [(&[u8], [&[u8]; 4], (i64, i64), i32); 3] = [
        (
            b"Brand#12",
            [b"SM CASE", b"SM BOX", b"SM PACK", b"SM PKG"],
            (100, 1100),
            5,
        ),
        (
            b"Brand#23",
            [b"MED BAG", b"MED BOX", b"MED PKG", b"MED PACK"],
            (1000, 2000),
            10,
        ),
        (
            b"Brand#34",
            [b"LG CASE", b"LG BOX", b"LG PACK", b"LG PKG"],
            (2000, 3000),
            15,
        ),
    ];
    let mut sum = None;
    for i in 0..l_partkey.len() {
        if !matches!(l_shipmode.str_at(i), b"AIR" | b"AIR REG")
            || l_shipinstruct.str_at(i) != b"DELIVER IN PERSON"
        {
            continue;
        }
        let Some(&p) = parts.get(&l_partkey[i]) else {
            continue;
        };
        let hit = branches.iter().any(|(brand, containers, (lo, hi), size)| {
            p_brand.str_at(p) == *brand
                && containers.contains(&p_container.str_at(p))
                && (*lo..=*hi).contains(&l_qty[i])
                && (1..=*size).contains(&p_size[p])
        });
        if hit {
            *sum.get_or_insert(0i128) += disc_price(l_price[i], l_disc[i], false);
        }
    }
    vec![dec(4, sum.into_iter().collect())]
}

fn q20(c: &[Column]) -> Vec<Column> {
    let (s_suppkey, s_name, s_address, s_nationkey) = (c[0].i64s(), &c[1], &c[2], c[3].i64s());
    let (n_nationkey, n_name) = (c[4].i64s(), &c[5]);
    let (ps_partkey, ps_suppkey, ps_availqty) = (c[6].i64s(), c[7].i64s(), c[8].i32s());
    let (l_partkey, l_suppkey, l_qty, l_shipdate) =
        (c[9].i64s(), c[10].i64s(), c[11].i64s(), c[12].i32s());
    let parts: BTreeSet<i64> = c[13].i64s().iter().copied().collect();

    let (lo, hi) = (days(1994, 1, 1), days(1995, 1, 1));
    let mut shipped: FxMap<(i64, i64), i128> = FxMap::default();
    for i in 0..l_partkey.len() {
        if l_shipdate[i] >= lo && l_shipdate[i] < hi {
            *shipped.entry((l_partkey[i], l_suppkey[i])).or_default() += l_qty[i] as i128;
        }
    }
    // ps_availqty > 0.5 * sum(l_quantity)  <=>  200 * ps_availqty > sum (cents).
    let candidates: BTreeSet<i64> = (0..ps_partkey.len())
        .filter(|&i| {
            parts.contains(&ps_partkey[i])
                && shipped
                    .get(&(ps_partkey[i], ps_suppkey[i]))
                    .is_some_and(|&s| 200 * ps_availqty[i] as i128 > s)
        })
        .map(|i| ps_suppkey[i])
        .collect();
    let canada: BTreeSet<i64> = rows_eq(n_name, b"CANADA")
        .into_iter()
        .map(|i| n_nationkey[i])
        .collect();
    let mut rows: Vec<usize> = (0..s_suppkey.len())
        .filter(|&i| canada.contains(&s_nationkey[i]) && candidates.contains(&s_suppkey[i]))
        .collect();
    rows.sort_by_key(|&i| s_suppkey[i]);
    vec![
        strs(rows.iter().map(|&i| s_name.str_at(i))),
        strs(rows.iter().map(|&i| s_address.str_at(i))),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_match_the_calendar() {
        assert_eq!(days(1970, 1, 1), 0);
        assert_eq!(days(1995, 3, 15), 9204);
        assert_eq!(days(2000, 3, 1), 11017);
    }
}
