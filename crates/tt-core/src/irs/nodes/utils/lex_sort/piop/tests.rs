//! The Lexicographic Sort Check and the Rotation Check binding its rotated
//! keys, on eight rows, through a gadget that calls them inline.

use std::sync::Arc;

use ark_ff::One;
use ark_piop::{DefaultSnarkBackend, SnarkBackend, errors::SnarkError};
use datafusion::arrow::datatypes::{DataType, Field, Schema};

use super::{SortKey, Tie, integer_key_width, prove, prove_with_ties, sortedness::rotate, verify};
use crate::irs::nodes::utils::{
    contig_sort::{rotation, tests::assert_rejected},
    lex_sort::{data_oracles, data_polys},
};
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};
use crate::test_utils::inline_gadget::InlineGadget;

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const NV: usize = 3;
const KEYS: &str = "keys";
const NEXT: &str = "next";
const SAME: &str = "same";

struct Key {
    values: Vec<i64>,
    asc: bool,
    width: usize,
}

fn asc(values: &[i64]) -> Key {
    Key {
        values: values.to_vec(),
        asc: true,
        width: 8,
    }
}

fn desc(values: &[i64]) -> Key {
    Key {
        asc: false,
        ..asc(values)
    }
}

/// `values` on the eight rows, zero beyond them.
fn column(values: &[i64]) -> Vec<F> {
    let mut column: Vec<F> = values.iter().map(|v| F::from(*v as i128)).collect();
    column.resize(1 << NV, F::from(0u64));
    column
}

#[derive(Default)]
struct Run {
    /// Active rows.
    s: usize,
    strict: bool,
    /// `t_0 = C_{µ,s−1}·(1 − same)` instead of the mask.
    same: Option<Vec<i64>>,
    /// Committed tie indicators in place of the honest ones.
    ties: Option<Vec<Vec<i64>>>,
    /// Rotated keys in place of the honest ones.
    next: Option<Vec<Vec<i64>>>,
    /// Sorts the keys before this index non-strictly first and checks the
    /// rest from the `t_m` it returns.
    chain_at: Option<usize>,
    /// The `t_m` the prover must return.
    expected_tie: Option<Vec<i64>>,
}

fn table(prefix: &str, columns: Vec<Vec<F>>) -> TableSpec<F> {
    let fields: Vec<Arc<Field>> = (0..columns.len())
        .map(|i| Arc::new(Field::new(format!("{prefix}{i}"), DataType::UInt64, false)))
        .collect();
    TableSpec {
        schema: Schema::new(
            fields
                .iter()
                .map(|f| f.as_ref().clone())
                .collect::<Vec<_>>(),
        ),
        log_size: NV,
        cols: fields.into_iter().zip(columns).collect(),
        activator: None,
    }
}

fn run(keys: Vec<Key>, opts: Run) -> Result<(), SnarkError> {
    let meta: Vec<(bool, usize)> = keys.iter().map(|k| (k.asc, k.width)).collect();
    let data: Vec<Vec<F>> = keys.iter().map(|k| column(&k.values)).collect();
    let next: Vec<Vec<F>> = match &opts.next {
        Some(next) => next.iter().map(|v| column(v)).collect(),
        None => data.iter().map(|v| rotate(v)).collect(),
    };
    let forged: Option<Vec<Vec<F>>> = opts
        .ties
        .map(|ties| ties.iter().map(|t| column(t)).collect());
    let expected_tie = opts.expected_tie.map(|t| column(&t));
    let (s, strict, split) = (opts.s, opts.strict, opts.chain_at);
    let verifier_meta = meta.clone();
    let one = F::one();

    let gadget = InlineGadget::<B>::node(
        Box::new(move |prover, payload| {
            // A run without keys has no key tables: a table needs a column.
            let pairs: Vec<_> = match payload.get(KEYS) {
                Some(keys) => data_polys(keys)
                    .into_iter()
                    .zip(data_polys(&payload[NEXT]))
                    .collect(),
                None => Vec::new(),
            };
            rotation::prove(prover, &pairs, NV, s)?;
            let mask = Tie::mask(prover, NV, s)?;
            let tie = match payload.get(SAME) {
                Some(table) => {
                    let same = &data_polys(table)[0];
                    let poly = mask.poly() * &same.mul_scalar_poly(-one).add_scalar_poly(one);
                    Tie::new(poly, NV, s)
                }
                None => mask,
            };
            let keys: Vec<_> = pairs
                .into_iter()
                .zip(&meta)
                .map(|((data, next), &(asc, width))| SortKey {
                    data,
                    next,
                    asc,
                    width,
                })
                .collect();
            let (first, rest) = keys.split_at(split.unwrap_or(0));
            let tie = match split {
                Some(_) => prove(prover, first, tie, false)?,
                None => tie,
            };
            let output = match &forged {
                Some(ties) => prove_with_ties(prover, rest, tie, strict, ties.clone())?,
                None => prove(prover, rest, tie, strict)?,
            };
            if let Some(expected) = &expected_tie {
                assert_eq!(&output.poly().evaluations(), expected);
            }
            Ok(())
        }),
        Box::new(move |verifier, payload| {
            // A run without keys has no key tables: a table needs a column.
            let pairs: Vec<_> = match payload.get(KEYS) {
                Some(keys) => data_oracles(keys)
                    .into_iter()
                    .zip(data_oracles(&payload[NEXT]))
                    .collect(),
                None => Vec::new(),
            };
            rotation::verify(verifier, &pairs, NV, s)?;
            let mask = Tie::mask_oracle(verifier, NV, s)?;
            let tie = match payload.get(SAME) {
                Some(table) => {
                    let same = &data_oracles(table)[0];
                    let poly = mask.poly() * &same.mul_scalar_oracle(-one).add_scalar_oracle(one);
                    Tie::new(poly, NV, s)
                }
                None => mask,
            };
            let keys: Vec<_> = pairs
                .into_iter()
                .zip(&verifier_meta)
                .map(|((data, next), &(asc, width))| SortKey {
                    data,
                    next,
                    asc,
                    width,
                })
                .collect();
            let (first, rest) = keys.split_at(split.unwrap_or(0));
            let tie = match split {
                Some(_) => verify(verifier, first, tie, false)?,
                None => tie,
            };
            verify(verifier, rest, tie, strict)?;
            Ok(())
        }),
    );
    let id = gadget.id();
    let mut builder = GadgetHarness::<B>::builder(16).with_gadget(gadget);
    if !data.is_empty() {
        builder =
            builder
                .with_table(id, KEYS, table("k", data))
                .with_table(id, NEXT, table("n", next));
    }
    if let Some(same) = &opts.same {
        builder = builder.with_table(id, SAME, table("same", vec![column(same)]));
    }
    run_gadget_pipeline(builder.build())
}

#[test]
fn multi_key_sorted_accepted() {
    let keys = vec![asc(&[1, 1, 2, 2, 3]), asc(&[5, 7, 0, 0, 9])];
    run(
        keys,
        Run {
            s: 5,
            ..Run::default()
        },
    )
    .expect("a sorted table verifies");
}

#[test]
fn multi_key_strict_accepted() {
    let keys = vec![asc(&[1, 1, 2, 3, 3]), asc(&[5, 7, 0, 1, 2])];
    let opts = Run {
        s: 5,
        strict: true,
        ..Run::default()
    };
    run(keys, opts).expect("a strictly sorted table verifies");
}

#[test]
fn duplicate_row_rejected_in_strict_mode() {
    let keys = vec![asc(&[1, 1, 2]), asc(&[5, 5, 0])];
    assert_rejected(run(
        keys,
        Run {
            s: 3,
            strict: true,
            ..Run::default()
        },
    ));
}

#[test]
fn unsorted_first_key_rejected() {
    let keys = vec![asc(&[1, 3, 2, 4]), asc(&[0, 1, 5, 6])];
    assert_rejected(run(
        keys,
        Run {
            s: 4,
            ..Run::default()
        },
    ));
}

#[test]
fn unsorted_second_key_under_a_tie_rejected() {
    let keys = vec![asc(&[1, 1, 2]), asc(&[5, 4, 0])];
    assert_rejected(run(
        keys,
        Run {
            s: 3,
            ..Run::default()
        },
    ));
}

#[test]
fn descending_key() {
    run(
        vec![asc(&[1, 1, 1, 2]), desc(&[9, 4, 4, 8])],
        Run {
            s: 4,
            ..Run::default()
        },
    )
    .expect("the second key descends within the first's ties");
    assert_rejected(run(
        vec![asc(&[1, 1, 1, 2]), asc(&[9, 4, 4, 8])],
        Run {
            s: 4,
            ..Run::default()
        },
    ));
    assert_rejected(run(
        vec![desc(&[3, 2, 2, 4])],
        Run {
            s: 4,
            ..Run::default()
        },
    ));
}

#[test]
fn wide_key() {
    let wide = |values: &[i64]| Key {
        width: integer_key_width(&DataType::UInt32).expect("UInt32 has a width"),
        ..asc(values)
    };
    let top = i64::from(u32::MAX);
    run(
        vec![wide(&[0, 1 << 31, top, top])],
        Run {
            s: 4,
            ..Run::default()
        },
    )
    .expect("a sorted 32-bit key verifies");
    assert_rejected(run(
        vec![wide(&[0, top, 1 << 31, top])],
        Run {
            s: 4,
            ..Run::default()
        },
    ));
}

#[test]
fn padding_rows_are_not_compared() {
    let keys = vec![asc(&[4, 5, 6, 1, 0, 9, 2, 3])];
    run(
        keys,
        Run {
            s: 3,
            ..Run::default()
        },
    )
    .expect("rows from s on are not compared");
}

#[test]
fn single_active_row_proves_nothing() {
    let keys = vec![asc(&[7, 1, 0])];
    let opts = Run {
        s: 1,
        strict: true,
        ..Run::default()
    };
    run(keys, opts).expect("one active row has no pair");
}

#[test]
fn initial_tie_excluding_equal_neighbours() {
    // Rows 0 and 1 are equal; `same` takes them out of the strict check.
    let opts = |same: Option<Vec<i64>>| Run {
        s: 4,
        strict: true,
        same,
        ..Run::default()
    };
    run(vec![asc(&[2, 2, 5, 7])], opts(Some(vec![1, 0, 0, 0])))
        .expect("t_0 = mask·(1 − same) skips the equal pair");
    assert_rejected(run(vec![asc(&[2, 2, 5, 7])], opts(None)));
}

#[test]
fn strict_without_keys_requires_an_empty_initial_tie() {
    let opts = |same: Vec<i64>| Run {
        s: 4,
        strict: true,
        same: Some(same),
        ..Run::default()
    };
    run(vec![], opts(vec![1, 1, 1, 0])).expect("every pair is excluded");
    assert_rejected(run(vec![], opts(vec![1, 0, 1, 0])));
}

#[test]
fn final_tie_is_returned_and_chains() {
    let first = Run {
        s: 4,
        expected_tie: Some(vec![1, 0, 1, 0]),
        ..Run::default()
    };
    run(vec![asc(&[1, 1, 2, 2])], first).expect("t_1 marks the pairs tied on the key");
    let chained = |strict: bool| Run {
        s: 4,
        strict,
        chain_at: Some(1),
        ..Run::default()
    };
    run(vec![asc(&[1, 1, 2, 2]), asc(&[3, 4, 0, 0])], chained(false))
        .expect("the second check starts from t_1");
    run(vec![asc(&[1, 1, 2, 2]), asc(&[3, 4, 0, 1])], chained(true))
        .expect("strict on the second key separates every tied pair");
    assert_rejected(run(
        vec![asc(&[1, 1, 2, 2]), asc(&[3, 4, 0, 0])],
        chained(true),
    ));
}

#[test]
fn forged_tie_on_unequal_values_rejected() {
    // Claiming rows 1 and 2 tied on the first key would skip its order check,
    // and in strict mode leave the pair to the last key, which ascends.
    let keys = || vec![asc(&[1, 3, 2, 4]), asc(&[0, 1, 5, 6])];
    let opts = |strict: bool, ties: Vec<Vec<i64>>| Run {
        s: 4,
        strict,
        ties: Some(ties),
        ..Run::default()
    };
    assert_rejected(run(
        keys(),
        opts(false, vec![vec![0, 1, 0, 0], vec![0, 0, 0, 0]]),
    ));
    assert_rejected(run(keys(), opts(true, vec![vec![0, 1, 0, 0]])));
}

#[test]
fn forged_broken_tie_on_equal_values_rejected_in_strict_mode() {
    // Rows 0 and 1 are equal; claiming the first key separates them would
    // let the strict check pass.
    let keys = vec![asc(&[1, 1, 2, 3]), asc(&[4, 4, 5, 6])];
    let opts = Run {
        s: 4,
        strict: true,
        ties: Some(vec![vec![0, 0, 0, 0]]),
        ..Run::default()
    };
    assert_rejected(run(keys, opts));
}

#[test]
fn non_boolean_tie_rejected() {
    let keys = vec![asc(&[1, 1, 2, 3]), asc(&[4, 5, 5, 6])];
    let opts = Run {
        s: 4,
        ties: Some(vec![vec![2, 0, 0, 0], vec![0, 0, 0, 0]]),
        ..Run::default()
    };
    assert_rejected(run(keys, opts));
}

#[test]
fn forged_rotation_rejected() {
    // A rotated copy that is not the key shifted by one row hides the
    // descent from 3 to 1.
    let opts = Run {
        s: 4,
        next: Some(vec![vec![4, 4, 4, 4]]),
        ..Run::default()
    };
    assert_rejected(run(vec![asc(&[3, 1, 2, 4])], opts));
}

#[test]
fn forged_rotation_of_one_of_several_keys_rejected() {
    // Both keys share one multiset check; the second key's rotated copy
    // hides its descent from 5 to 4 under the first key's tie.
    let opts = Run {
        s: 3,
        next: Some(vec![vec![1, 2, 1], vec![6, 6, 5]]),
        ..Run::default()
    };
    assert_rejected(run(vec![asc(&[1, 1, 2]), asc(&[5, 4, 0])], opts));
}
