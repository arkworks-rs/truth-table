//! The String Sort Check on four rows of one string and one integer key,
//! through a gadget that calls it inline.

use ark_piop::{DefaultSnarkBackend, SnarkBackend, errors::SnarkError};

use super::{Key, prove, prove_with_source, verify};
use crate::irs::nodes::utils::{
    contig_sort::tests::assert_rejected,
    lex_sort::{
        data_oracles, data_polys,
        piop::{
            character_projection::Characters,
            sortedness::tests::{CHAR_NV, ROW_NV, char_table, hash, int, padded, spec},
        },
    },
};
use crate::test_utils::gadget_harness::{GadgetHarness, TableSpec, run_gadget_pipeline};
use crate::test_utils::inline_gadget::InlineGadget;

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const INPUT: &str = "input";
const OUTPUT: &str = "output";
const CHARS: &str = "chars";

/// The input rows, unsorted.
const ROWS: [(&[u8], i64); 4] = [(b"b", 1), (b"a", 2), (b"c", 0), (b"a", 1)];

#[derive(Clone, Copy)]
enum Kind {
    String,
    Integer,
}

/// `[hash slots…, length, integer]` of `rows`, all active.
fn table(rows: &[(&[u8], i64)]) -> TableSpec<F> {
    let mut columns: Vec<(String, Vec<F>)> = (0..2)
        .map(|slot| {
            let values = rows.iter().map(|(s, _)| hash(s, false)[slot]).collect();
            (format!("hash_{slot}"), values)
        })
        .collect();
    columns.push((
        "length".to_string(),
        rows.iter().map(|(s, _)| int(s.len() as i64)).collect(),
    ));
    columns.push((
        "integer".to_string(),
        rows.iter().map(|(_, v)| int(*v)).collect(),
    ));
    spec(ROW_NV, columns, Some(vec![int(1); rows.len()]))
}

/// The keys `kinds`, ascending, over the output's and the input's
/// `[hash slots…, length, integer]` columns.
fn keys<P: Clone>(
    kinds: &[Kind],
    output: Vec<P>,
    input: Vec<P>,
    chars: Vec<P>,
    char_activator: P,
) -> Vec<Key<P>> {
    let [orig_ind, int_ind, chars]: [P; 3] = chars.try_into().ok().expect("three char columns");
    kinds
        .iter()
        .map(|kind| match kind {
            Kind::String => Key::String {
                identity: output[..3].to_vec(),
                input_identity: input[..3].to_vec(),
                chars: Characters {
                    orig_ind: orig_ind.clone(),
                    int_ind: int_ind.clone(),
                    chars: chars.clone(),
                    activator: char_activator.clone(),
                },
                asc: true,
            },
            Kind::Integer => Key::Value {
                data: output[3].clone(),
                asc: true,
                width: 8,
            },
        })
        .collect()
}

/// Checks that `output` is [`ROWS`] sorted on `kinds`, with `src` in place
/// of the honest source rows when given.
fn run(
    kinds: &'static [Kind],
    output: &[(&[u8], i64)],
    src: Option<[i64; 4]>,
) -> Result<(), SnarkError> {
    let s = ROWS.len();
    let gadget = InlineGadget::<B>::node(
        Box::new(move |prover, payload| {
            let input_active = payload[INPUT].activator_tracked_poly().expect("input act");
            let output_active = payload[OUTPUT]
                .activator_tracked_poly()
                .expect("output act");
            let keys = keys(
                kinds,
                data_polys(&payload[OUTPUT]),
                data_polys(&payload[INPUT]),
                data_polys(&payload[CHARS]),
                payload[CHARS].activator_tracked_poly().expect("char-act"),
            );
            match src {
                None => prove(prover, &keys, &input_active, &output_active, s),
                Some(src) => {
                    let src = padded(src.iter().map(|row| int(*row)).collect(), ROW_NV);
                    prove_with_source(prover, &keys, &input_active, &output_active, s, src)
                }
            }
        }),
        Box::new(move |verifier, payload| {
            let input_active = payload[INPUT].activator_tracked_poly().expect("input act");
            let output_active = payload[OUTPUT]
                .activator_tracked_poly()
                .expect("output act");
            let keys = keys(
                kinds,
                data_oracles(&payload[OUTPUT]),
                data_oracles(&payload[INPUT]),
                data_oracles(&payload[CHARS]),
                payload[CHARS].activator_tracked_poly().expect("char-act"),
            );
            verify(verifier, &keys, &input_active, &output_active, s)
        }),
    );
    let id = gadget.id();
    let owners: Vec<&[u8]> = ROWS.iter().map(|(s, _)| *s).collect();
    let harness = GadgetHarness::<B>::builder(16)
        .with_gadget(gadget)
        .with_table(id, INPUT, table(&ROWS))
        .with_table(id, OUTPUT, table(output))
        .with_table(id, CHARS, char_table(&owners, CHAR_NV))
        .build();
    run_gadget_pipeline(harness)
}

#[test]
fn sorted_on_a_string_then_an_integer() {
    let output: [(&[u8], i64); 4] = [(b"a", 1), (b"a", 2), (b"b", 1), (b"c", 0)];
    run(&[Kind::String, Kind::Integer], &output, None).expect("a sorted output verifies");
    run(&[Kind::String], &output, None).expect("sorted on the string alone");
}

#[test]
fn a_wrong_integer_order_inside_tied_strings_rejected() {
    let output: [(&[u8], i64); 4] = [(b"a", 2), (b"a", 1), (b"b", 1), (b"c", 0)];
    run(&[Kind::String], &output, None).expect("sorted on the string alone");
    assert_rejected(run(&[Kind::String, Kind::Integer], &output, None));
}

#[test]
fn sorted_on_an_integer_then_a_string() {
    let output: [(&[u8], i64); 4] = [(b"c", 0), (b"a", 1), (b"b", 1), (b"a", 2)];
    run(&[Kind::Integer, Kind::String], &output, None).expect("a sorted output verifies");
}

#[test]
fn a_wrong_string_order_inside_tied_integers_rejected() {
    let output: [(&[u8], i64); 4] = [(b"c", 0), (b"b", 1), (b"a", 1), (b"a", 2)];
    run(&[Kind::Integer], &output, None).expect("sorted on the integer alone");
    assert_rejected(run(&[Kind::Integer, Kind::String], &output, None));
}

/// `src` must point each output row at an input row holding its string
/// (the lookup), each input row once (the multiset check).
#[test]
fn a_forged_source_rejected() {
    let output: [(&[u8], i64); 4] = [(b"a", 1), (b"a", 2), (b"b", 1), (b"c", 0)];
    let kinds = &[Kind::String, Kind::Integer];
    run(kinds, &output, Some([1, 3, 0, 2])).expect("either `a` row may source either `a`");
    assert_rejected(run(kinds, &output, Some([1, 3, 2, 0])));
    assert_rejected(run(kinds, &output, Some([1, 1, 0, 2])));
}
