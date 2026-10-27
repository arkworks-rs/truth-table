//! The Rank Certification Check on up to eight strings: through its gadget,
//! whose prover sorts by the given ranks, and through a gadget that calls it
//! inline with a forged sorted copy or witness.

use std::sync::Arc;

use ark_piop::{DefaultSnarkBackend, SnarkBackend, errors::SnarkError};

use super::{prove_in_order, verify};
use crate::irs::nodes::{
    Node,
    utils::{
        contig_sort::tests::assert_rejected,
        lex_sort::{
            data_oracles, data_polys,
            piop::sortedness::{
                Witness,
                tests::{CHAR_NV, ROW_NV, char_table, hash, int, spec},
            },
            rank_certification::{self, CHARS_LABEL, GadgetNode, STRINGS_LABEL},
        },
    },
};
use crate::test_utils::gadget_harness::{GadgetHarness, run_gadget_pipeline};
use crate::test_utils::inline_gadget::InlineGadget;

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

enum Prover {
    /// The gadget's own prover, which sorts by rank.
    Honest,
    /// The sorted copy holds these rows, and `forge` edits the Lexicographic
    /// Sortedness Check's witness.
    Forged(Vec<usize>, fn(&mut Witness<F>)),
}

/// Certifies `ranks` for `strings`, every row active unless `active` says
/// otherwise.
fn run(
    strings: &[&[u8]],
    ranks: &[i64],
    active: Option<&[i64]>,
    prover: Prover,
) -> Result<(), SnarkError> {
    let mut columns: Vec<(String, Vec<F>)> = (0..2)
        .map(|slot| {
            let values = strings.iter().map(|s| hash(s, false)[slot]).collect();
            (format!("hash_{slot}"), values)
        })
        .collect();
    columns.push((
        "length".to_string(),
        strings.iter().map(|s| int(s.len() as i64)).collect(),
    ));
    columns.push(("rank".to_string(), ranks.iter().map(|r| int(*r)).collect()));
    let activator = active
        .map(|a| a.to_vec())
        .unwrap_or_else(|| vec![1; strings.len()]);
    let table = spec(
        ROW_NV,
        columns,
        Some(activator.iter().map(|a| int(*a)).collect()),
    );

    let gadget: Arc<Node<B>> = match prover {
        Prover::Honest => Arc::new(Node::Gadget(Arc::new(GadgetNode::<B>::default()))),
        Prover::Forged(order, forge) => InlineGadget::<B>::node(
            Box::new(move |prover, payload| {
                let strings = &payload[STRINGS_LABEL];
                let chars = &payload[CHARS_LABEL];
                let (strings, chars) = rank_certification::columns(
                    data_polys(strings),
                    strings.activator_tracked_poly().expect("a"),
                    data_polys(chars),
                    chars.activator_tracked_poly().expect("char-act"),
                );
                prove_in_order(prover, &strings, &chars, ROW_NV, order.clone(), forge)
            }),
            Box::new(move |verifier, payload| {
                let strings = &payload[STRINGS_LABEL];
                let chars = &payload[CHARS_LABEL];
                let (strings, chars) = rank_certification::columns(
                    data_oracles(strings),
                    strings.activator_tracked_poly().expect("a"),
                    data_oracles(chars),
                    chars.activator_tracked_poly().expect("char-act"),
                );
                verify(verifier, &strings, &chars, ROW_NV)
            }),
        ),
    };
    let id = gadget.id();
    let harness = GadgetHarness::<B>::builder(16)
        .with_gadget(gadget)
        .with_table(id, STRINGS_LABEL, table)
        .with_table(id, CHARS_LABEL, char_table(strings, CHAR_NV))
        .build();
    run_gadget_pipeline(harness)
}

#[test]
fn dense_ranks_accepted() {
    let strings: [&[u8]; 6] = [b"b", b"a", b"ab", b"b", b"", b"a"];
    run(&strings, &[3, 1, 2, 3, 0, 1], None, Prover::Honest).expect("dense ranks verify");
}

#[test]
fn inactive_rows_are_not_ranked() {
    let strings: [&[u8]; 5] = [b"b", b"zz", b"a", b"", b"b"];
    let active = [1, 0, 1, 0, 1];
    run(&strings, &[1, 0, 0, 7, 1], Some(&active), Prover::Honest)
        .expect("only the active rows are certified");
}

#[test]
fn no_active_row_accepted() {
    run(&[b"a", b"b"], &[0, 1], Some(&[0, 0]), Prover::Honest).expect("nothing to certify");
}

#[test]
fn sparse_ranks_accepted() {
    // Only the order of the ranks is certified, not their density.
    run(&[b"a", b"b", b"c"], &[0, 4, 7], None, Prover::Honest).expect("sparse ranks verify");
}

#[test]
fn single_row_accepted() {
    run(&[b"z"], &[0], None, Prover::Honest).expect("one row has no pair");
}

#[test]
fn constant_column_accepted() {
    run(&[b"x", b"x", b"x"], &[0, 0, 0], None, Prover::Honest).expect("one rank verifies");
}

#[test]
fn non_monotone_ranks_rejected() {
    let strings: [&[u8]; 3] = [b"a", b"b", b"c"];
    let ranks = [0, 2, 1];
    // Sorted by rank, the copy is not lexicographically sorted; sorted by
    // the strings, the ranks descend.
    assert_rejected(run(&strings, &ranks, None, Prover::Honest));
    assert_rejected(run(
        &strings,
        &ranks,
        None,
        Prover::Forged(vec![0, 1, 2], |_| {}),
    ));
}

#[test]
fn distinct_strings_sharing_a_rank_rejected() {
    let strings: [&[u8]; 2] = [b"a", b"b"];
    assert_rejected(run(&strings, &[0, 0], None, Prover::Honest));
    // Calling them equal would excuse the equal ranks.
    assert_rejected(run(
        &strings,
        &[0, 0],
        None,
        Prover::Forged(vec![0, 1], |w| {
            w.same[0] = int(1);
            w.projections.clear();
            w.projections_next.clear();
        }),
    ));
}

#[test]
fn equal_strings_with_different_ranks_rejected() {
    let strings: [&[u8]; 2] = [b"x", b"x"];
    assert_rejected(run(&strings, &[0, 1], None, Prover::Honest));
    // Calling them distinct would excuse the different ranks.
    assert_rejected(run(
        &strings,
        &[0, 1],
        None,
        Prover::Forged(vec![0, 1], |w| w.same[0] = int(0)),
    ));
}

#[test]
fn unrotated_rank_of_an_all_equal_column_rejected() {
    // Every pair is equal, so R = 0 and only the Rotation Check binds
    // rk^{π,next}; setting it to rk^π hides the rank change.
    let forge: fn(&mut Witness<F>) = |w| w.extras_next[0].rotate_right(1);
    assert_rejected(run(
        &[b"x", b"x", b"x"],
        &[0, 1, 0],
        None,
        Prover::Forged(vec![0, 2, 1], forge),
    ));
}

#[test]
fn copy_of_a_missing_row_rejected() {
    // Row 1 twice and row 0 never: the lookup holds, the multiset check
    // does not.
    assert_rejected(run(
        &[b"a", b"a", b"b"],
        &[0, 0, 1],
        None,
        Prover::Forged(vec![1, 1, 2], |_| {}),
    ));
}
