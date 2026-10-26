//! The Character Projection Check on four strings, through a gadget that
//! calls it inline.

use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, errors::SnarkError,
    prover::structs::polynomial::get_or_insert_shift_poly,
    verifier::structs::oracle::get_or_insert_shift_oracle,
};

use super::{Characters, Strings, prove, prove_with_indicators, verify};
use crate::irs::nodes::utils::{
    contig_sort::tests::assert_rejected,
    lex_sort::{
        data_oracles, data_polys,
        piop::sortedness::tests::{int, spec},
    },
};
use crate::test_utils::gadget_harness::{GadgetHarness, run_gadget_pipeline};
use crate::test_utils::inline_gadget::InlineGadget;

type B = DefaultSnarkBackend;
type F = <B as SnarkBackend>::F;

const ROW_NV: usize = 2;
const CHAR_NV: usize = 3;
const STRINGS: &str = "strings";
const CHARS: &str = "chars";
const PROJECTIONS: &str = "projections";

const STRS: [&str; 4] = ["ab", "", "abc", "b"];

/// The `k`-th character of `s`, or `⊥ = −1`.
fn char_at(s: &str, k: usize) -> i64 {
    s.as_bytes().get(k).map_or(-1, |&c| i64::from(c))
}

/// The projections of `STRS` onto the first `r` positions.
fn projections(r: usize) -> Vec<Vec<i64>> {
    (0..r)
        .map(|k| STRS.iter().map(|s| char_at(s, k)).collect())
        .collect()
}

/// `g_k = a·1[l > k]` for the first `r` positions.
fn indicators(r: usize, active: &[i64]) -> Vec<Vec<i64>> {
    (0..r)
        .map(|k| {
            STRS.iter()
                .zip(active)
                .map(|(s, a)| if s.len() > k { *a } else { 0 })
                .collect()
        })
        .collect()
}

/// Checks `projections` of `STRS` with string activator `active` and the
/// characters of string `i` under `char_active[i]`. `forged` replaces the
/// prover's length indicators.
fn run(
    projections: Vec<Vec<i64>>,
    active: [i64; 4],
    char_active: [i64; 4],
    forged: Option<Vec<Vec<i64>>>,
) -> Result<(), SnarkError> {
    let mut orig_ind = Vec::new();
    let mut int_ind = Vec::new();
    let mut chars = Vec::new();
    let mut char_act = Vec::new();
    for (i, s) in STRS.iter().enumerate() {
        for (k, c) in s.bytes().enumerate() {
            orig_ind.push(int(i as i64));
            int_ind.push(int(k as i64));
            chars.push(int(i64::from(c)));
            char_act.push(int(char_active[i]));
        }
    }
    for column in [&mut orig_ind, &mut int_ind, &mut chars, &mut char_act] {
        column.resize(1 << CHAR_NV, int(0));
    }
    let lengths = STRS.iter().map(|s| int(s.len() as i64)).collect();
    let forged: Option<Vec<Vec<F>>> = forged.map(|g| {
        g.iter()
            .map(|g| g.iter().map(|v| int(*v)).collect())
            .collect()
    });

    let gadget = InlineGadget::<B>::node(
        Box::new(move |prover, payload| {
            let strings_table = &payload[STRINGS];
            let chars_table = &payload[CHARS];
            let strings = Strings {
                index: get_or_insert_shift_poly(prover, ROW_NV, 0, true),
                length: data_polys(strings_table)[0].clone(),
                activator: strings_table.activator_tracked_poly().expect("a"),
            };
            let [orig_ind, int_ind, chars_poly] = data_polys(chars_table).try_into().expect("3");
            let chars = Characters {
                orig_ind,
                int_ind,
                chars: chars_poly,
                activator: chars_table.activator_tracked_poly().expect("char-act"),
            };
            let projections = data_polys(&payload[PROJECTIONS]);
            match &forged {
                Some(g) => prove_with_indicators(prover, &strings, &chars, &projections, g.clone()),
                None => prove(prover, &strings, &chars, &projections),
            }
        }),
        Box::new(move |verifier, payload| {
            let strings_table = &payload[STRINGS];
            let chars_table = &payload[CHARS];
            let strings = Strings {
                index: get_or_insert_shift_oracle(verifier, ROW_NV, 0, true),
                length: data_oracles(strings_table)[0].clone(),
                activator: strings_table.activator_tracked_poly().expect("a"),
            };
            let [orig_ind, int_ind, chars_oracle] =
                data_oracles(chars_table).try_into().expect("3");
            let chars = Characters {
                orig_ind,
                int_ind,
                chars: chars_oracle,
                activator: chars_table.activator_tracked_poly().expect("char-act"),
            };
            verify(
                verifier,
                &strings,
                &chars,
                &data_oracles(&payload[PROJECTIONS]),
            )
        }),
    );
    let id = gadget.id();
    let projection_columns: Vec<(String, Vec<F>)> = projections
        .iter()
        .enumerate()
        .map(|(k, c)| (format!("c{k}"), c.iter().map(|v| int(*v)).collect()))
        .collect();
    let harness = GadgetHarness::<B>::builder(16)
        .with_gadget(gadget)
        .with_table(
            id,
            STRINGS,
            spec(
                ROW_NV,
                vec![("length".to_string(), lengths)],
                Some(active.iter().map(|a| int(*a)).collect()),
            ),
        )
        .with_table(
            id,
            CHARS,
            spec(
                CHAR_NV,
                vec![
                    ("orig_ind".to_string(), orig_ind),
                    ("int_ind".to_string(), int_ind),
                    ("char".to_string(), chars),
                ],
                Some(char_act),
            ),
        )
        .with_table(id, PROJECTIONS, spec(ROW_NV, projection_columns, None))
        .build();
    run_gadget_pipeline(harness)
}

const ALL: [i64; 4] = [1, 1, 1, 1];

#[test]
fn projections_accepted() {
    for r in [1, 3, 4] {
        run(projections(r), ALL, ALL, None)
            .unwrap_or_else(|e| panic!("{r} honest projections verify: {e:?}"));
    }
}

#[test]
fn character_of_another_string_rejected() {
    let mut c = projections(3);
    c[0][3] = i64::from(b'a');
    assert_rejected(run(c, ALL, ALL, None));
}

#[test]
fn character_from_another_position_rejected() {
    let mut c = projections(3);
    c[1][2] = i64::from(b'c');
    assert_rejected(run(c, ALL, ALL, None));
}

#[test]
fn swapped_characters_rejected() {
    let mut c = projections(3);
    c[0][2] = i64::from(b'b');
    c[1][2] = i64::from(b'a');
    assert_rejected(run(c, ALL, ALL, None));
}

#[test]
fn sentinel_where_a_character_exists_rejected() {
    let mut c = projections(3);
    c[1][0] = -1;
    assert_rejected(run(c, ALL, ALL, None));
}

#[test]
fn character_past_the_end_rejected() {
    let mut c = projections(3);
    c[2][0] = i64::from(b'b');
    assert_rejected(run(c, ALL, ALL, None));
}

#[test]
fn forged_length_indicator_rejected() {
    // Hiding the second character of "ab" behind the sentinel.
    let mut c = projections(3);
    c[1][0] = -1;
    let mut g = indicators(3, &ALL);
    g[1][0] = 0;
    assert_rejected(run(c, ALL, ALL, Some(g)));
    // Claiming "ab" has a third character.
    let mut c = projections(3);
    c[2][0] = i64::from(b'b');
    let mut g = indicators(3, &ALL);
    g[2][0] = 1;
    assert_rejected(run(c, ALL, ALL, Some(g)));
}

#[test]
fn inactive_string_is_not_checked() {
    let active = [1, 1, 1, 0];
    let mut c = projections(3);
    for column in &mut c {
        column[3] = i64::from(b'z');
    }
    run(c, active, active, None).expect("the inactive string's projections are free");
}

#[test]
fn non_boolean_length_indicator_rejected() {
    // `g_0 = −1` on "" passes both range checks and the ⊥ zerocheck. The
    // lookup rejects it too: on an active row `g_k ≠ 1` needs `c_k = ⊥`,
    // which no character matches, so `Bool(g_k)` is implied there.
    let mut g = indicators(3, &ALL);
    g[0][1] = -1;
    assert_rejected(run(projections(3), ALL, ALL, Some(g)));
}

#[test]
fn length_indicator_of_inactive_string_rejected() {
    // String 3 is inactive but its character is not, as when `index` points
    // an inactive row at an active row's characters: only `g_k·(1 − a) = 0`
    // rejects `g_0 = 1` there.
    let active = [1, 1, 1, 0];
    run(projections(3), active, ALL, None).expect("the honest indicators verify");
    assert_rejected(run(projections(3), active, ALL, Some(indicators(3, &ALL))));
}
