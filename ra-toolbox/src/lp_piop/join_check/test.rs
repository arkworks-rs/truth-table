use arithmetic::{
    ACTIVATOR_COL_NAME, col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::{PCS, kzg10::KZG10, pst13::PST13},
    piop::PIOP,
    prover::structs::polynomial::TrackedPoly,
    test_utils::test_prelude,
    to_field_vec,
    verifier::structs::oracle::TrackedOracle,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use datafusion::arrow::datatypes::{DataType, Field, FieldRef};
use indexmap::IndexMap;
use std::sync::Arc;

use crate::lp_piop::join_check::{InnerJoinPIOP, InnerJoinProverInput, InnerJoinVerifierInput};

struct InnerJoinTestInput<E: Pairing> {
    pub nv_left_table: usize,
    pub activator_left_table: Option<Vec<E::ScalarField>>,
    pub data_left_table: Vec<Vec<E::ScalarField>>,
    pub nv_right_table: usize,
    pub activator_right_table: Option<Vec<E::ScalarField>>,
    pub data_right_table: Vec<Vec<E::ScalarField>>,
    pub nv_out_table: usize,
    pub activator_out_table: Option<Vec<E::ScalarField>>,
    pub data_out_table: Vec<Vec<E::ScalarField>>,
    pub nv_left_keysupp: usize,
    pub activator_left_keysupp: Option<Vec<E::ScalarField>>,
    pub data_left_keysupp: Vec<Vec<E::ScalarField>>,
    pub nv_right_keysupp: usize,
    pub activator_right_keysupp: Option<Vec<E::ScalarField>>,
    pub data_right_keysupp: Vec<Vec<E::ScalarField>>,
    pub nv_out_keysupp: usize,
    pub activator_out_keysupp: Option<Vec<E::ScalarField>>,
    pub data_out_keysupp: Vec<Vec<E::ScalarField>>,
    pub nv_all_keysupp: usize,
    pub activator_all_keysupp: Option<Vec<E::ScalarField>>,
    pub data_all_keysupp: Vec<Vec<E::ScalarField>>,
    pub join_left_source_data: Vec<E::ScalarField>,
    pub join_right_source_data: Vec<E::ScalarField>,
}

#[allow(clippy::type_complexity)]
fn assemble_table_columns<F, MvPCS, UvPCS>(
    label: &str,
    data_polys: &[TrackedPoly<F, MvPCS, UvPCS>],
    activator: &Option<TrackedPoly<F, MvPCS, UvPCS>>,
) -> (
    IndexMap<FieldRef, TrackedPoly<F, MvPCS, UvPCS>>,
    Vec<FieldRef>,
)
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    let mut columns = IndexMap::new();
    let mut fields = Vec::new();

    for (idx, poly) in data_polys.iter().enumerate() {
        let field = Arc::new(Field::new(
            format!("{label}_col{idx}"),
            DataType::UInt64,
            false,
        ));
        columns.insert(field.clone(), poly.clone());
        fields.push(field);
    }

    if let Some(poly) = activator.clone() {
        let field = Arc::new(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false));
        columns.insert(field.clone(), poly);
        fields.push(field);
    }

    (columns, fields)
}

fn assemble_table_oracles<F, MvPCS, UvPCS>(
    field_order: &[FieldRef],
    data_oracles: &[TrackedOracle<F, MvPCS, UvPCS>],
    activator: &Option<TrackedOracle<F, MvPCS, UvPCS>>,
) -> IndexMap<FieldRef, TrackedOracle<F, MvPCS, UvPCS>>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    let mut columns = IndexMap::new();
    let mut data_iter = data_oracles.iter();

    for field in field_order {
        if field.name() == ACTIVATOR_COL_NAME {
            let activator_oracle = activator
                .clone()
                .expect("activator column present without associated oracle");
            columns.insert(field.clone(), activator_oracle);
        } else {
            let oracle = data_iter
                .next()
                .cloned()
                .expect("missing oracle for data column");
            columns.insert(field.clone(), oracle);
        }
    }

    assert!(
        data_iter.next().is_none(),
        "extraneous data oracles provided for table"
    );

    columns
}

#[test]
fn inner_join_is_complete() -> SnarkResult<()> {
    let input = InnerJoinTestInput {
        nv_left_table: 2,
        activator_left_table: None,
        data_left_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([5, 6, 7, 8], Fr),
        ],
        nv_right_table: 2,
        activator_right_table: None,
        data_right_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([9, 10, 11, 12], Fr),
        ],
        nv_out_table: 3,
        activator_out_table: None,
        data_out_table: vec![
            to_field_vec!([1, 1, 1, 1, 2, 2, 2, 2], Fr),
            to_field_vec!([5, 5, 6, 6, 7, 7, 8, 8], Fr),
            to_field_vec!([9, 10, 9, 10, 11, 12, 11, 12], Fr),
        ],
        nv_left_keysupp: 1,
        activator_left_keysupp: None,
        data_left_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_right_keysupp: 1,
        activator_right_keysupp: None,
        data_right_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_out_keysupp: 1,
        activator_out_keysupp: None,
        data_out_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_all_keysupp: 1,
        activator_all_keysupp: None,
        data_all_keysupp: vec![to_field_vec!([1, 2], Fr)],
        join_left_source_data: to_field_vec!([0, 0, 1, 1, 2, 2, 3, 3], Fr),
        join_right_source_data: to_field_vec!([0, 1, 0, 1, 2, 3, 2, 3], Fr),
    };
    inner_join_test_helper::<Bls12_381, PST13<Bls12_381>, KZG10<Bls12_381>>(input)?;

    // Second scenario: different table shapes (left: 2 rows, right: 4 rows)
    let input2 = InnerJoinTestInput {
        nv_left_table: 1,
        activator_left_table: None,
        data_left_table: vec![to_field_vec!([1, 2], Fr), to_field_vec!([5, 6], Fr)],
        nv_right_table: 2,
        activator_right_table: None,
        data_right_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([9, 10, 11, 12], Fr),
        ],
        nv_out_table: 2,
        activator_out_table: None,
        data_out_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([5, 5, 6, 6], Fr),
            to_field_vec!([9, 10, 11, 12], Fr),
        ],
        nv_left_keysupp: 1,
        activator_left_keysupp: None,
        data_left_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_right_keysupp: 1,
        activator_right_keysupp: None,
        data_right_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_out_keysupp: 1,
        activator_out_keysupp: None,
        data_out_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_all_keysupp: 1,
        activator_all_keysupp: None,
        data_all_keysupp: vec![to_field_vec!([1, 2], Fr)],
        join_left_source_data: to_field_vec!([0, 0, 1, 1], Fr),
        join_right_source_data: to_field_vec!([0, 1, 2, 3], Fr),
    };
    inner_join_test_helper::<Bls12_381, PST13<Bls12_381>, KZG10<Bls12_381>>(input2)?;

    // Third scenario: left has duplicates across two keys; right unique
    let input3 = InnerJoinTestInput {
        nv_left_table: 2, // 4 rows
        activator_left_table: None,
        data_left_table: vec![
            to_field_vec!([2, 2, 3, 3], Fr),
            to_field_vec!([50, 60, 70, 80], Fr),
        ],
        nv_right_table: 1, // 2 rows
        activator_right_table: None,
        data_right_table: vec![to_field_vec!([2, 3], Fr), to_field_vec!([900, 1000], Fr)],
        nv_out_table: 2, // 4 rows
        activator_out_table: None,
        data_out_table: vec![
            to_field_vec!([2, 2, 3, 3], Fr),
            to_field_vec!([50, 60, 70, 80], Fr),
            to_field_vec!([900, 900, 1000, 1000], Fr),
        ],
        nv_left_keysupp: 1,
        activator_left_keysupp: None,
        data_left_keysupp: vec![to_field_vec!([2, 3], Fr)],
        nv_right_keysupp: 1,
        activator_right_keysupp: None,
        data_right_keysupp: vec![to_field_vec!([2, 3], Fr)],
        nv_out_keysupp: 1,
        activator_out_keysupp: None,
        data_out_keysupp: vec![to_field_vec!([2, 3], Fr)],
        nv_all_keysupp: 1,
        activator_all_keysupp: None,
        data_all_keysupp: vec![to_field_vec!([2, 3], Fr)],
        // Join sources map each output row to (left_idx, right_idx)
        join_left_source_data: to_field_vec!([0, 1, 2, 3], Fr),
        join_right_source_data: to_field_vec!([0, 0, 1, 1], Fr),
        // Multiplicities of table rows used in the join
    };
    inner_join_test_helper::<Bls12_381, PST13<Bls12_381>, KZG10<Bls12_381>>(input3)?;

    // Fourth scenario: larger tables (8x8 join -> 16 rows)
    let input4 = InnerJoinTestInput {
        nv_left_table: 3, // 8 rows
        activator_left_table: None,
        data_left_table: vec![
            // keys: [1,1,2,2,3,3,4,4]
            to_field_vec!([1, 1, 2, 2, 3, 3, 4, 4], Fr),
            // left payloads
            to_field_vec!([10, 11, 20, 21, 30, 31, 40, 41], Fr),
        ],
        nv_right_table: 3, // 8 rows
        activator_right_table: None,
        data_right_table: vec![
            // keys: [1,1,2,2,3,3,4,4]
            to_field_vec!([1, 1, 2, 2, 3, 3, 4, 4], Fr),
            // right payloads
            to_field_vec!([100, 101, 200, 201, 300, 301, 400, 401], Fr),
        ],
        nv_out_table: 4, // 16 rows
        activator_out_table: None,
        data_out_table: vec![
            // output keys
            to_field_vec!([1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4], Fr),
            // left payload expanded according to join
            to_field_vec!(
                [
                    10, 10, 11, 11, 20, 20, 21, 21, 30, 30, 31, 31, 40, 40, 41, 41
                ],
                Fr
            ),
            // right payload per matched right row
            to_field_vec!(
                [
                    100, 101, 100, 101, 200, 201, 200, 201, 300, 301, 300, 301, 400, 401, 400, 401
                ],
                Fr
            ),
        ],
        nv_left_keysupp: 2,
        activator_left_keysupp: None,
        data_left_keysupp: vec![to_field_vec!([1, 2, 3, 4], Fr)],
        nv_right_keysupp: 2,
        activator_right_keysupp: None,
        data_right_keysupp: vec![to_field_vec!([1, 2, 3, 4], Fr)],
        nv_out_keysupp: 2,
        activator_out_keysupp: None,
        data_out_keysupp: vec![to_field_vec!([1, 2, 3, 4], Fr)],
        nv_all_keysupp: 2,
        activator_all_keysupp: None,
        data_all_keysupp: vec![to_field_vec!([1, 2, 3, 4], Fr)],
        // Each left row joins with two right rows of same key
        join_left_source_data: to_field_vec!([0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7], Fr),
        join_right_source_data: to_field_vec!([0, 1, 0, 1, 2, 3, 2, 3, 4, 5, 4, 5, 6, 7, 6, 7], Fr),
        // Multiplicities reflect matches per row
    };
    inner_join_test_helper::<Bls12_381, PST13<Bls12_381>, KZG10<Bls12_381>>(input4)?;

    Ok(())
}

#[test]
fn inner_join_is_complete_with_activator() -> SnarkResult<()> {
    // Left has 4 rows; activate first of each key. Right activates second of each
    // // key. Output has 2 rows joining the active pairs per key.
    let input = InnerJoinTestInput {
        // Left table (4 rows): keys [1,1,2,2], payload [5,6,7,8]
        nv_left_table: 2,
        activator_left_table: Some(to_field_vec!([1, 0, 1, 0], Fr)),
        data_left_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([5, 6, 7, 8], Fr),
        ],
        // Right table (4 rows): keys [1,1,2,2], payload [9,10,11,12]
        nv_right_table: 2,
        activator_right_table: Some(to_field_vec!([0, 1, 0, 1], Fr)),
        data_right_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([9, 10, 11, 12], Fr),
        ],
        // Output table (4 rows, activate 2): keys [1,1,2,2], left [5,5,7,7],
        // right [10,10,12,12]
        // Activator marks rows 0 and 2 as active.
        nv_out_table: 2,
        activator_out_table: Some(to_field_vec!([1, 0, 1, 0], Fr)),
        data_out_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([5, 5, 7, 7], Fr),
            to_field_vec!([10, 10, 12, 12], Fr),
        ],
        // Key supports (keys {1,2}) with activators present
        nv_left_keysupp: 1,
        activator_left_keysupp: Some(to_field_vec!([1, 1], Fr)),
        data_left_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_right_keysupp: 1,
        activator_right_keysupp: Some(to_field_vec!([1, 1], Fr)),
        data_right_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_out_keysupp: 1,
        activator_out_keysupp: Some(to_field_vec!([1, 1], Fr)),
        data_out_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_all_keysupp: 1,
        activator_all_keysupp: Some(to_field_vec!([1, 1], Fr)),
        data_all_keysupp: vec![to_field_vec!([1, 2], Fr)],
        // Join sources map each output to (left_idx, right_idx)
        // Map 4 output rows to source indices; only rows 0 and 2 are active
        join_left_source_data: to_field_vec!([0, 0, 2, 2], Fr),
        join_right_source_data: to_field_vec!([1, 1, 3, 3], Fr),
    };

    inner_join_test_helper::<Bls12_381, PST13<Bls12_381>, KZG10<Bls12_381>>(input)?;
    // Second scenario: left activator effectively
    // all-ones -> use None; right // selects first of each key
    let input2 = InnerJoinTestInput {
        nv_left_table: 2,
        activator_left_table: None, // all rows active
        data_left_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([5, 6, 7, 8], Fr),
        ],
        nv_right_table: 2,
        activator_right_table: Some(to_field_vec!([1, 0, 1, 0], Fr)),
        data_right_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([9, 10, 11, 12], Fr),
        ],
        nv_out_table: 2,
        activator_out_table: None, // all outputs active
        data_out_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([5, 6, 7, 8], Fr),
            to_field_vec!([9, 9, 11, 11], Fr),
        ],
        nv_left_keysupp: 1,
        activator_left_keysupp: None,
        data_left_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_right_keysupp: 1,
        activator_right_keysupp: None,
        data_right_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_out_keysupp: 1,
        activator_out_keysupp: None,
        data_out_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_all_keysupp: 1,
        activator_all_keysupp: None,
        data_all_keysupp: vec![to_field_vec!([1, 2], Fr)],
        join_left_source_data: to_field_vec!([0, 1, 2, 3], Fr),
        join_right_source_data: to_field_vec!([0, 0, 2, 2], Fr),
    };
    inner_join_test_helper::<Bls12_381, PST13<Bls12_381>, KZG10<Bls12_381>>(input2)?;

    // Third scenario: right activator effectively all-ones -> use None; left
    // selects second of each key
    let input3 = InnerJoinTestInput {
        nv_left_table: 2,
        activator_left_table: Some(to_field_vec!([0, 1, 0, 1], Fr)),
        data_left_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([5, 6, 7, 8], Fr),
        ],
        nv_right_table: 2,
        activator_right_table: None,
        data_right_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([9, 10, 11, 12], Fr),
        ],
        nv_out_table: 2,
        activator_out_table: None,
        data_out_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([6, 6, 8, 8], Fr),
            to_field_vec!([9, 10, 11, 12], Fr),
        ],
        nv_left_keysupp: 1,
        activator_left_keysupp: None,
        data_left_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_right_keysupp: 1,
        activator_right_keysupp: None,
        data_right_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_out_keysupp: 1,
        activator_out_keysupp: None,
        data_out_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_all_keysupp: 1,
        activator_all_keysupp: None,
        data_all_keysupp: vec![to_field_vec!([1, 2], Fr)],
        join_left_source_data: to_field_vec!([1, 1, 3, 3], Fr),
        join_right_source_data: to_field_vec!([0, 1, 2, 3], Fr),
    };
    inner_join_test_helper::<Bls12_381, PST13<Bls12_381>, KZG10<Bls12_381>>(input3)?;
    // Fourth scenario: right has 8 rows with
    // activator; left has 4 rows, no activator
    let input4 = InnerJoinTestInput {
        nv_left_table: 2, // 4 rows
        activator_left_table: None,
        data_left_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([5, 6, 7, 8], Fr),
        ],
        nv_right_table: 3, // 8 rows
        activator_right_table: Some(to_field_vec!([1, 0, 0, 0, 1, 0, 0, 0], Fr)),
        data_right_table: vec![
            to_field_vec!([1, 1, 1, 1, 2, 2, 2, 2], Fr),
            to_field_vec!([9, 10, 11, 12, 13, 14, 15, 16], Fr),
        ],
        nv_out_table: 3, // match right activator domain
        activator_out_table: Some(to_field_vec!([1, 0, 1, 0, 1, 0, 1, 0], Fr)),
        data_out_table: vec![
            to_field_vec!([1, 1, 1, 1, 2, 2, 2, 2], Fr),
            to_field_vec!([5, 5, 6, 6, 7, 7, 8, 8], Fr),
            to_field_vec!([9, 9, 9, 9, 13, 13, 13, 13], Fr),
        ],
        nv_left_keysupp: 1,
        activator_left_keysupp: None,
        data_left_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_right_keysupp: 1,
        activator_right_keysupp: None,
        data_right_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_out_keysupp: 1,
        activator_out_keysupp: None,
        data_out_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_all_keysupp: 1,
        activator_all_keysupp: None,
        data_all_keysupp: vec![to_field_vec!([1, 2], Fr)],
        join_left_source_data: to_field_vec!([0, 0, 1, 1, 2, 2, 3, 3], Fr),
        join_right_source_data: to_field_vec!([0, 0, 0, 0, 4, 4, 4, 4], Fr),
    };
    inner_join_test_helper::<Bls12_381, PST13<Bls12_381>, KZG10<Bls12_381>>(input4)?;

    // Seventh scenario: both have activators on 4-row domain; output selects 2
    // active rows

    let input7 = InnerJoinTestInput {
        nv_left_table: 2,
        activator_left_table: Some(to_field_vec!([1, 0, 1, 0], Fr)),
        data_left_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([50, 60, 70, 80], Fr),
        ],
        nv_right_table: 2,
        activator_right_table: Some(to_field_vec!([1, 0, 1, 0], Fr)),
        data_right_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([900, 910, 1000, 1010], Fr),
        ],
        nv_out_table: 2,
        activator_out_table: Some(to_field_vec!([1, 0, 1, 0], Fr)),
        data_out_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([50, 50, 70, 70], Fr),
            to_field_vec!([900, 900, 1000, 1000], Fr),
        ],
        nv_left_keysupp: 1,
        activator_left_keysupp: None,
        data_left_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_right_keysupp: 1,
        activator_right_keysupp: None,
        data_right_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_out_keysupp: 1,
        activator_out_keysupp: None,
        data_out_keysupp: vec![to_field_vec!([1, 2], Fr)],
        nv_all_keysupp: 1,
        activator_all_keysupp: None,
        data_all_keysupp: vec![to_field_vec!([1, 2], Fr)],
        join_left_source_data: to_field_vec!([0, 0, 2, 2], Fr),
        join_right_source_data: to_field_vec!([0, 0, 2, 2], Fr),
    };
    inner_join_test_helper::<Bls12_381, PST13<Bls12_381>, KZG10<Bls12_381>>(input7)?;

    Ok(())
}

#[test]
fn inner_join_is_complete_with_multiple_key_columns() -> SnarkResult<()> {
    let input = InnerJoinTestInput {
        nv_left_table: 2,
        activator_left_table: None,
        data_left_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([3, 3, 4, 4], Fr),
            to_field_vec!([5, 6, 7, 8], Fr),
        ],
        nv_right_table: 2,
        activator_right_table: None,
        data_right_table: vec![
            to_field_vec!([1, 1, 2, 2], Fr),
            to_field_vec!([3, 3, 4, 4], Fr),
            to_field_vec!([9, 10, 11, 12], Fr),
        ],
        nv_out_table: 3,
        activator_out_table: None,
        data_out_table: vec![
            to_field_vec!([1, 1, 1, 1, 2, 2, 2, 2], Fr),
            to_field_vec!([3, 3, 3, 3, 4, 4, 4, 4], Fr),
            to_field_vec!([5, 5, 6, 6, 7, 7, 8, 8], Fr),
            to_field_vec!([9, 10, 9, 10, 11, 12, 11, 12], Fr),
        ],
        nv_left_keysupp: 1,
        activator_left_keysupp: None,
        data_left_keysupp: vec![to_field_vec!([1, 2], Fr), to_field_vec!([3, 4], Fr)],
        nv_right_keysupp: 1,
        activator_right_keysupp: None,
        data_right_keysupp: vec![to_field_vec!([1, 2], Fr), to_field_vec!([3, 4], Fr)],
        nv_out_keysupp: 1,
        activator_out_keysupp: None,
        data_out_keysupp: vec![to_field_vec!([1, 2], Fr), to_field_vec!([3, 4], Fr)],
        nv_all_keysupp: 1,
        activator_all_keysupp: None,
        data_all_keysupp: vec![to_field_vec!([1, 2], Fr), to_field_vec!([3, 4], Fr)],
        join_left_source_data: to_field_vec!([0, 0, 1, 1, 2, 2, 3, 3], Fr),
        join_right_source_data: to_field_vec!([0, 1, 0, 1, 2, 3, 2, 3], Fr),
    };
    inner_join_test_helper::<Bls12_381, PST13<Bls12_381>, KZG10<Bls12_381>>(input)?;

    Ok(())
}

//TODO: Add soundness tests
#[allow(dead_code)]
fn inner_join_test_soundness_helper(input: InnerJoinTestInput<Bls12_381>) -> SnarkResult<()> {
    let err =
        inner_join_test_helper::<Bls12_381, PST13<Bls12_381>, KZG10<Bls12_381>>(input).unwrap_err();
    #[cfg(feature = "honest-prover")]
    {
        assert!(matches!(
            err,
            ark_piop::errors::SnarkError::ProverError(
                ark_piop::prover::errors::ProverError::HonestProverError(
                    ark_piop::prover::errors::HonestProverError::FalseClaim
                )
            )
        ));
    }

    #[cfg(not(feature = "honest-prover"))]
    {
        assert!(matches!(
            err,
            ark_piop::errors::SnarkError::VerifierError(
                ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(_)
            )
        ));
    }

    Ok(())
}

fn inner_join_test_helper<
    E: Pairing,
    MvPCS: PCS<E::ScalarField, Poly = MLE<E::ScalarField>>,
    UvPCS: PCS<E::ScalarField, Poly = LDE<E::ScalarField>>,
>(
    input: InnerJoinTestInput<E>,
) -> SnarkResult<()> {
    let (mut prover, mut verifier) = test_prelude::<E::ScalarField, MvPCS, UvPCS>()?;

    // left table prep
    let activator_left_table_poly = match &input.activator_left_table {
        Some(activator_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(input.nv_left_table, activator_values.as_slice()),
        )?),
        None => None,
    };
    let data_left_table_polys = input
        .data_left_table
        .iter()
        .map(|col| {
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(
                input.nv_left_table,
                col.as_slice(),
            ))
        })
        .collect::<SnarkResult<Vec<_>>>()?;

    // right table prep
    let activator_right_table_poly = match &input.activator_right_table {
        Some(activator_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(input.nv_right_table, activator_values.as_slice()),
        )?),
        None => None,
    };
    let data_right_table_polys = input
        .data_right_table
        .iter()
        .map(|col| {
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(
                input.nv_right_table,
                col.as_slice(),
            ))
        })
        .collect::<SnarkResult<Vec<_>>>()?;

    // output table prep
    let activator_out_table_poly = match &input.activator_out_table {
        Some(activator_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(input.nv_out_table, activator_values.as_slice()),
        )?),
        None => None,
    };
    let data_out_table_polys = input
        .data_out_table
        .iter()
        .map(|col| {
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(
                input.nv_out_table,
                col.as_slice(),
            ))
        })
        .collect::<SnarkResult<Vec<_>>>()?;

    let (left_table_columns, left_table_field_order) = assemble_table_columns(
        "left_table",
        &data_left_table_polys,
        &activator_left_table_poly,
    );
    let (right_table_columns, right_table_field_order) = assemble_table_columns(
        "right_table",
        &data_right_table_polys,
        &activator_right_table_poly,
    );
    let (out_table_columns, out_table_field_order) = assemble_table_columns(
        "out_table",
        &data_out_table_polys,
        &activator_out_table_poly,
    );

    // keysupp prep
    let activator_left_keysupp_poly = match &input.activator_left_keysupp {
        Some(activator_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(input.nv_left_keysupp, activator_values.as_slice()),
        )?),
        None => None,
    };
    let data_left_keysupp_polys = input
        .data_left_keysupp
        .iter()
        .map(|col| {
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(
                input.nv_left_keysupp,
                col.as_slice(),
            ))
        })
        .collect::<SnarkResult<Vec<_>>>()?;

    let activator_right_keysupp_poly = match &input.activator_right_keysupp {
        Some(activator_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(input.nv_right_keysupp, activator_values.as_slice()),
        )?),
        None => None,
    };
    let data_right_keysupp_polys = input
        .data_right_keysupp
        .iter()
        .map(|col| {
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(
                input.nv_right_keysupp,
                col.as_slice(),
            ))
        })
        .collect::<SnarkResult<Vec<_>>>()?;

    let activator_out_keysupp_poly = match &input.activator_out_keysupp {
        Some(activator_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(input.nv_out_keysupp, activator_values.as_slice()),
        )?),
        None => None,
    };
    let data_out_keysupp_polys = input
        .data_out_keysupp
        .iter()
        .map(|col| {
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(
                input.nv_out_keysupp,
                col.as_slice(),
            ))
        })
        .collect::<SnarkResult<Vec<_>>>()?;

    let activator_all_keysupp_poly = match &input.activator_all_keysupp {
        Some(activator_values) => Some(prover.track_and_commit_mat_mv_poly(
            &MLE::from_evaluations_slice(input.nv_all_keysupp, activator_values.as_slice()),
        )?),
        None => None,
    };
    let data_all_keysupp_polys = input
        .data_all_keysupp
        .iter()
        .map(|col| {
            prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_slice(
                input.nv_all_keysupp,
                col.as_slice(),
            ))
        })
        .collect::<SnarkResult<Vec<_>>>()?;

    let (left_keysupp_columns, left_keysupp_field_order) = assemble_table_columns(
        "left_keysupp",
        &data_left_keysupp_polys,
        &activator_left_keysupp_poly,
    );
    let (right_keysupp_columns, right_keysupp_field_order) = assemble_table_columns(
        "right_keysupp",
        &data_right_keysupp_polys,
        &activator_right_keysupp_poly,
    );
    let (out_keysupp_columns, out_keysupp_field_order) = assemble_table_columns(
        "out_keysupp",
        &data_out_keysupp_polys,
        &activator_out_keysupp_poly,
    );
    let (all_keysupp_columns, all_keysupp_field_order) = assemble_table_columns(
        "all_keysupp",
        &data_all_keysupp_polys,
        &activator_all_keysupp_poly,
    );

    // source col prep
    let join_left_source_poly = prover.track_and_commit_mat_mv_poly(
        &MLE::from_evaluations_slice(input.nv_out_table, input.join_left_source_data.as_slice()),
    )?;
    let join_right_source_poly = prover.track_and_commit_mat_mv_poly(
        &MLE::from_evaluations_slice(input.nv_out_table, input.join_right_source_data.as_slice()),
    )?;

    let inner_join_prover_input: InnerJoinProverInput<E::ScalarField, MvPCS, UvPCS> =
        InnerJoinProverInput {
            left_table: TrackedTable::new(None, left_table_columns, input.nv_left_table),
            right_table: TrackedTable::new(None, right_table_columns, input.nv_right_table),
            out_table: TrackedTable::new(None, out_table_columns, input.nv_out_table),
            // keysupp tables
            left_key_support_table: TrackedTable::new(
                None,
                left_keysupp_columns,
                input.nv_left_keysupp,
            ),
            right_key_support_table: TrackedTable::new(
                None,
                right_keysupp_columns,
                input.nv_right_keysupp,
            ),
            out_key_support_table: TrackedTable::new(
                None,
                out_keysupp_columns,
                input.nv_out_keysupp,
            ),
            all_key_support_table: TrackedTable::new(
                None,
                all_keysupp_columns,
                input.nv_all_keysupp,
            ),
            // source cols
            join_left_source: TrackedCol::new(
                join_left_source_poly,
                activator_left_table_poly.clone(),
                None,
            ),
            join_right_source: TrackedCol::new(
                join_right_source_poly,
                activator_right_table_poly.clone(),
                None,
            ),
        };

    InnerJoinPIOP::<E::ScalarField, MvPCS, UvPCS>::prove(&mut prover, inner_join_prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);
    //////////////////////////////////////////////////////

    let activator_left_tracked_table_oracle = match &input.activator_left_table {
        Some(_) => {
            let id = verifier.peek_next_id();
            Some(verifier.track_mv_com_by_id(id).unwrap())
        },

        None => None,
    };
    let data_left_tracked_table_oracles = input
        .data_left_table
        .iter()
        .map(|_| {
            let id = verifier.peek_next_id();
            verifier.track_mv_com_by_id(id).unwrap()
        })
        .collect::<Vec<_>>();
    let activator_right_tracked_table_oracle = match &input.activator_right_table {
        Some(_) => {
            let id = verifier.peek_next_id();
            Some(verifier.track_mv_com_by_id(id).unwrap())
        },
        None => None,
    };
    let data_right_tracked_table_oracles = input
        .data_right_table
        .iter()
        .map(|_| {
            let id = verifier.peek_next_id();
            verifier.track_mv_com_by_id(id).unwrap()
        })
        .collect::<Vec<_>>();
    let activator_out_tracked_table_oracle = match &input.activator_out_table {
        Some(_) => {
            let id = verifier.peek_next_id();
            Some(verifier.track_mv_com_by_id(id).unwrap())
        },
        None => None,
    };
    let data_out_tracked_table_oracles = input
        .data_out_table
        .iter()
        .map(|_| {
            let id = verifier.peek_next_id();
            verifier.track_mv_com_by_id(id).unwrap()
        })
        .collect::<Vec<_>>();

    let activator_left_keysupp_tracked_table_oracle = match &input.activator_left_keysupp {
        Some(_) => {
            let id = verifier.peek_next_id();
            Some(verifier.track_mv_com_by_id(id).unwrap())
        },
        None => None,
    };
    let data_left_keysupp_tracked_table_oracles = input
        .data_left_keysupp
        .iter()
        .map(|_| {
            let id = verifier.peek_next_id();
            verifier.track_mv_com_by_id(id).unwrap()
        })
        .collect::<Vec<_>>();

    let activator_right_keysupp_tracked_table_oracle = match &input.activator_right_keysupp {
        Some(_) => {
            let id = verifier.peek_next_id();
            Some(verifier.track_mv_com_by_id(id).unwrap())
        },
        None => None,
    };
    let data_right_keysupp_tracked_table_oracles = input
        .data_right_keysupp
        .iter()
        .map(|_| {
            let id = verifier.peek_next_id();
            verifier.track_mv_com_by_id(id).unwrap()
        })
        .collect::<Vec<_>>();

    let activator_out_keysupp_tracked_table_oracle = match &input.activator_out_keysupp {
        Some(_) => {
            let id = verifier.peek_next_id();
            Some(verifier.track_mv_com_by_id(id).unwrap())
        },
        None => None,
    };
    let data_out_keysupp_tracked_table_oracles = input
        .data_out_keysupp
        .iter()
        .map(|_| {
            let id = verifier.peek_next_id();
            verifier.track_mv_com_by_id(id).unwrap()
        })
        .collect::<Vec<_>>();

    let activator_all_keysupp_tracked_table_oracle = match &input.activator_all_keysupp {
        Some(_) => {
            let id = verifier.peek_next_id();
            Some(verifier.track_mv_com_by_id(id).unwrap())
        },
        None => None,
    };
    let data_all_keysupp_tracked_table_oracles = input
        .data_all_keysupp
        .iter()
        .map(|_| {
            let id = verifier.peek_next_id();
            verifier.track_mv_com_by_id(id).unwrap()
        })
        .collect::<Vec<_>>();
    let join_left_source_id = verifier.peek_next_id();
    let join_left_source_comm = verifier.track_mv_com_by_id(join_left_source_id)?;
    let join_right_source_id = verifier.peek_next_id();
    let join_right_source_comm = verifier.track_mv_com_by_id(join_right_source_id)?;

    let inner_join_verifier_input: InnerJoinVerifierInput<E::ScalarField, MvPCS, UvPCS> =
        InnerJoinVerifierInput {
            left_tracked_table_oracle: TrackedTableOracle::new(
                None,
                assemble_table_oracles(
                    &left_table_field_order,
                    &data_left_tracked_table_oracles,
                    &activator_left_tracked_table_oracle,
                ),
                input.nv_left_table,
            ),
            right_tracked_table_oracle: TrackedTableOracle::new(
                None,
                assemble_table_oracles(
                    &right_table_field_order,
                    &data_right_tracked_table_oracles,
                    &activator_right_tracked_table_oracle,
                ),
                input.nv_right_table,
            ),
            out_tracked_table_oracle: TrackedTableOracle::new(
                None,
                assemble_table_oracles(
                    &out_table_field_order,
                    &data_out_tracked_table_oracles,
                    &activator_out_tracked_table_oracle,
                ),
                input.nv_out_table,
            ),
            left_key_support_table_oracle: TrackedTableOracle::new(
                None,
                assemble_table_oracles(
                    &left_keysupp_field_order,
                    &data_left_keysupp_tracked_table_oracles,
                    &activator_left_keysupp_tracked_table_oracle,
                ),
                input.nv_left_keysupp,
            ),
            right_key_support_table_oracle: TrackedTableOracle::new(
                None,
                assemble_table_oracles(
                    &right_keysupp_field_order,
                    &data_right_keysupp_tracked_table_oracles,
                    &activator_right_keysupp_tracked_table_oracle,
                ),
                input.nv_right_keysupp,
            ),
            out_key_support_table_oracle: TrackedTableOracle::new(
                None,
                assemble_table_oracles(
                    &out_keysupp_field_order,
                    &data_out_keysupp_tracked_table_oracles,
                    &activator_out_keysupp_tracked_table_oracle,
                ),
                input.nv_out_keysupp,
            ),
            all_key_support_table_oracle: TrackedTableOracle::new(
                None,
                assemble_table_oracles(
                    &all_keysupp_field_order,
                    &data_all_keysupp_tracked_table_oracles,
                    &activator_all_keysupp_tracked_table_oracle,
                ),
                input.nv_all_keysupp,
            ),
            join_left_source_table_oracle: TrackedColOracle::new(
                join_left_source_comm,
                activator_left_tracked_table_oracle.clone(),
                None,
            ),
            join_right_source_table_oracle: TrackedColOracle::new(
                join_right_source_comm,
                activator_right_tracked_table_oracle.clone(),
                None,
            ),
        };

    InnerJoinPIOP::<E::ScalarField, MvPCS, UvPCS>::verify(
        &mut verifier,
        inner_join_verifier_input,
    )?;
    verifier.verify()?;
    Ok(())
}
