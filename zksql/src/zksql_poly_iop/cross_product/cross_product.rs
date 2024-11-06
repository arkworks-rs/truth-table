use ark_ec::pairing::Pairing;
use std::marker::PhantomData;
use crate::subroutines::pcs::PolynomialCommitmentScheme;

use crate::tracker::prelude::*;
// use crate::zksql_poly_iop::cross_product::utils::{
//     // back_alias_tracked_poly, 
//     // front_alias_tracked_poly, 
//     // back_alias_tracked_comm, 
//     // front_alias_tracked_comm,
// };


// Unlike other IOPs, no new polynomials committed to in this IOP. 
// Thus, we also do not recieve the result as an input
// instead we just create it directly
// puts new vars at the front of table A cols (making values repeat in chunks)
// puts new vars at the back  of table B cols (making entire col repeat)
pub struct CrossProductIOP<E: Pairing, PCS: PolynomialCommitmentScheme<E>>(PhantomData<E>, PhantomData<PCS>);
impl <E: Pairing, PCS: PolynomialCommitmentScheme<E>> CrossProductIOP<E, PCS> 
where PCS: PolynomialCommitmentScheme<E> {
    pub fn prover_cross_product(
        table_a: &Table<E, PCS>,
        table_b: &Table<E, PCS>,
    ) -> Result<Table<E, PCS>, PolyIOPErrors> {
        let table_a_nv = table_a.num_vars();
        let table_b_nv = table_b.num_vars();
        let result_cols_len = table_a.col_vals.len() + table_b.col_vals.len();
        let mut result_table_col_vals = Vec::<TrackedPoly<E, PCS>>::with_capacity(result_cols_len);

        // create mles by puttings new vars at the front of table A cols (making values repeat in chunks)
        for a_col in table_a.col_vals.clone() {
            let res_col = a_col.increase_nv_front(table_b_nv);
            result_table_col_vals.push(res_col);
        }
        // create mles by puttings new vars at the back of table B cols (making entire col repeat)
        for b_col in table_b.col_vals.clone() {
            let res_col = b_col.increase_nv_back(table_a_nv);
            result_table_col_vals.push(res_col);
        }

        // create the new table selector by aliasing the old selectors and multiplying them
        let aliased_a_sel = table_a.selector.increase_nv_front(table_b_nv);
        let aliased_b_sel = table_b.selector.increase_nv_back(table_a_nv);
        let res_sel_poly = aliased_a_sel.mul_poly(&aliased_b_sel);

        // put together the table struct
        let result_table = Table::new(result_table_col_vals, res_sel_poly);
        Ok(result_table)

    }

    pub fn verifier_cross_product(
        table_a: &TableComm<E, PCS>,
        table_b: &TableComm<E, PCS>,
    ) -> Result<TableComm<E, PCS>, PolyIOPErrors> {
        let table_a_nv = table_a.num_vars();
        let table_b_nv = table_b.num_vars();
        let result_nv = table_a_nv + table_b_nv;
        let result_cols_len = table_a.col_vals.len() + table_b.col_vals.len();
        let mut result_table_col_vals = Vec::<TrackedComm<E, PCS>>::with_capacity(result_cols_len);

        // put new vars at the front of table A cols (making values repeat in chunks)
        for a_col in table_a.col_vals.clone() {
            let res_col = a_col.increase_nv_front(table_b_nv);
            result_table_col_vals.push(res_col);
        }
        // put new vars at the back of table B cols (making entire col repeat)
        for b_col in table_b.col_vals.clone() {
            let res_col = b_col.increase_nv_back(table_a_nv);
            result_table_col_vals.push(res_col);
        }
        // create the new table selector by aliasing the old selectors and multiplying them
        let aliased_a_sel = table_a.selector.increase_nv_front(table_b_nv);
        let aliased_b_sel = table_b.selector.increase_nv_back(table_a_nv);
        let res_sel_comm = aliased_a_sel.mul_comms(&aliased_b_sel);

        // put together the table struct
        let result_table = TableComm::new(result_table_col_vals, res_sel_comm, result_nv);
        Ok(result_table)
    }
}