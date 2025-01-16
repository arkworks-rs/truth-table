mod data_structures;
#[cfg(test)]
mod test;

use crate::{
    col_toolbox::{
        fold_check::FoldCheckPIOP, multiplicity_check::MultiplicityCheck, supp_check::{utils::calc_supp_check_advice, SuppCheckPIOP}
    },
    tracker::prelude::*,
};
use arithmetic::{ark_ff::PrimeField, mle::mat::fold_mles};
/// the process of group by is
/// 1. get the support and prove its correct
/// 2. go through the list of aggregation instructions and prove each one on the
///    relevant column
use arithmetic::ark_poly::DenseMultilinearExtension;
use crypto::pcs::PolynomialCommitmentScheme;
use data_structures::GroupByInstruction;
use std::{collections::HashMap, marker::PhantomData};

pub struct GroupByPIOP<F: PrimeField, PCS: PolynomialCommitmentScheme<F>>(
    PhantomData<F>,
    PhantomData<PCS>,
);

impl<F: PrimeField, PCS: PolynomialCommitmentScheme<F>> GroupByPIOP<F, PCS>
where
    PCS: PolynomialCommitmentScheme<F>,
    F: PrimeField,
{

// TODO: These range stuff should be removed and accessible globally
    pub fn prove(
        p_trckr: &mut ProverTrackerRef<F, PCS>,
        in_table: &Table<F, PCS>,
        out_table: &Table<F, PCS>,
        range_col: &Col<F, PCS>,
        instr: &GroupByInstruction,
    ) -> Result<(), PolyIOPErrors> {
        // Parse the group_by instruction by destructuring it
        let GroupByInstruction {
            gpd_col_indices,
            agg_instr,
        } = instr;
        let num_gpd_cols = gpd_col_indices.len();
        // Fix this unwrap and do sth for the error propagation
        let gpd_cols_fld_challs:Vec<F> = (0..num_gpd_cols).into_iter().map(|_| p_trckr.get_and_append_challenge(b"Grouping columns folding challeng").unwrap()).collect();
        let in_fldd_gp_col = in_table.fold(&gpd_col_indices, &gpd_cols_fld_challs);
        let gpd_cols = in_table.cols(&gpd_col_indices);
        FoldCheckPIOP::<F, PCS>::prove(p_trckr, &gpd_cols, &in_fldd_gp_col, &gpd_cols_fld_challs)?;
        let out_fldd_gp_col = out_table.fold(&gpd_col_indices, &gpd_cols_fld_challs); 
        SuppCheckPIOP::<F, PCS>::prove(p_trckr, &in_fldd_gp_col, &out_fldd_gp_col, &range_col)?;
        Ok(())
    }


    pub fn verify(
        v_trckr: &mut VerifierTrackerRef<F, PCS>,
        in_table_comm: &TableComm<F, PCS>,
        out_table_comm: &TableComm<F, PCS>,
        range_comm: &ColComm<F, PCS>,
        instr: &GroupByInstruction,
    ) -> Result<(),PolyIOPErrors> {
        // Parse the group_by instruction by destructuring it
        let GroupByInstruction {
            gpd_col_indices,
            agg_instr,
        } = instr;
        let num_gpd_cols = gpd_col_indices.len();
        let gpd_cols_fld_challs:Vec<F> = (0..num_gpd_cols).into_iter().map(|_| v_trckr.get_and_append_challenge(b"Grouping columns folding challeng").unwrap()).collect();
        let in_fldd_gp_col = in_table_comm.fold(&gpd_col_indices, &gpd_cols_fld_challs);
        let gpd_col_comms = in_table_comm.cols(&gpd_col_indices);
        FoldCheckPIOP::<F, PCS>::verify(v_trckr, &gpd_col_comms, &in_fldd_gp_col, &gpd_cols_fld_challs)?; 
        let out_fldd_gp_col = out_table_comm.fold(&gpd_col_indices, &gpd_cols_fld_challs); 
        SuppCheckPIOP::<F, PCS>::verify(v_trckr, &in_fldd_gp_col, &out_fldd_gp_col, &range_comm)?;
        Ok(())
    }


}
//     // prove with advice
//     // returns the result table
//     pub fn prove_with_advice(
//         prover_tracker: &mut ProverTrackerRef<F, PCS>,
//         input_table: &Table<F, PCS>,
//         output_table: &Table<F, PCS>,
//         group_by_instructions: &GroupByInstructionWithProvingAdvice<F, PCS>,
//         range_col: &Col<F, PCS>,
//     ) -> Result<Table<F, PCS>, PolyIOPErrors> {
//         // 0. input validation for group_by_instructions
//         if group_by_instructions.grouping_cols.len() > 1 {
//             return Err(PolyIOPErrors::InvalidParameters(format!(
//                 "GroupByIOP Error: only 1 grouping column is supported for now"
//             )));
//         }
//         let grouping_col_idx = group_by_instructions.grouping_cols[0];
//         if grouping_col_idx >= input_table.col_vals.len() {
//             return Err(PolyIOPErrors::InvalidParameters(format!(
//                 "GroupByIOP Error: grouping column index {} is out of bounds",
//                 grouping_col_idx
//             )));
//         }
//         for (col_idx, ..) in group_by_instructions.agg_instr.iter() {
//             if *col_idx >= input_table.col_vals.len() {
//                 return Err(PolyIOPErrors::InvalidParameters(format!(
//                     "GroupByIOP Error: aggregation column index {} is out of bounds",
//                     *col_idx
//                 )));
//             }
//         }
//         let supp_poly = group_by_instructions.support_cols[0].clone();
//         let supp_sel_poly = group_by_instructions.support_sel.clone();
//         let support_multiplicity_poly = group_by_instructions.support_multiplicity.clone();
//         let pre_grouping_col_col = Col::new(
//             input_table.col_vals[grouping_col_idx].clone(),
//             input_table.selector.clone(),
//         );

//         // 1. prove the grouping col is a the support of the pre-grouping col as part of
//         //    this proof, it shows that support_multiplicity_poly is the relevent
//         //    multiplicity vector for proving the grouping col is a subset of the
//         //    support of the pre-grouping col
//         let grouped_col_col = Col::new(supp_poly.clone(), supp_sel_poly.clone());
//         SuppCheckPIOP::<F, PCS>::prove_with_advice(
//             prover_tracker,
//             &pre_grouping_col_col.clone(),
//             &grouped_col_col.clone(),
//             &support_multiplicity_poly.clone(),
//             range_col,
//         )?;
//         let mut res_table_col_polys =
//             Vec::<TrackedPoly<F, PCS>>::with_capacity(1 + group_by_instructions.agg_instr.len());
//         res_table_col_polys.push(supp_poly.clone());
//         let mut res_table = Table::new(res_table_col_polys, supp_sel_poly.clone());

//         // 2. go through the list of aggregation instructions and prove each one on the
//         //    relevant column
//         for (col_idx, agg_instr, agg_poly) in group_by_instructions.agg_instr.iter() {
//             match agg_instr {
//                 AggregationType::Count => {
//                     // the column that results from the count aggregation is the same as the
//                     // support_multiplicity_poly
//                     res_table.col_vals.push(support_multiplicity_poly.clone());
//                 },
//                 AggregationType::Sum => {
//                     let pre_agg_poly = input_table.col_vals[*col_idx].clone();
//                     // prove the sum aggregation is correct
//                     // use multiplicity_check with the grouping columns as values and the agg_poly
//                     // as multiplicities
//                     MultiplicityCheck::<F, PCS>::prove(
//                         prover_tracker,
//                         &vec![pre_grouping_col_col.clone()],
//                         &vec![grouped_col_col.clone()],
//                         &vec![pre_agg_poly.clone()],
//                         &vec![agg_poly.clone()],
//                     )?;
//                 },
//                 AggregationType::Avg => {
//                     // prove the avg aggregation is correct
//                     todo!();
//                 },
//                 AggregationType::Min => {
//                     // prove the min aggregation is correct
//                     todo!();
//                 },
//                 AggregationType::Max => {
//                     // prove the max aggregation is correct
//                     todo!();
//                 },
//             }
//         }

//         // TODO: do we want outputs?
//         Ok(res_table)
//     }

//     pub fn verify() -> Result<(), PolyIOPErrors> {
//         todo!()
//     }

//     pub fn verify_with_advice(
//         verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
//         input_table: &TableComm<F, PCS>,
//         group_by_instructions: &GroupByInstructionWithVerifyingAdvice<F, PCS>,
//         range_col: &ColComm<F, PCS>,
//     ) -> Result<TableComm<F, PCS>, PolyIOPErrors> {
//         // TODO: should res_table_nv actually be input_table.num_vars()?
//         // means supp cannot be smaller.
//         // In Supp IOP we give supp_col as an input, so we have the info
//         let res_table_nv = input_table.num_vars();

//         // 0. input validation for group_by_instructions
//         if group_by_instructions.grouping_cols.len() > 1 {
//             return Err(PolyIOPErrors::InvalidParameters(format!(
//                 "GroupByIOP Error: only 1 grouping column is supported for now"
//             )));
//         }
//         let grouping_col_idx = group_by_instructions.grouping_cols[0];
//         if grouping_col_idx >= input_table.col_vals.len() {
//             return Err(PolyIOPErrors::InvalidParameters(format!(
//                 "GroupByIOP Error: grouping column index {} is out of bounds",
//                 grouping_col_idx
//             )));
//         }
//         for (col_idx, ..) in group_by_instructions.agg_instr.iter() {
//             if *col_idx >= input_table.col_vals.len() {
//                 return Err(PolyIOPErrors::InvalidParameters(format!(
//                     "GroupByIOP Error: aggregation column index {} is out of bounds",
//                     *col_idx
//                 )));
//             }
//         }
//         let supp_comm = group_by_instructions.support_cols[0].clone();
//         let supp_sel_comm = group_by_instructions.support_sel.clone();
//         let support_multiplicity_comm = group_by_instructions.support_multiplicity.clone();
//         let pre_grouping_col_col = ColComm::new(
//             input_table.col_vals[grouping_col_idx].clone(),
//             input_table.selector.clone(),
//             input_table.num_vars(),
//         );

//         // 1. verify the grouping col is a the support of the pre-grouping col as part
//         //    of this proof, it shows that support_multiplicity_poly is the relevent
//         //    multiplicity vector for proving the grouping col is a subset of the
//         //    support of the pre-grouping col
//         let grouped_col_col = ColComm::new(supp_comm.clone(), supp_sel_comm.clone(), res_table_nv);
//         SuppCheckPIOP::<F, PCS>::verify_with_advice(
//             verifier_tracker,
//             &pre_grouping_col_col,
//             &grouped_col_col,
//             &support_multiplicity_comm,
//             &range_col,
//         )?;
//         let mut res_table_col_comms =
//             Vec::<TrackedComm<F, PCS>>::with_capacity(1 + group_by_instructions.agg_instr.len());
//         res_table_col_comms.push(supp_comm.clone());
//         let mut res_table =
//             TableComm::new(res_table_col_comms, supp_sel_comm.clone(), res_table_nv);

//         // 2. go through the list of aggregation instructions and prove each one on the
//         //    relevant column
//         for (col_idx, agg_instr, agg_poly) in group_by_instructions.agg_instr.iter() {
//             match agg_instr {
//                 AggregationType::Count => {
//                     // the column that results from the count aggregation is the same as the
//                     // support_multiplicity_poly
//                     res_table.col_vals.push(support_multiplicity_comm.clone());
//                 },
//                 AggregationType::Sum => {
//                     let pre_agg_poly = input_table.col_vals[*col_idx].clone();
//                     // prove the sum aggregation is correct
//                     // use multiplicity_check with the grouping columns as values and the agg_poly
//                     // as multiplicities
//                     MultiplicityCheck::<F, PCS>::verify(
//                         verifier_tracker,
//                         &vec![pre_grouping_col_col.clone()],
//                         &vec![grouped_col_col.clone()],
//                         &vec![pre_agg_poly],
//                         &vec![agg_poly.clone()],
//                     )?;
//                 },
//                 AggregationType::Avg => {
//                     // prove the avg aggregation is correct
//                     todo!();
//                 },
//                 AggregationType::Min => {
//                     // prove the min aggregation is correct
//                     todo!();
//                 },
//                 AggregationType::Max => {
//                     // prove the max aggregation is correct
//                     todo!();
//                 },
//             }
//         }

//         // TODO: do we want outputs?
//         Ok(res_table)
//     }
// }
