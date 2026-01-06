use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_COL_NAME, col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_piop::{SnarkBackend, piop::PIOP, prover::ArgProver, verifier::ArgVerifier};
use col_toolbox::lookup::{HintedLookupPIOP, HintedLookupProverInput, HintedLookupVerifierInput};
use datafusion::functions_window::expr_fn::row_number;
use datafusion::prelude::DataFrame;
use datafusion_common::Result as DataFusionResult;
use datafusion_expr::{ExprFunctionExt, JoinType, col, expr_fn::when, lit};
use datafusion_functions_aggregate::expr_fn::count;
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub const INCLUDED_LABEL: &str = "_included_";
pub const SUPER_LABEL: &str = "_super_";
pub const SUPER_MULTIPLICITIES_LABEL: &str = "_super_multiplicities_";

#[cfg(test)]
mod tests;

pub struct GadgetNode<B: SnarkBackend> {
    phantom: std::marker::PhantomData<B>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Lookup".to_string()
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let mut gadget_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };

        let included_hint = match gadget_payload.get(INCLUDED_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };
        let super_hint = match gadget_payload.get(SUPER_LABEL) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };

        let multiplicities_df = multiplicity_once_per_active_key(
            super_hint.data_frame().clone(),
            included_hint.data_frame().clone(),
        )
        .expect("lookup multiplicity hint planning should succeed");

        let should_materialize = multiplicities_df
            .schema()
            .fields()
            .iter()
            .map(|field| (field.clone(), field.name() != ACTIVATOR_COL_NAME))
            .collect();
        let multiplicities_hint =
            crate::irs::nodes::hints::HintDF::new(multiplicities_df, should_materialize);

        gadget_payload.insert(SUPER_MULTIPLICITIES_LABEL.to_string(), multiplicities_hint);
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));
        Ok(())
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        Vec::new()
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for Lookup gadget node");
        };

        let (Some(included_table), Some(super_table), Some(multiplicities_table)) = (
            payload.get(INCLUDED_LABEL).cloned(),
            payload.get(SUPER_LABEL).cloned(),
            payload.get(SUPER_MULTIPLICITIES_LABEL).cloned(),
        ) else {
            panic!("Expected included, super, and super multiplicities inputs for Lookup gadget");
        };
        let included_cols = Self::tracked_cols_from_table(&included_table);
        let super_col = Self::single_col_from_table(&super_table);
        let super_col_multiplicities =
            Self::multiplicities_from_table(&multiplicities_table, included_cols.len());

        let input = HintedLookupProverInput {
            included_cols,
            super_col,
            super_col_multiplicities,
        };
        HintedLookupPIOP::<B>::prove(prover, input)?;
        Ok(())
    }

    fn verify(
        &self,
        verifier: &mut ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("Expected gadget payload for Lookup gadget node");
        };

        let (Some(included_table), Some(super_table), Some(multiplicities_table)) = (
            payload.get(INCLUDED_LABEL).cloned(),
            payload.get(SUPER_LABEL).cloned(),
            payload.get(SUPER_MULTIPLICITIES_LABEL).cloned(),
        ) else {
            panic!("Expected included, super, and super multiplicities inputs for Lookup gadget");
        };

        let included_cols = Self::tracked_cols_from_table_oracle(&included_table);
        let super_col = Self::single_col_from_table_oracle(&super_table);
        let super_col_multiplicities =
            Self::multiplicities_from_table_oracle(&multiplicities_table, included_cols.len());

        let input = HintedLookupVerifierInput {
            included_tracked_col_oracles: included_cols,
            super_tracked_col_oracle: super_col,
            super_col_multiplicities,
        };
        HintedLookupPIOP::<B>::verify(verifier, input)?;
        Ok(())
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }

    fn tracked_cols_from_table(table: &TrackedTable<B>) -> Vec<TrackedCol<B>> {
        table
            .data_tracked_polys_indices()
            .into_iter()
            .map(|idx| table.tracked_col_by_ind(idx))
            .collect()
    }

    fn tracked_cols_from_table_oracle(table: &TrackedTableOracle<B>) -> Vec<TrackedColOracle<B>> {
        table
            .data_tracked_oracles_indices()
            .into_iter()
            .map(|idx| table.tracked_col_oracle_by_ind(idx))
            .collect()
    }

    fn single_col_from_table(table: &TrackedTable<B>) -> TrackedCol<B> {
        let data_indices = table.data_tracked_polys_indices();
        debug_assert_eq!(
            data_indices.len(),
            1,
            "Lookup gadget expects a single data column for super input."
        );
        table.tracked_col_by_ind(data_indices[0])
    }

    fn single_col_from_table_oracle(table: &TrackedTableOracle<B>) -> TrackedColOracle<B> {
        let data_indices = table.data_tracked_oracles_indices();
        debug_assert_eq!(
            data_indices.len(),
            1,
            "Lookup gadget expects a single data column for super input."
        );
        table.tracked_col_oracle_by_ind(data_indices[0])
    }

    fn multiplicities_from_table(
        table: &TrackedTable<B>,
        expected_len: usize,
    ) -> Vec<ark_piop::prover::structs::polynomial::TrackedPoly<B>> {
        let data_indices = table.data_tracked_polys_indices();
        debug_assert_eq!(
            data_indices.len(),
            expected_len,
            "Lookup multiplicity hints must align with included columns."
        );
        data_indices
            .into_iter()
            .map(|idx| table.tracked_col_by_ind(idx).data_tracked_poly())
            .collect()
    }

    fn multiplicities_from_table_oracle(
        table: &TrackedTableOracle<B>,
        expected_len: usize,
    ) -> Vec<ark_piop::verifier::structs::oracle::TrackedOracle<B>> {
        let data_indices = table.data_tracked_oracles_indices();
        debug_assert_eq!(
            data_indices.len(),
            expected_len,
            "Lookup multiplicity hints must align with included column oracles."
        );
        data_indices
            .into_iter()
            .map(|idx| table.tracked_col_oracle_by_ind(idx).data_tracked_oracle())
            .collect()
    }
}

fn multiplicity_once_per_active_key(a: DataFrame, b: DataFrame) -> DataFusionResult<DataFrame> {
    let schema = a.schema();
    let data_cols: Vec<String> = schema
        .fields()
        .iter()
        .filter(|f| f.name() != ACTIVATOR_COL_NAME)
        .map(|f| f.name().clone())
        .collect();

    let row_id_expr = row_number()
        .partition_by(Vec::new())
        .build()?
        .alias("__row_id__");
    let a_with_row_id = a.select(
        data_cols
            .iter()
            .map(|c| col(c))
            .chain(std::iter::once(col(ACTIVATOR_COL_NAME)))
            .chain(std::iter::once(row_id_expr))
            .collect(),
    )?;

    let a_active = a_with_row_id
        .clone()
        .filter(col(ACTIVATOR_COL_NAME).eq(lit(true)))?;
    let rn_active_expr = row_number()
        .partition_by(data_cols.iter().map(|c| col(c)).collect())
        .order_by(vec![col("__row_id__").sort(true, true)])
        .build()?
        .alias("__rn_active__");
    let a_active = a_active.select(
        data_cols
            .iter()
            .map(|c| col(c))
            .chain(std::iter::once(col("__row_id__")))
            .chain(std::iter::once(rn_active_expr))
            .collect(),
    )?;
    let a_active = a_active
        .select(vec![col("__row_id__"), col("__rn_active__")])?
        .with_column_renamed("__row_id__", "__row_id_rhs__")?;

    let b_counts = b.filter(col(ACTIVATOR_COL_NAME).eq(lit(true)))?.aggregate(
        data_cols.iter().map(|c| col(c)).collect(),
        vec![count(lit(1_i64)).alias("mult")],
    )?;
    let b_group_cols: Vec<String> = data_cols
        .iter()
        .enumerate()
        .map(|(idx, name)| format!("__b_group_{idx}_{name}"))
        .collect();
    let mut renamed_b_counts = b_counts;
    for (original, renamed) in data_cols.iter().zip(b_group_cols.iter()) {
        renamed_b_counts = renamed_b_counts.with_column_renamed(original, renamed)?;
    }

    let left_cols: Vec<&str> = data_cols.iter().map(|c| c.as_str()).collect();
    let right_cols: Vec<&str> = b_group_cols.iter().map(|c| c.as_str()).collect();
    let joined = a_with_row_id
        .join(
            a_active,
            JoinType::Left,
            &["__row_id__"],
            &["__row_id_rhs__"],
            None,
        )?
        .join(
            renamed_b_counts,
            JoinType::Left,
            &left_cols,
            &right_cols,
            None,
        )?;

    let mult_or_zero = when(col("mult").is_null(), lit(0_i64)).otherwise(col("mult"))?;
    let multiplicity_expr = when(col(ACTIVATOR_COL_NAME).eq(lit(false)), lit(0_i64))
        .when(col("__rn_active__").eq(lit(1_i64)), mult_or_zero)
        .otherwise(lit(0_i64))?
        .alias("multiplicity");

    let ordered = joined.sort(vec![col("__row_id__").sort(true, true)])?;
    ordered.select(vec![col(ACTIVATOR_COL_NAME), multiplicity_expr])
}
