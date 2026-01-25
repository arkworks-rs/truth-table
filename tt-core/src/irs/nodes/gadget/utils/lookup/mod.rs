use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_COL_NAME, ROW_ID_COL_NAME, col::TrackedCol, col_oracle::TrackedColOracle,
    is_system_column, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_piop::{SnarkBackend, piop::PIOP, prover::ArgProver, verifier::ArgVerifier};
use col_toolbox::lookup::{HintedLookupPIOP, HintedLookupProverInput, HintedLookupVerifierInput};
use datafusion::functions_window::expr_fn::row_number;
use datafusion::prelude::DataFrame;
use datafusion_common::{Column, Result as DataFusionResult};
use datafusion_expr::{Expr, ExprFunctionExt, JoinType, col, expr_fn::when, lit};
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

    fn display(&self) -> String {
        let name = self.name();
        crate::irs::nodes::display_with_inputs(&name, &self.children())
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
            .map(|field| (field.clone(), !is_system_column(field.name())))
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
        _prover: &mut ark_piop::prover::ArgProver<B>,
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
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
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
        let included_len = included_table.data_tracked_polys_indices().len();
        let super_len = super_table.data_tracked_polys_indices().len();
        if included_len != super_len {
            panic!(
                "Lookup included/super data column mismatch: {} vs {}",
                included_len, super_len
            );
        }
        let (included_cols, super_col) = if included_len <= 1 {
            (
                Self::tracked_cols_from_table(&included_table),
                Self::single_col_from_table(prover, &super_table)?,
            )
        } else {
            let mut challenges = Vec::with_capacity(included_len);
            for _ in 0..included_len {
                challenges.push(prover.get_and_append_challenge(b"lookup_fold")?);
            }
            (
                vec![included_table.fold_all_data_columns(&challenges)],
                super_table.fold_all_data_columns(&challenges),
            )
        };
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

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
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

        let included_len = included_table.data_tracked_oracles_indices().len();
        let super_len = super_table.data_tracked_oracles_indices().len();
        if included_len != super_len {
            panic!(
                "Lookup included/super data column mismatch: {} vs {}",
                included_len, super_len
            );
        }
        let (included_cols, super_col) = if included_len <= 1 {
            (
                Self::tracked_cols_from_table_oracle(&included_table),
                Self::single_col_from_table_oracle(verifier, &super_table)?,
            )
        } else {
            let mut challenges = Vec::with_capacity(included_len);
            for _ in 0..included_len {
                challenges.push(verifier.get_and_append_challenge(b"lookup_fold")?);
            }
            (
                vec![included_table.fold_all_data_oracles(&challenges)],
                super_table.fold_all_data_oracles(&challenges),
            )
        };
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

impl<B: SnarkBackend> Default for GadgetNode<B> {
    fn default() -> Self {
        Self::new()
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

    fn single_col_from_table(
        prover: &mut ArgProver<B>,
        table: &TrackedTable<B>,
    ) -> ark_piop::errors::SnarkResult<TrackedCol<B>> {
        let data_indices = table.data_tracked_polys_indices();
        if data_indices.len() == 1 {
            return Ok(table.tracked_col_by_ind(data_indices[0]));
        }
        let mut challenges = Vec::with_capacity(data_indices.len());
        for _ in 0..data_indices.len() {
            challenges.push(prover.get_and_append_challenge(b"lookup_fold")?);
        }
        Ok(table.fold_all_data_columns(&challenges))
    }

    fn single_col_from_table_oracle(
        verifier: &mut ArgVerifier<B>,
        table: &TrackedTableOracle<B>,
    ) -> ark_piop::errors::SnarkResult<TrackedColOracle<B>> {
        let data_indices = table.data_tracked_oracles_indices();
        if data_indices.len() == 1 {
            return Ok(table.tracked_col_oracle_by_ind(data_indices[0]));
        }
        let mut challenges = Vec::with_capacity(data_indices.len());
        for _ in 0..data_indices.len() {
            challenges.push(verifier.get_and_append_challenge(b"lookup_fold")?);
        }
        Ok(table.fold_all_data_oracles(&challenges))
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

/// Compute a per-row multiplicity table for lookup constraints.
///
/// For each row in `a`:
/// - If `a.__activator__` is false, the multiplicity is 0.
/// - If `a.__activator__` is true, count how many rows in `b` are active and
///   share the same data-key (all non-system columns).
/// - If the same active key appears multiple times in `a`, only the first
///   occurrence gets the count; later duplicates get 0.
///
/// The output keeps the same row order as `a` (using `__row_id__` when present),
/// and returns a two-column table: (`__activator__`, `multiplicity`).
fn multiplicity_once_per_active_key(a: DataFrame, b: DataFrame) -> DataFusionResult<DataFrame> {
    // 1) Identify data-key columns (exclude system columns like activator/row_id).
    let schema = a.schema();
    let data_cols: Vec<String> = schema
        .fields()
        .iter()
        .filter(|f| !is_system_column(f.name()))
        .map(|f| f.name().clone())
        .collect();

    let row_id_cols: Vec<Column> = schema
        .iter()
        .filter_map(|(qualifier, field)| {
            (field.name() == ROW_ID_COL_NAME)
                .then_some(Column::new(qualifier.cloned(), ROW_ID_COL_NAME))
        })
        .collect();

    let activator_expr = combined_activator_expr(&a);
    let row_id_col = ROW_ID_COL_NAME;
    let a_with_row_id = if row_id_cols.len() == 1 {
        // Keep data columns + combined activator + row_id.
        a.select(
            data_cols
                .iter()
                .map(col)
                .chain(std::iter::once(
                    activator_expr.clone().alias(ACTIVATOR_COL_NAME),
                ))
                .chain(std::iter::once(
                    Expr::Column(row_id_cols[0].clone()).alias(row_id_col),
                ))
                .collect(),
        )?
    } else {
        // Attach a synthetic row id to preserve a deterministic order.
        let row_number_builder = if row_id_cols.is_empty() {
            row_number().partition_by(Vec::new())
        } else {
            row_number().partition_by(Vec::new()).order_by(
                row_id_cols
                    .iter()
                    .cloned()
                    .map(|col_ref| Expr::Column(col_ref).sort(true, true))
                    .collect(),
            )
        };
        let row_id_expr = row_number_builder.build()?.alias(row_id_col);
        a.select(
            data_cols
                .iter()
                .map(col)
                .chain(std::iter::once(
                    activator_expr.clone().alias(ACTIVATOR_COL_NAME),
                ))
                .chain(std::iter::once(row_id_expr))
                .collect(),
        )?
    };

    // 3) Mark the first active occurrence per key in `a`.
    //    This drives the "only first active row gets multiplicity" rule.
    let a_active = a_with_row_id
        .clone()
        .filter(col(ACTIVATOR_COL_NAME).eq(lit(true)))?;
    let rn_active_expr = row_number()
        .partition_by(data_cols.iter().map(col).collect())
        .order_by(vec![col(row_id_col).sort(true, true)])
        .build()?
        .alias("__rn_active__");
    let a_active = a_active.select(
        data_cols
            .iter()
            .map(col)
            .chain(std::iter::once(col(row_id_col)))
            .chain(std::iter::once(rn_active_expr))
            .collect(),
    )?;
    let a_active = a_active
        .select(vec![col(row_id_col), col("__rn_active__")])?
        .with_column_renamed(row_id_col, "__row_id_rhs__")?;

    // 4) Count active rows per key in `b`.
    let b_counts = b
        .clone()
        .filter(combined_activator_expr(&b).eq(lit(true)))?
        .aggregate(
            data_cols.iter().map(col).collect(),
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

    // 5) Join `a` with the "first active row" marker and with `b`'s counts.
    //    The row-id join is used to align markers with `a`'s original rows.
    let left_cols: Vec<&str> = data_cols.iter().map(|c| c.as_str()).collect();
    let right_cols: Vec<&str> = b_group_cols.iter().map(|c| c.as_str()).collect();
    let joined = a_with_row_id
        .join(
            a_active,
            JoinType::Left,
            &[row_id_col],
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

    // 6) Compute multiplicity:
    //    - inactive rows in `a` -> 0
    //    - first active row for a key -> count from `b` (or 0 if missing)
    //    - later active duplicates -> 0
    let mult_or_zero = when(col("mult").is_null(), lit(0_i64)).otherwise(col("mult"))?;
    let multiplicity_expr = when(col(ACTIVATOR_COL_NAME).eq(lit(false)), lit(0_i64))
        .when(col("__rn_active__").eq(lit(1_i64)), mult_or_zero)
        .otherwise(lit(0_i64))?
        .alias("multiplicity");

    // 7) Restore deterministic ordering by row_id and project final columns.
    let ordered = joined.sort(vec![col(row_id_col).sort(true, true)])?;
    ordered.select(vec![col(ACTIVATOR_COL_NAME), multiplicity_expr])
}

fn combined_activator_expr(df: &DataFrame) -> Expr {
    let mut activators: Vec<Expr> = df
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            (field.name() == ACTIVATOR_COL_NAME).then_some(Expr::Column(Column::new(
                qualifier.cloned(),
                ACTIVATOR_COL_NAME,
            )))
        })
        .collect();
    if activators.is_empty() {
        return lit(true);
    }
    let mut combined = activators.remove(0);
    for expr in activators {
        combined = combined.and(expr);
    }
    combined
}
