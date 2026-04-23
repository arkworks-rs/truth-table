use std::collections::HashSet;
use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_FIELD, col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_piop::arithmetic::mat_poly::mle::MLE;
use ark_piop::{SnarkBackend, piop::PIOP, prover::ArgProver, verifier::ArgVerifier};
use col_toolbox::lookup::{HintedLookupPIOP, HintedLookupProverInput, HintedLookupVerifierInput};
use datafusion::arrow::datatypes::{DataType, Field};
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

    fn children(&self) -> Vec<Arc<Node<B>>> {
        Vec::new()
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
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
            Some(hint_df) => hint_df,
            None => return Ok(()),
        };
        let _super_hint = match gadget_payload.get(SUPER_LABEL) {
            Some(hint_df) => hint_df,
            None => return Ok(()),
        };
        let _ = included_hint;
        let multiplicities_hint = multiplicity_schema_only_hint();

        gadget_payload.insert(SUPER_MULTIPLICITIES_LABEL.to_string(), multiplicities_hint);
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));
        Ok(())
    }
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let mut payload = match virtualized_ir.payload_for_node(&id).cloned() {
            Some(PayloadStructure::GadgetPayload(map)) => map,
            _ => return Ok(()),
        };
        let (Some(included_table), Some(super_table)) = (
            payload.get(INCLUDED_LABEL).cloned(),
            payload.get(SUPER_LABEL).cloned(),
        ) else {
            return Ok(());
        };

        let multiplicities =
            multiplicities_from_runtime_tables_prover(prover, &super_table, &included_table)?;
        payload.insert(SUPER_MULTIPLICITIES_LABEL.to_string(), multiplicities);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(payload)));
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let mut gadget_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        if gadget_payload.get(INCLUDED_LABEL).is_none() {
            return Ok(());
        }
        let _super_hint = match gadget_payload.get(SUPER_LABEL) {
            Some(hint_df) => hint_df,
            None => return Ok(()),
        };
        let multiplicities_hint = multiplicity_schema_only_hint();

        gadget_payload.insert(SUPER_MULTIPLICITIES_LABEL.to_string(), multiplicities_hint);
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));
        Ok(())
    }
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
    fn initialize_gadgets(
        &self,
        id: crate::irs::nodes::NodeId,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let (mut payload, multiplicities) = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => {
                let Some(super_table) = map.get(SUPER_LABEL) else {
                    return Ok(());
                };
                let multiplicities =
                    multiplicities_from_runtime_tables_verifier(verifier, super_table)?;
                (map.clone(), multiplicities)
            }
            _ => return Ok(()),
        };
        payload.insert(SUPER_MULTIPLICITIES_LABEL.to_string(), multiplicities);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(payload)));
        Ok(())
    }
}

fn multiplicity_schema_only_hint() -> crate::irs::nodes::hints::HintDF {
    let df = crate::irs::nodes::hints::schema_only_df(vec![
        ACTIVATOR_FIELD.as_ref().clone(),
        Field::new("multiplicity", DataType::Int64, true),
    ]);
    // This is only a planning-time schema placeholder. The real multiplicity
    // polynomial is computed and committed later in initialize_gadgets().
    crate::irs::nodes::hints::HintDF::new_virtual(df)
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

        // Debug subset relation expected by HintedLookupPIOP honest check.
        #[cfg(feature = "honest-prover")]
        {
            for (idx, included_col) in included_cols.iter().enumerate() {
                let included_vals: Vec<B::F> = included_col.effective_iter().into_iter().collect();
                let super_set = super_col.effective_hashset();
                let missing: Vec<B::F> = included_vals
                    .iter()
                    .copied()
                    .filter(|v| !super_set.contains(v))
                    .take(5)
                    .collect();
                tracing::debug!(
                    "Lookup subset debug: node_id={}, idx={}, included_log_size={}, super_log_size={}, included_active_count={}, super_active_count={}, super_set_size={}, missing_examples={:?}",
                    id,
                    idx,
                    included_col.log_size(),
                    super_col.log_size(),
                    included_vals.len(),
                    super_col.effective_iter().into_iter().count(),
                    super_set.len(),
                    missing
                );
            }
        }

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
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        use ark_piop::errors::SnarkError;
        use ark_piop::prover::errors::{HonestProverError, ProverError};
        use indexmap::IndexSet;

        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };

        let (Some(included_table), Some(super_table), Some(multiplicities_table)) = (
            payload.get(INCLUDED_LABEL).cloned(),
            payload.get(SUPER_LABEL).cloned(),
            payload.get(SUPER_MULTIPLICITIES_LABEL).cloned(),
        ) else {
            return Ok(());
        };

        let included_values = data_column_values(&included_table);
        let super_values = data_column_values(&super_table);
        if included_values.len() != super_values.len() {
            return Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::FalseClaim,
            )));
        }

        let super_active = active_row_mask(&super_table);
        let included_active = active_row_mask(&included_table);
        let multiplicity_values = multiplicity_column_values(&multiplicities_table);
        let multiplicity_active = active_row_mask(&multiplicities_table);

        let active_super_keys: IndexSet<String> = (0..super_table.size())
            .filter(|&row| super_active[row])
            .map(|row| key_at_row(&super_values, row))
            .collect();

        for (row, is_active) in included_active
            .iter()
            .enumerate()
            .take(included_table.size())
        {
            if !*is_active {
                continue;
            }
            let key = key_at_row(&included_values, row);
            if !active_super_keys.contains(&key) {
                tracing::debug!(
                    node_id = ?id,
                    row,
                    key = %key,
                    "lookup honest check found included key missing from super table"
                );
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }

        let expected = expected_lookup_multiplicities_from_values::<B>(
            &super_values,
            &included_values,
            &super_active,
            &included_active,
        );

        if multiplicity_values.len() != expected.len()
            || multiplicity_active.len() != expected.len()
        {
            return Err(SnarkError::ProverError(ProverError::HonestProverError(
                HonestProverError::FalseClaim,
            )));
        }

        for row in 0..expected.len() {
            if multiplicity_active[row] != super_active[row] {
                tracing::debug!(
                    node_id = ?id,
                    row,
                    "lookup honest check found multiplicity activator mismatch"
                );
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
            if multiplicity_values[row] != expected[row] {
                tracing::debug!(
                    node_id = ?id,
                    row,
                    "lookup honest check found multiplicity mismatch"
                );
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }

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

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
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
fn multiplicities_from_runtime_tables_prover<B: SnarkBackend>(
    prover: &mut ArgProver<B>,
    super_table: &TrackedTable<B>,
    included_table: &TrackedTable<B>,
) -> ark_piop::errors::SnarkResult<TrackedTable<B>> {
    let super_data_indices = super_table.data_tracked_polys_indices();
    let included_data_indices = included_table.data_tracked_polys_indices();
    assert_eq!(
        super_data_indices.len(),
        included_data_indices.len(),
        "Lookup included/super data column mismatch while recomputing multiplicities"
    );
    let super_values: Vec<Vec<B::F>> = super_data_indices
        .iter()
        .map(|idx| {
            super_table
                .tracked_col_by_ind(*idx)
                .data_tracked_poly()
                .evaluations()
        })
        .collect();
    let included_values: Vec<Vec<B::F>> = included_data_indices
        .iter()
        .map(|idx| {
            included_table
                .tracked_col_by_ind(*idx)
                .data_tracked_poly()
                .evaluations()
        })
        .collect();

    let super_activator = super_table
        .activator_tracked_poly()
        .map(|poly| poly.evaluations());
    let included_activator = included_table
        .activator_tracked_poly()
        .map(|poly| poly.evaluations());

    let multiplicities = expected_lookup_multiplicities_from_values::<B>(
        &super_values,
        &included_values,
        &active_mask_from_optional(super_activator.as_ref(), super_table.size()),
        &active_mask_from_optional(included_activator.as_ref(), included_table.size()),
    );

    let multiplicity_poly = prover.track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
        super_table.log_size(),
        multiplicities,
    ))?;
    let multiplicity_field = Arc::new(Field::new("multiplicity", DataType::Int64, false));
    Ok(TrackedTable::single_column_with_activator(
        multiplicity_field,
        multiplicity_poly,
        super_table.activator_tracked_poly(),
    ))
}

fn multiplicities_from_runtime_tables_verifier<B: SnarkBackend>(
    verifier: &mut ArgVerifier<B>,
    super_table: &TrackedTableOracle<B>,
) -> ark_piop::errors::SnarkResult<TrackedTableOracle<B>> {
    let multiplicity_oracle = verifier.track_next_mv_com()?;
    let multiplicity_field = Arc::new(Field::new("multiplicity", DataType::Int64, false));
    Ok(TrackedTableOracle::single_column_with_activator(
        multiplicity_field,
        multiplicity_oracle,
        super_table.activator_tracked_poly(),
    ))
}

fn key_at_row<F: core::fmt::Debug>(cols: &[Vec<F>], row: usize) -> String {
    if cols.is_empty() {
        return String::new();
    }
    let mut parts = Vec::with_capacity(cols.len());
    for col in cols {
        parts.push(format!("{:?}", col[row]));
    }
    parts.join("|")
}

fn data_column_values<B: SnarkBackend>(table: &TrackedTable<B>) -> Vec<Vec<B::F>> {
    table
        .data_tracked_polys_indices()
        .iter()
        .map(|idx| {
            table
                .tracked_col_by_ind(*idx)
                .data_tracked_poly()
                .evaluations()
        })
        .collect()
}

fn multiplicity_column_values<B: SnarkBackend>(table: &TrackedTable<B>) -> Vec<B::F> {
    let data_indices = table.data_tracked_polys_indices();
    assert_eq!(
        data_indices.len(),
        1,
        "Lookup multiplicity table must have exactly one data column"
    );
    table
        .tracked_col_by_ind(data_indices[0])
        .data_tracked_poly()
        .evaluations()
}

fn active_row_mask<B: SnarkBackend>(table: &TrackedTable<B>) -> Vec<bool> {
    active_mask_from_optional(
        table
            .activator_tracked_poly()
            .map(|poly| poly.evaluations())
            .as_ref(),
        table.size(),
    )
}

fn active_mask_from_optional<F: ark_ff::Field>(values: Option<&Vec<F>>, size: usize) -> Vec<bool> {
    match values {
        Some(vals) => vals
            .iter()
            .take(size)
            .map(|value| !value.is_zero())
            .collect(),
        None => vec![true; size],
    }
}

fn expected_lookup_multiplicities_from_values<B: SnarkBackend>(
    super_values: &[Vec<B::F>],
    included_values: &[Vec<B::F>],
    super_active: &[bool],
    included_active: &[bool],
) -> Vec<B::F> {
    let mut included_counts = std::collections::HashMap::<String, u64>::new();
    for (row, is_active) in included_active.iter().enumerate() {
        if !*is_active {
            continue;
        }
        let key = key_at_row(included_values, row);
        *included_counts.entry(key).or_insert(0) += 1;
    }

    let mut seen_active_super = HashSet::<String>::new();
    let mut multiplicities = vec![B::F::from(0u64); super_active.len()];
    for (row, out) in multiplicities
        .iter_mut()
        .enumerate()
        .take(super_active.len())
    {
        if !super_active[row] {
            continue;
        }
        let key = key_at_row(super_values, row);
        if seen_active_super.insert(key.clone()) {
            let count = included_counts.get(&key).copied().unwrap_or(0);
            *out = B::F::from(count);
        }
    }
    multiplicities
}
