use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_FIELD, col::TrackedCol, col_oracle::TrackedColOracle,
    encoding::segment_suffixes_for_type, is_system_column, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_piop::{
    SnarkBackend,
    arithmetic::errors::DataTypeError,
    errors::{SnarkError, SnarkResult},
    prover::structs::polynomial::TrackedPoly,
    verifier::structs::oracle::TrackedOracle,
};
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use datafusion_common::{Column, TableReference};
use datafusion_expr::UNNAMED_TABLE;

use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{
            IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps,
            hints::{HintDF, QUALIFIER_METADATA_KEY},
            utils::{compaction, contig_sort, lookup},
        },
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};
pub mod lexicographic;
#[cfg(test)]
mod tests;

pub const INPUT_LABEL: &str = "__input__";
pub const OUTPUT_LABEL: &str = "__output__";
/// The sort keys of the input rows, one column per key named
/// [`sort_key_name`], with the activator and row ids. Virtual.
pub const INPUT_SORT_EXPRS: &str = "__input_sort_exprs__";

/// The column of ORDER BY key `index` in the sort check's table: a name of
/// its own, so two keys over same-named columns stay apart.
pub fn sort_key_name(index: usize) -> String {
    format!("__sort_key_{index}")
}

/// The label of the base-table side of rank key `index`'s lookup: the scan's
/// hash slots, `__length` and rank, under the scan's activator.
pub fn rank_super_label(index: usize) -> String {
    format!("__rank_super_{index}__")
}

#[derive(Clone, Debug)]
pub struct SortKey {
    /// The key column of the sort's input (and output), as its schema
    /// qualifies it.
    pub column: Column,
    pub asc: bool,
    pub order: KeyOrder,
}

/// What a key is sorted on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyOrder {
    /// Its own encoding, which preserves its order.
    Value,
    /// A string's base column rank (TruthTable++ Rank-Based String Sort Check, §7.3, PIOP 13).
    Rank,
    /// A string's characters (TruthTable++ String Sort Check, §7.2, PIOP 11).
    Characters,
}

/// Whether the ORDER BY is checked by the String Sort Check chain
/// ([`lexicographic`]) rather than the sort check on values and ranks.
pub(crate) fn sorts_on_characters(keys: &[SortKey]) -> bool {
    keys.iter().any(|key| key.order == KeyOrder::Characters)
}

impl SortKey {
    /// The index among `columns`, given as (qualifier, name), of the key's
    /// column: the one of its name whose qualifier, where both are known,
    /// is the key's. A key that names no column, or more than one, is an
    /// error.
    pub(crate) fn index_in<'a>(
        &self,
        columns: impl IntoIterator<Item = (Option<String>, &'a str)>,
    ) -> SnarkResult<usize> {
        let relation = self.column.relation.as_ref().map(|r| r.to_string());
        let named: Vec<(usize, Option<String>)> = columns
            .into_iter()
            .enumerate()
            .filter(|(_, (_, name))| *name == self.column.name)
            .map(|(index, (qualifier, _))| (index, qualifier))
            .collect();
        let chosen: Vec<usize> = named
            .iter()
            .filter(|(_, qualifier)| match (&relation, qualifier) {
                (Some(relation), Some(qualifier)) => relation == qualifier,
                _ => true,
            })
            .map(|(index, _)| *index)
            .collect();
        match chosen.as_slice() {
            [index] => Ok(*index),
            _ => Err(SnarkError::DataTypeError(DataTypeError::NotSupported(
                format!(
                    "ORDER BY key {} names {} columns of the sorted table, not one (qualifiers of that name: {:?})",
                    self.column,
                    chosen.len(),
                    named
                        .iter()
                        .map(|(_, qualifier)| qualifier)
                        .collect::<Vec<_>>()
                ),
            ))),
        }
    }
}

/// The qualifier of a column given by its field and, in a DataFrame, its
/// schema qualifier: the one the hints record in the field, else the
/// schema's. The placeholder qualifier of an unnamed (schema-only) table
/// qualifies nothing.
pub(crate) fn column_qualifier(
    schema_qualifier: Option<&TableReference>,
    field: &Field,
) -> Option<String> {
    field
        .metadata()
        .get(QUALIFIER_METADATA_KEY)
        .cloned()
        .filter(|qualifier| qualifier != UNNAMED_TABLE)
        .or_else(|| {
            schema_qualifier
                .map(|qualifier| qualifier.to_string())
                .filter(|qualifier| qualifier != UNNAMED_TABLE)
        })
}

/// The ORDER BY check (paper PIOP 14): the output is a permutation of the
/// input (the compaction child) sorted on its keys (the sort check). With a
/// key sorted on its characters the sort check is the [`lexicographic`]
/// chain; otherwise it is the following.
///
/// A string key is sorted on its rank, as in the TruthTable++ Rank-Based
/// String Sort Check (§7.3, PIOP 13). No operator carries the rank, so its
/// provenance is taken against the base column instead of inherited: the
/// sorted rank column `rk_out`, which the sort check commits, is looked up
/// as (output hash slots, `__length`, `rk_out`) in (hash slots, `__length`,
/// rank) of the base table scan, one lookup child per rank key. Each output
/// string is a base string (upstream checks bind it), so collision
/// resistance of (hash, length) pins `rk_out` to the owner-committed rank of
/// that very string; lineage only picks a scan that makes the lookup
/// complete. The multi-key sort is the sort check's, with one-way ties, on
/// ranks in place of strings. So a string key costs an integer key plus a
/// lookup into the base table with a base-sized multiplicity column, more
/// than PIOP 13's integer-sort cost; carrying the rank through the
/// operators would remove the lookup.
pub struct GadgetNode<B: SnarkBackend> {
    sort_check: SortCheck<B>,
    compaction_gadget: Arc<Node<B>>,
    keys: Vec<SortKey>,
}

enum SortCheck<B: SnarkBackend> {
    OnValues {
        sort_gadget: Arc<Node<B>>,
        /// One per rank key, in key order.
        rank_lookups: Vec<Arc<Node<B>>>,
    },
    OnCharacters(Arc<Node<B>>),
}

/// The sort check's table hint: the key columns of the input rows, which the
/// sort check sorts to plan its witnesses. Only the rank columns are
/// committed, here, in sorted order: they are `rk_out`. The other key
/// columns are the output's own, which `initialize_gadgets` puts in.
fn populate_sort_gadget_table<B: SnarkBackend>(
    planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    sort_gadget_node_id: crate::irs::nodes::NodeId,
    key_hint: &HintDF,
    keys: &[SortKey],
) {
    let rank_names: Vec<String> = keys
        .iter()
        .enumerate()
        .filter(|(_, key)| key.order == KeyOrder::Rank)
        .map(|(index, _)| sort_key_name(index))
        .collect();
    let df = key_hint.data_frame().clone();
    let should_materialize = df
        .schema()
        .fields()
        .iter()
        .map(|field| (field.clone(), rank_names.contains(field.name())))
        .collect();
    let mut payload = match planned_ir.payload_for_node(&sort_gadget_node_id) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    payload.insert(
        contig_sort::TABLE_LABEL.to_string(),
        HintDF::new(df, should_materialize),
    );
    planned_ir.set_payload_for_node(
        sort_gadget_node_id,
        Some(PayloadStructure::GadgetPayload(payload)),
    );
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Order By".to_string()
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

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        match &self.sort_check {
            SortCheck::OnValues {
                sort_gadget,
                rank_lookups,
            } => {
                let mut children = vec![sort_gadget.clone(), self.compaction_gadget.clone()];
                children.extend(rank_lookups.iter().cloned());
                children
            }
            SortCheck::OnCharacters(chain) => vec![chain.clone(), self.compaction_gadget.clone()],
        }
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
        let input_hint = match gadget_payload.get(INPUT_SORT_EXPRS) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };

        let SortCheck::OnValues { sort_gadget, .. } = &self.sort_check else {
            return Ok(());
        };
        // Row-id was only needed for ordering: drop it from the input payload.
        let sanitized_input = crate::irs::nodes::hints::strip_row_id_from_hint(&input_hint);
        gadget_payload.insert(INPUT_SORT_EXPRS.to_string(), sanitized_input);
        populate_sort_gadget_table(planned_ir, sort_gadget.id(), &input_hint, &self.keys);
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
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };

        let mut compaction_payload =
            match virtualized_ir.payload_for_node(&self.compaction_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
        if let Some(input) = payload.get(INPUT_LABEL).cloned() {
            compaction_payload.insert(compaction::INPUT_LABEL.to_string(), input);
        }
        if let Some(output) = payload.get(OUTPUT_LABEL).cloned() {
            compaction_payload.insert(compaction::OUTPUT_LABEL.to_string(), output);
        }
        if !compaction_payload.is_empty() {
            virtualized_ir.set_payload_for_node(
                self.compaction_gadget.id(),
                Some(PayloadStructure::GadgetPayload(compaction_payload)),
            );
        }

        let (sort_gadget, rank_lookups) = match &self.sort_check {
            SortCheck::OnValues {
                sort_gadget,
                rank_lookups,
            } => (sort_gadget, rank_lookups),
            SortCheck::OnCharacters(chain) => {
                virtualized_ir.set_payload_for_node(
                    chain.id(),
                    Some(PayloadStructure::GadgetPayload(chain_payload(&payload))),
                );
                return Ok(());
            }
        };
        if let Some(output) = payload.get(OUTPUT_LABEL) {
            let mut sort_payload = match virtualized_ir.payload_for_node(&sort_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            let (table, lookups) = self.sort_check_tables_prover(
                output,
                sort_payload.get(contig_sort::TABLE_LABEL),
                &payload,
            )?;
            for (lookup_node, (included, super_table)) in rank_lookups.iter().zip(lookups) {
                virtualized_ir.set_payload_for_node(
                    lookup_node.id(),
                    Some(PayloadStructure::GadgetPayload(IndexMap::from([
                        (lookup::INCLUDED_LABEL.to_string(), included),
                        (lookup::SUPER_LABEL.to_string(), super_table),
                    ]))),
                );
            }
            sort_payload.insert(contig_sort::TABLE_LABEL.to_string(), table);
            if let Some(count) = payload.get(contig_sort::ACTIVE_ROWS_LABEL) {
                sort_payload.insert(contig_sort::ACTIVE_ROWS_LABEL.to_string(), count.clone());
            }
            virtualized_ir.set_payload_for_node(
                sort_gadget.id(),
                Some(PayloadStructure::GadgetPayload(sort_payload)),
            );
        }
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let gadget_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => return Ok(()),
        };
        let input_hint = match gadget_payload.get(INPUT_SORT_EXPRS) {
            Some(hint_df) => hint_df.clone(),
            None => return Ok(()),
        };

        if let SortCheck::OnValues { sort_gadget, .. } = &self.sort_check {
            populate_sort_gadget_table(planned_ir, sort_gadget.id(), &input_hint, &self.keys);
        }
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
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            return Ok(());
        };

        let mut compaction_payload =
            match virtualized_ir.payload_for_node(&self.compaction_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
        if let Some(input) = payload.get(INPUT_LABEL).cloned() {
            compaction_payload.insert(compaction::INPUT_LABEL.to_string(), input);
        }
        if let Some(output) = payload.get(OUTPUT_LABEL).cloned() {
            compaction_payload.insert(compaction::OUTPUT_LABEL.to_string(), output);
        }
        if !compaction_payload.is_empty() {
            virtualized_ir.set_payload_for_node(
                self.compaction_gadget.id(),
                Some(PayloadStructure::GadgetPayload(compaction_payload)),
            );
        }

        let (sort_gadget, rank_lookups) = match &self.sort_check {
            SortCheck::OnValues {
                sort_gadget,
                rank_lookups,
            } => (sort_gadget, rank_lookups),
            SortCheck::OnCharacters(chain) => {
                virtualized_ir.set_payload_for_node(
                    chain.id(),
                    Some(PayloadStructure::GadgetPayload(chain_payload(&payload))),
                );
                return Ok(());
            }
        };
        if let Some(output) = payload.get(OUTPUT_LABEL) {
            let mut sort_payload = match virtualized_ir.payload_for_node(&sort_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
            let (table, lookups) = self.sort_check_tables_verifier(
                output,
                sort_payload.get(contig_sort::TABLE_LABEL),
                &payload,
            )?;
            for (lookup_node, (included, super_table)) in rank_lookups.iter().zip(lookups) {
                virtualized_ir.set_payload_for_node(
                    lookup_node.id(),
                    Some(PayloadStructure::GadgetPayload(IndexMap::from([
                        (lookup::INCLUDED_LABEL.to_string(), included),
                        (lookup::SUPER_LABEL.to_string(), super_table),
                    ]))),
                );
            }
            sort_payload.insert(contig_sort::TABLE_LABEL.to_string(), table);
            if let Some(count) = payload.get(contig_sort::ACTIVE_ROWS_LABEL) {
                sort_payload.insert(contig_sort::ACTIVE_ROWS_LABEL.to_string(), count.clone());
            }
            virtualized_ir.set_payload_for_node(
                sort_gadget.id(),
                Some(PayloadStructure::GadgetPayload(sort_payload)),
            );
        }
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
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
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

/// The [`lexicographic`] chain's payload: the ORDER BY's input, output and
/// active-row count.
fn chain_payload<T: Clone>(payload: &IndexMap<String, T>) -> IndexMap<String, T> {
    [INPUT_LABEL, OUTPUT_LABEL, contig_sort::ACTIVE_ROWS_LABEL]
        .into_iter()
        .filter_map(|label| Some((label.to_string(), payload.get(label)?.clone())))
        .collect()
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(keys: Vec<SortKey>) -> Self {
        let compaction_gadget =
            Arc::new(Node::<B>::Gadget(Arc::new(compaction::GadgetNode::new())));
        if sorts_on_characters(&keys) {
            let chain = Arc::new(Node::<B>::Gadget(Arc::new(lexicographic::GadgetNode::new(
                keys.clone(),
            ))));
            return Self {
                sort_check: SortCheck::OnCharacters(chain),
                compaction_gadget,
                keys,
            };
        }
        let sort_specs = keys
            .iter()
            .enumerate()
            .map(|(index, key)| (sort_key_name(index), key.asc, false))
            .collect();
        // DataFusion sort expressions do not encode strictness, so the sort
        // gadget is non-strict.
        let strict: bool = false;
        let sort_gadget = Arc::new(Node::<B>::Gadget(Arc::new(contig_sort::GadgetNode::new(
            contig_sort::SortConfig::PerColumn(contig_sort::PerColumnConfig { sort_specs, strict }),
        ))));
        let rank_lookups = keys
            .iter()
            .filter(|key| key.order == KeyOrder::Rank)
            .map(|_| Arc::new(Node::<B>::Gadget(Arc::new(lookup::GadgetNode::new()))))
            .collect();
        Self {
            sort_check: SortCheck::OnValues {
                sort_gadget,
                rank_lookups,
            },
            compaction_gadget,
            keys,
        }
    }

    /// The sort check's table (paper PIOP 14, step 3): key `i` under
    /// [`sort_key_name`], the output's own column, or `rk_out` from the sort
    /// check's committed table for a rank key; then the output activator.
    /// Also each rank key's (INCLUDED, SUPER) lookup tables. INCLUDED holds
    /// the very polynomials of the output and of the sort check's table, so
    /// the lookup constrains the columns the sort check sorts.
    #[allow(clippy::type_complexity)]
    fn sort_check_tables_prover(
        &self,
        output: &TrackedTable<B>,
        committed: Option<&TrackedTable<B>>,
        payload: &IndexMap<String, TrackedTable<B>>,
    ) -> SnarkResult<(TrackedTable<B>, Vec<(TrackedTable<B>, TrackedTable<B>)>)> {
        let activator = output
            .activator_tracked_poly()
            .expect("the sort output's activator is C_{µ,s}");
        let columns: Vec<(&FieldRef, &TrackedCol<B>)> = output
            .tracked_cols_iter()
            .filter(|(field, _)| !is_system_column(field.name()))
            .collect();
        let mut table = IndexMap::new();
        let mut lookups = Vec::new();
        for (index, key) in self.keys.iter().enumerate() {
            let (field, column) = columns[key.index_in(
                columns
                    .iter()
                    .map(|(field, _)| (column_qualifier(None, field), field.name().as_str())),
            )?];
            let name = sort_key_name(index);
            if key.order != KeyOrder::Rank {
                table.insert(
                    Arc::new(Field::new(&name, field.data_type().clone(), true)),
                    single_segment(column.num_segments(), key, column.data_tracked_poly())?,
                );
                continue;
            }
            let rank = committed
                .and_then(|table| table.tracked_col_by_name(&name))
                .map(|column| column.data_tracked_poly())
                .ok_or_else(|| missing_rank(&name))?;
            table.insert(rank_field(&name), rank.clone());
            let mut included = string_identity_prover(column, field.data_type())?;
            included.push(rank);
            let super_table = payload
                .get(&rank_super_label(index))
                .cloned()
                .ok_or_else(|| missing_rank(&rank_super_label(index)))?;
            lookups.push((
                lookup_table_prover(included, Some(activator.clone()), output.log_size()),
                super_table,
            ));
        }
        table.insert(ACTIVATOR_FIELD.clone(), activator);
        Ok((
            TrackedTable::new(Some(schema_of(table.keys())), table, output.log_size()),
            lookups,
        ))
    }

    #[allow(clippy::type_complexity)]
    fn sort_check_tables_verifier(
        &self,
        output: &TrackedTableOracle<B>,
        committed: Option<&TrackedTableOracle<B>>,
        payload: &IndexMap<String, TrackedTableOracle<B>>,
    ) -> SnarkResult<(
        TrackedTableOracle<B>,
        Vec<(TrackedTableOracle<B>, TrackedTableOracle<B>)>,
    )> {
        let activator = output
            .activator_tracked_poly()
            .expect("the sort output's activator is C_{µ,s}");
        let columns: Vec<(&FieldRef, &TrackedColOracle<B>)> = output
            .tracked_col_oracles_iter()
            .filter(|(field, _)| !is_system_column(field.name()))
            .collect();
        let mut table = IndexMap::new();
        let mut lookups = Vec::new();
        for (index, key) in self.keys.iter().enumerate() {
            let (field, column) = columns[key.index_in(
                columns
                    .iter()
                    .map(|(field, _)| (column_qualifier(None, field), field.name().as_str())),
            )?];
            let name = sort_key_name(index);
            if key.order != KeyOrder::Rank {
                table.insert(
                    Arc::new(Field::new(&name, field.data_type().clone(), true)),
                    single_segment(column.num_segments(), key, column.data_tracked_oracle())?,
                );
                continue;
            }
            let rank = committed
                .and_then(|table| table.tracked_col_oracle_by_name(&name))
                .map(|column| column.data_tracked_oracle())
                .ok_or_else(|| missing_rank(&name))?;
            table.insert(rank_field(&name), rank.clone());
            let mut included = string_identity_verifier(column, field.data_type())?;
            included.push(rank);
            let super_table = payload
                .get(&rank_super_label(index))
                .cloned()
                .ok_or_else(|| missing_rank(&rank_super_label(index)))?;
            lookups.push((
                lookup_table_verifier(included, Some(activator.clone()), output.log_size()),
                super_table,
            ));
        }
        table.insert(ACTIVATOR_FIELD.clone(), activator);
        Ok((
            TrackedTableOracle::new(Some(schema_of(table.keys())), table, output.log_size()),
            lookups,
        ))
    }
}

fn single_segment<T>(segments: usize, key: &SortKey, data: T) -> SnarkResult<T> {
    if segments == 1 {
        Ok(data)
    } else {
        Err(SnarkError::DataTypeError(DataTypeError::NotSupported(
            format!(
                "ORDER BY key {} is encoded in {segments} segments, not one ordered value",
                key.column
            ),
        )))
    }
}

fn missing_rank(name: &str) -> SnarkError {
    SnarkError::DataTypeError(DataTypeError::NotSupported(format!(
        "the ORDER BY gadget has no {name}"
    )))
}

fn missing_segment(suffix: &str) -> SnarkError {
    SnarkError::DataTypeError(DataTypeError::NotSupported(format!(
        "an ORDER BY string column lacks its {suffix:?} segment"
    )))
}

fn rank_field(name: &str) -> FieldRef {
    Arc::new(Field::new(name, DataType::UInt32, true))
}

/// A string column's hash slots and `__length`, in encoder order: what a
/// lookup matches to identify the string. When every string of one table is
/// at most a byte long, its slot is the byte itself, not a hash, so the
/// lookup is complete only if both tables encode alike.
pub(crate) fn string_identity_prover<B: SnarkBackend>(
    column: &TrackedCol<B>,
    data_type: &DataType,
) -> SnarkResult<Vec<TrackedPoly<B>>> {
    segment_suffixes_for_type::<B::F>(data_type)
        .iter()
        .map(|suffix| match suffix.as_str() {
            "" => Ok(column.data_tracked_poly()),
            suffix => column
                .aux_segment(suffix)
                .map(|segment| segment.data.clone())
                .ok_or_else(|| missing_segment(suffix)),
        })
        .collect()
}

pub(crate) fn string_identity_verifier<B: SnarkBackend>(
    column: &TrackedColOracle<B>,
    data_type: &DataType,
) -> SnarkResult<Vec<TrackedOracle<B>>> {
    segment_suffixes_for_type::<B::F>(data_type)
        .iter()
        .map(|suffix| match suffix.as_str() {
            "" => Ok(column.data_tracked_oracle()),
            suffix => column
                .aux_segment(suffix)
                .map(|segment| segment.data.clone())
                .ok_or_else(|| missing_segment(suffix)),
        })
        .collect()
}

fn lookup_field(index: usize) -> FieldRef {
    Arc::new(Field::new(
        format!("rank_lookup_{index}"),
        DataType::Int64,
        true,
    ))
}

/// A lookup table whose data columns are `columns`, in order.
pub(crate) fn lookup_table_prover<B: SnarkBackend>(
    columns: Vec<TrackedPoly<B>>,
    activator: Option<TrackedPoly<B>>,
    log_size: usize,
) -> TrackedTable<B> {
    let mut polys: IndexMap<FieldRef, TrackedPoly<B>> = columns
        .into_iter()
        .enumerate()
        .map(|(index, poly)| (lookup_field(index), poly))
        .collect();
    polys.extend(activator.map(|poly| (ACTIVATOR_FIELD.clone(), poly)));
    TrackedTable::new(Some(schema_of(polys.keys())), polys, log_size)
}

pub(crate) fn lookup_table_verifier<B: SnarkBackend>(
    columns: Vec<TrackedOracle<B>>,
    activator: Option<TrackedOracle<B>>,
    log_size: usize,
) -> TrackedTableOracle<B> {
    let mut oracles: IndexMap<FieldRef, TrackedOracle<B>> = columns
        .into_iter()
        .enumerate()
        .map(|(index, oracle)| (lookup_field(index), oracle))
        .collect();
    oracles.extend(activator.map(|oracle| (ACTIVATOR_FIELD.clone(), oracle)));
    TrackedTableOracle::new(Some(schema_of(oracles.keys())), oracles, log_size)
}

fn schema_of<'a>(fields: impl Iterator<Item = &'a FieldRef>) -> Schema {
    Schema::new(
        fields
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>(),
    )
}
