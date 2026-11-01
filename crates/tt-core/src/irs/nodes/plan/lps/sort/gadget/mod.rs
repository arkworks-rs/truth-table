use std::sync::Arc;

use arithmetic::{
    ACTIVATOR_FIELD,
    col::TrackedCol,
    col_oracle::TrackedColOracle,
    encoding::{STRING_RANK_SUFFIX, segment_suffixes_for_type},
    is_system_column,
    table::TrackedTable,
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
            utils::{compaction, contig_sort},
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
/// String Sort Check (§7.3, PIOP 13): the output's `__rank` segment of the
/// key. The permutation check ties it to the input's, and every operator
/// below ties its copy to its own input's, down to the rank the data owner
/// committed for that string.
pub struct GadgetNode<B: SnarkBackend> {
    sort_check: SortCheck<B>,
    compaction_gadget: Arc<Node<B>>,
    keys: Vec<SortKey>,
}

enum SortCheck<B: SnarkBackend> {
    OnValues(Arc<Node<B>>),
    OnCharacters(Arc<Node<B>>),
}

/// The sort check's table hint: the key columns of the input rows, which the
/// sort check sorts to plan its witnesses. Nothing is committed here: the
/// key columns are the output's own, which `initialize_gadgets` puts in.
fn populate_sort_gadget_table<B: SnarkBackend>(
    planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    sort_gadget_node_id: crate::irs::nodes::NodeId,
    key_hint: &HintDF,
) {
    let mut payload = match planned_ir.payload_for_node(&sort_gadget_node_id) {
        Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
        _ => IndexMap::new(),
    };
    payload.insert(
        contig_sort::TABLE_LABEL.to_string(),
        HintDF::new_virtual(key_hint.data_frame().clone()),
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
            SortCheck::OnValues(check) | SortCheck::OnCharacters(check) => {
                vec![check.clone(), self.compaction_gadget.clone()]
            }
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

        let SortCheck::OnValues(sort_gadget) = &self.sort_check else {
            return Ok(());
        };
        // Row-id was only needed for ordering: drop it from the input payload.
        let sanitized_input = crate::irs::nodes::hints::strip_row_id_from_hint(&input_hint);
        gadget_payload.insert(INPUT_SORT_EXPRS.to_string(), sanitized_input);
        populate_sort_gadget_table(planned_ir, sort_gadget.id(), &input_hint);
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

        let sort_gadget = match &self.sort_check {
            SortCheck::OnValues(sort_gadget) => sort_gadget,
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
            let table = self.sort_check_table_prover(output)?;
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

        if let SortCheck::OnValues(sort_gadget) = &self.sort_check {
            populate_sort_gadget_table(planned_ir, sort_gadget.id(), &input_hint);
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

        let sort_gadget = match &self.sort_check {
            SortCheck::OnValues(sort_gadget) => sort_gadget,
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
            let table = self.sort_check_table_verifier(output)?;
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
        Self {
            sort_check: SortCheck::OnValues(sort_gadget),
            compaction_gadget,
            keys,
        }
    }

    /// The sort check's table (paper PIOP 14, step 3): key `i` under
    /// [`sort_key_name`], the output's own column, or its `__rank` segment
    /// for a rank key; then the output activator.
    fn sort_check_table_prover(&self, output: &TrackedTable<B>) -> SnarkResult<TrackedTable<B>> {
        let activator = output
            .activator_tracked_poly()
            .expect("the sort output's activator is C_{µ,s}");
        let columns: Vec<(&FieldRef, &TrackedCol<B>)> = output
            .tracked_cols_iter()
            .filter(|(field, _)| !is_system_column(field.name()))
            .collect();
        let mut table = IndexMap::new();
        for (index, key) in self.keys.iter().enumerate() {
            let (field, column) = columns[key.index_in(
                columns
                    .iter()
                    .map(|(field, _)| (column_qualifier(None, field), field.name().as_str())),
            )?];
            let name = sort_key_name(index);
            let (field, poly) = if key.order == KeyOrder::Rank {
                let rank = column
                    .aux_segment(STRING_RANK_SUFFIX)
                    .ok_or_else(|| missing_segment(STRING_RANK_SUFFIX))?;
                (rank_field(&name), rank.data.clone())
            } else {
                (
                    Arc::new(Field::new(&name, field.data_type().clone(), true)),
                    single_segment(column.num_segments(), key, column.data_tracked_poly())?,
                )
            };
            table.insert(field, poly);
        }
        table.insert(ACTIVATOR_FIELD.clone(), activator);
        Ok(TrackedTable::new(
            Some(schema_of(table.keys())),
            table,
            output.log_size(),
        ))
    }

    fn sort_check_table_verifier(
        &self,
        output: &TrackedTableOracle<B>,
    ) -> SnarkResult<TrackedTableOracle<B>> {
        let activator = output
            .activator_tracked_poly()
            .expect("the sort output's activator is C_{µ,s}");
        let columns: Vec<(&FieldRef, &TrackedColOracle<B>)> = output
            .tracked_col_oracles_iter()
            .filter(|(field, _)| !is_system_column(field.name()))
            .collect();
        let mut table = IndexMap::new();
        for (index, key) in self.keys.iter().enumerate() {
            let (field, column) = columns[key.index_in(
                columns
                    .iter()
                    .map(|(field, _)| (column_qualifier(None, field), field.name().as_str())),
            )?];
            let name = sort_key_name(index);
            let (field, oracle) = if key.order == KeyOrder::Rank {
                let rank = column
                    .aux_segment(STRING_RANK_SUFFIX)
                    .ok_or_else(|| missing_segment(STRING_RANK_SUFFIX))?;
                (rank_field(&name), rank.data.clone())
            } else {
                (
                    Arc::new(Field::new(&name, field.data_type().clone(), true)),
                    single_segment(column.num_segments(), key, column.data_tracked_oracle())?,
                )
            };
            table.insert(field, oracle);
        }
        table.insert(ACTIVATOR_FIELD.clone(), activator);
        Ok(TrackedTableOracle::new(
            Some(schema_of(table.keys())),
            table,
            output.log_size(),
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

fn schema_of<'a>(fields: impl Iterator<Item = &'a FieldRef>) -> Schema {
    Schema::new(
        fields
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>(),
    )
}
