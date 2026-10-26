//! The sort check of an ORDER BY in the lexicographic string order: the
//! TruthTable++ String Sort Check (§7.2, PIOP 11,
//! [`string_sort`](crate::irs::nodes::utils::lex_sort::piop::string_sort))
//! over the ORDER BY's keys. The ORDER BY's compaction child proves the
//! output a permutation of the input.
//!
//! The input must index its rows as its table scan does, which the plans
//! this mode accepts guarantee (`ensure_supported`), and its character table
//! is its table scan's, which the data owner commits.
//!
//! Payload: the ORDER BY gadget's [`INPUT_LABEL`] and [`OUTPUT_LABEL`] tables
//! and the [`ACTIVE_ROWS_LABEL`] count `s`.

use arithmetic::{
    col::TrackedCol,
    col_oracle::TrackedColOracle,
    encoding::{STRING_CHARS_SUFFIX, STRING_INT_IND_SUFFIX, STRING_ORIG_IND_SUFFIX},
    is_system_column,
    table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_piop::{
    SnarkBackend,
    arithmetic::errors::DataTypeError,
    errors::{SnarkError, SnarkResult},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};
use datafusion::arrow::datatypes::{DataType, FieldRef};
use indexmap::IndexMap;

use super::{
    INPUT_LABEL, KeyOrder, OUTPUT_LABEL, SortKey, column_qualifier, single_segment,
    string_identity_prover, string_identity_verifier,
};
use crate::{
    irs::{
        nodes::{
            IsGadgetNode, IsNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
            utils::{
                contig_sort::{ACTIVE_ROWS_LABEL, active_rows_prover, active_rows_verifier},
                lex_sort::piop::{
                    character_projection::Characters,
                    integer_key_width,
                    string_sort::{self, Key},
                },
            },
        },
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub struct GadgetNode<B: SnarkBackend> {
    keys: Vec<SortKey>,
    _backend: std::marker::PhantomData<B>,
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(keys: Vec<SortKey>) -> Self {
        Self {
            keys,
            _backend: std::marker::PhantomData,
        }
    }
}

fn missing(what: &str, key: &SortKey) -> SnarkError {
    SnarkError::DataTypeError(DataTypeError::NotSupported(format!(
        "ORDER BY key {}: the sort's input has no {what}",
        key.column
    )))
}

fn value_width(key: &SortKey, data_type: &DataType) -> SnarkResult<usize> {
    integer_key_width(data_type).ok_or_else(|| {
        SnarkError::DataTypeError(DataTypeError::NotSupported(format!(
            "ORDER BY key {} of type {data_type} has no ordered encoding",
            key.column
        )))
    })
}

/// The character table of a string column, from its side segments.
fn characters<P: Clone>(
    key: &SortKey,
    side: impl Fn(&str) -> Option<(P, Option<P>)>,
) -> SnarkResult<Characters<P>> {
    let segment = |suffix: &str| side(suffix).ok_or_else(|| missing(suffix, key));
    let (chars, activator) = segment(STRING_CHARS_SUFFIX)?;
    Ok(Characters {
        orig_ind: segment(STRING_ORIG_IND_SUFFIX)?.0,
        int_ind: segment(STRING_INT_IND_SUFFIX)?.0,
        chars,
        activator: activator.ok_or_else(|| missing("character activator", key))?,
    })
}

impl<B: SnarkBackend> GadgetNode<B> {
    fn key_columns_prover(
        &self,
        input: &TrackedTable<B>,
        output: &TrackedTable<B>,
    ) -> SnarkResult<Vec<Key<TrackedPoly<B>>>> {
        let data_columns = |table: &TrackedTable<B>| {
            table
                .tracked_cols_iter()
                .filter(|(field, _)| !is_system_column(field.name()))
                .map(|(field, column)| (field.clone(), column.clone()))
                .collect::<Vec<_>>()
        };
        let (inputs, outputs) = (data_columns(input), data_columns(output));
        let position = |key: &SortKey, columns: &[(FieldRef, TrackedCol<B>)]| {
            key.index_in(
                columns
                    .iter()
                    .map(|(field, _)| (column_qualifier(None, field), field.name().as_str())),
            )
        };
        self.keys
            .iter()
            .map(|key| {
                let (field, column) = &outputs[position(key, &outputs)?];
                match key.order {
                    KeyOrder::Value => Ok(Key::Value {
                        data: single_segment(
                            column.num_segments(),
                            key,
                            column.data_tracked_poly(),
                        )?,
                        asc: key.asc,
                        width: value_width(key, field.data_type())?,
                    }),
                    KeyOrder::Characters => {
                        let (input_field, input_column) = &inputs[position(key, &inputs)?];
                        Ok(Key::String {
                            identity: string_identity_prover(column, field.data_type())?,
                            input_identity: string_identity_prover(
                                input_column,
                                input_field.data_type(),
                            )?,
                            chars: characters(key, |suffix| {
                                input_column
                                    .side_segment(suffix)
                                    .map(|side| (side.data.clone(), side.activator.clone()))
                            })?,
                            asc: key.asc,
                        })
                    }
                    KeyOrder::Rank => Err(rank_key(key)),
                }
            })
            .collect()
    }

    fn key_columns_verifier(
        &self,
        input: &TrackedTableOracle<B>,
        output: &TrackedTableOracle<B>,
    ) -> SnarkResult<Vec<Key<TrackedOracle<B>>>> {
        let data_columns = |table: &TrackedTableOracle<B>| {
            table
                .tracked_col_oracles_iter()
                .filter(|(field, _)| !is_system_column(field.name()))
                .map(|(field, column)| (field.clone(), column.clone()))
                .collect::<Vec<_>>()
        };
        let (inputs, outputs) = (data_columns(input), data_columns(output));
        let position = |key: &SortKey, columns: &[(FieldRef, TrackedColOracle<B>)]| {
            key.index_in(
                columns
                    .iter()
                    .map(|(field, _)| (column_qualifier(None, field), field.name().as_str())),
            )
        };
        self.keys
            .iter()
            .map(|key| {
                let (field, column) = &outputs[position(key, &outputs)?];
                match key.order {
                    KeyOrder::Value => Ok(Key::Value {
                        data: single_segment(
                            column.num_segments(),
                            key,
                            column.data_tracked_oracle(),
                        )?,
                        asc: key.asc,
                        width: value_width(key, field.data_type())?,
                    }),
                    KeyOrder::Characters => {
                        let (input_field, input_column) = &inputs[position(key, &inputs)?];
                        Ok(Key::String {
                            identity: string_identity_verifier(column, field.data_type())?,
                            input_identity: string_identity_verifier(
                                input_column,
                                input_field.data_type(),
                            )?,
                            chars: characters(key, |suffix| {
                                input_column
                                    .side_segment(suffix)
                                    .map(|side| (side.data.clone(), side.activator.clone()))
                            })?,
                            asc: key.asc,
                        })
                    }
                    KeyOrder::Rank => Err(rank_key(key)),
                }
            })
            .collect()
    }
}

fn rank_key(key: &SortKey) -> SnarkError {
    SnarkError::DataTypeError(DataTypeError::NotSupported(format!(
        "ORDER BY key {} is sorted on its rank, not its characters",
        key.column
    )))
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "StringSortCheck".to_string()
    }

    fn display(&self) -> String {
        crate::irs::nodes::display_with_inputs(&self.name(), &self.children())
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _prover: &mut ArgProver<B>,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _verifier: &mut ArgVerifier<B>,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

/// The payload's input, output and active-row count.
fn tables<T: Clone>(payload: &IndexMap<String, T>) -> (T, T, T) {
    let get = |label: &str| {
        payload
            .get(label)
            .cloned()
            .unwrap_or_else(|| panic!("StringSortCheck: missing {label}"))
    };
    (get(INPUT_LABEL), get(OUTPUT_LABEL), get(ACTIVE_ROWS_LABEL))
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("StringSortCheck: missing gadget payload");
        };
        let (input, output, count) = tables(payload);
        let s = active_rows_prover(&count)?;
        let output_active = output
            .activator_tracked_poly()
            .expect("the sort output's activator is C_{µ,s}");
        let input_active = input
            .activator_tracked_poly()
            .expect("the sort input has an activator");
        let keys = self.key_columns_prover(&input, &output)?;
        string_sort::prove(prover, &keys, &input_active, &output_active, s)
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: NodeId,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn verify(
        &self,
        verifier: &mut ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            panic!("StringSortCheck: missing gadget payload");
        };
        let (input, output, count) = tables(payload);
        let s = active_rows_verifier(&count)?;
        let output_active = output
            .activator_tracked_poly()
            .expect("the sort output's activator is C_{µ,s}");
        let input_active = input
            .activator_tracked_poly()
            .expect("the sort input has an activator");
        let keys = self.key_columns_verifier(&input, &output)?;
        string_sort::verify(verifier, &keys, &input_active, &output_active, s)
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}
