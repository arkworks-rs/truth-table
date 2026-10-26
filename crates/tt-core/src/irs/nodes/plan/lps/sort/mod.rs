use arithmetic::ACTIVATOR_COL_NAME;
use arithmetic::ROW_ID_COL_NAME;
use arithmetic::{
    ACTIVATOR_FIELD, is_system_column, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_ff::One;
use ark_piop::{
    SnarkBackend,
    arithmetic::errors::DataTypeError,
    errors::{SnarkError, SnarkResult},
    prover::structs::polynomial::TrackedPoly,
    verifier::{errors::VerifierError, structs::oracle::TrackedOracle},
};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion_common::Column;
use datafusion_expr::{Expr, LogicalPlan, col};
use either::Either;
use indexmap::IndexMap;
use std::sync::{Arc, Mutex};

use crate::irs::nodes::hints::HintDF;
use crate::{
    irs::{
        lineage::{base_column, is_string_type},
        nodes::{
            IsLpNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
            plan::lps::table_scan,
            utils::{commit_with_tracker, contig_sort, field_to_usize, track_next_committed},
        },
        payloads::PayloadStructure,
        string_order::{StringOrder, string_order},
        supported::sort_key_position,
        tree::Tree,
    },
    prover::irs::VirtualizedIr as ProverVirtualizedIr,
    verifier::irs::VirtualizedIr as VerifierVirtualizedIr,
};
pub mod gadget;
pub(crate) mod output;
mod rank;
use datafusion::logical_expr::Sort;
use gadget::{KeyOrder, SortKey, rank_super_label, sort_key_name, sorts_on_characters};

pub struct LpNode<B>
where
    B: SnarkBackend,
{
    sort: Sort,
    input: Arc<Node<B>>,
    keys: Vec<SortKey>,
    rank_keys: Vec<RankKey<B>>,
    /// The base columns of the keys sorted on their characters, which the
    /// table scans load the character columns of.
    character_columns: Vec<String>,
    gadget: Arc<Node<B>>,
    /// `s`, from `add_virtual_witness` for `initialize_gadgets`, which hands
    /// it to the sort check.
    active_rows: Mutex<Option<usize>>,
}

/// A string ORDER BY key sorted on its base column's rank.
struct RankKey<B: SnarkBackend> {
    /// The key's index among the ORDER BY keys.
    index: usize,
    table: String,
    column: String,
    /// The table scan of the base column on the key's lineage, in the
    /// input's subtree: the lookup's base side.
    scan: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for LpNode<B> {
    fn name(&self) -> String {
        "Order By".to_string()
    }

    fn display(&self) -> String {
        let exprs = self
            .sort
            .expr
            .iter()
            .map(|expr| expr.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let fetch = self
            .sort
            .fetch
            .map(|val| val.to_string())
            .unwrap_or_else(|| "none".to_string());
        format!(
            "Order By\nInput: {}, exprs: {}, fetch: {}",
            self.input.name(),
            exprs,
            fetch
        )
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.input.clone(), self.gadget.clone()]
    }

    fn required_rank_columns(&self) -> Vec<(String, String)> {
        self.rank_keys
            .iter()
            .map(|key| (key.table.clone(), key.column.clone()))
            .collect()
    }

    fn required_side_columns(&self) -> Vec<String> {
        self.character_columns.clone()
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for LpNode<B> {
    /// The output activator is the public `C_{µ,s}` for the input's active
    /// count `s` (paper PIOP 14, step 1), so it is never committed. `s` is,
    /// which puts it in the transcript before any challenge.
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::PlanPayload(input)) =
            virtualized_ir.payload_for_node(&self.input.id())
        else {
            return Ok(());
        };
        let Some(input_act) = input.activator_tracked_poly() else {
            return Ok(());
        };
        let Some(PayloadStructure::PlanPayload(output)) = virtualized_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let output = output.clone();
        let s = input_act
            .evaluations()
            .iter()
            .filter(|value| value.is_one())
            .count();
        let tracker_rc = input_act.tracker();
        commit_with_tracker(&tracker_rc, 0, vec![B::F::from(s as u64)])?;
        let activator = tracker_rc
            .borrow_mut()
            .get_or_build_contig_one_poly(output.log_size(), s)?;
        self.cache_active_rows(s);

        let mut polys = output.tracked_polys();
        polys.insert(ACTIVATOR_FIELD.clone(), activator);
        let updated = TrackedTable::new_with_side_cols(
            with_activator_field(output.schema_ref()),
            polys,
            output.log_size(),
            output.side_cols(),
        );
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated)));
        Ok(())
    }

    /// The gadget takes the input and output tables, without the row-id
    /// column, and the base side of each rank key's lookup.
    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => Some(strip_row_id_tracked_table(table)),
            _ => None,
        };
        let output_table =
            virtualized_ir
                .payload_for_node(&_id)
                .and_then(|payload| match payload {
                    PayloadStructure::PlanPayload(table) => Some(strip_row_id_tracked_table(table)),
                    _ => None,
                });

        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        for key in &self.rank_keys {
            gadget_payload.insert(
                rank_super_label(key.index),
                key.base_side_prover(virtualized_ir)?,
            );
        }
        if let Some(input) = input_table {
            gadget_payload.insert(gadget::INPUT_LABEL.to_string(), input);
        }
        if let Some(output) = output_table {
            if let Some(activator) = output.activator_tracked_poly() {
                let count = TrackedPoly::new(
                    Either::Right(B::F::from(self.cached_active_rows() as u64)),
                    0,
                    activator.tracker(),
                );
                gadget_payload.insert(
                    contig_sort::ACTIVE_ROWS_LABEL.to_string(),
                    TrackedTable::single_column_with_activator(
                        contig_sort::active_rows_field(),
                        count,
                        None,
                    ),
                );
            }
            gadget_payload.insert(gadget::OUTPUT_LABEL.to_string(), output);
        }

        if !gadget_payload.is_empty() {
            virtualized_ir.set_payload_for_node(
                self.gadget.id(),
                Some(PayloadStructure::GadgetPayload(gadget_payload)),
            );
        }
        Ok(())
    }

    /// The sort keys of the input rows under [`sort_key_name`]; a rank key
    /// as its string's rank in the base column.
    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let input_hint_df = match planned_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df.clone(),
            _ => return Ok(()),
        };
        // The String Sort Check plans no witness: it computes them at proving.
        if sorts_on_characters(&self.keys) {
            return Ok(());
        }

        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(input_hint_df.data_frame().clone())
                .expect("sort input row-id sort should succeed");

        let data_columns: Vec<(Option<String>, Column)> = input_df
            .schema()
            .iter()
            .filter(|(_, field)| !is_system_column(field.name()))
            .map(|(qualifier, field)| {
                (
                    gadget::column_qualifier(qualifier, field),
                    Column::new(qualifier.cloned(), field.name()),
                )
            })
            .collect();
        let mut exprs = Vec::with_capacity(self.keys.len() + 2);
        for (index, key) in self.keys.iter().enumerate() {
            let position = key.index_in(
                data_columns
                    .iter()
                    .map(|(qualifier, column)| (qualifier.clone(), column.name.as_str())),
            )?;
            let column = Expr::Column(data_columns[position].1.clone());
            let key_expr = match self.rank_keys.iter().find(|rank| rank.index == index) {
                Some(rank) => {
                    let Some(PayloadStructure::PlanPayload(scan)) =
                        planned_ir.payload_for_node(&rank.scan.id())
                    else {
                        return Err(missing_scan(rank));
                    };
                    let ranks = rank::base_ranks(scan.data_frame(), &rank.column)
                        .map_err(|e| SnarkError::Artifact(format!("rank planning: {e}")))?;
                    rank::rank_expr(column, ranks)
                }
                None => column,
            };
            exprs.push(key_expr.alias(sort_key_name(index)));
        }
        if input_df
            .schema()
            .fields()
            .iter()
            .any(|field| field.name() == ACTIVATOR_COL_NAME)
        {
            // Preserve activator semantics for top-k/filter pipelines.
            exprs.push(col(ACTIVATOR_COL_NAME));
        }
        // Keep row-id only for deterministic ordering; payloads strip it later.
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);

        let sort_exprs_df = input_df
            .select(exprs)
            .expect("sort expr projection should succeed");
        let sort_exprs_df = crate::irs::nodes::hints::sort_by_row_id_if_present(sort_exprs_df)
            .expect("sort expr output sort should succeed");
        let sort_exprs_hint = HintDF::new_virtual(sort_exprs_df);

        let mut gadget_payload = match planned_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(gadget::INPUT_SORT_EXPRS.to_string(), sort_exprs_hint);
        planned_ir.set_payload_for_node(
            self.gadget.id(),
            Some(PayloadStructure::GadgetPayload(gadget_payload)),
        );
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for LpNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::PlanPayload(input)) =
            virtualized_ir.payload_for_node(&self.input.id())
        else {
            return Ok(());
        };
        let Some(input_act) = input.activator_tracked_poly() else {
            return Ok(());
        };
        let Some(PayloadStructure::PlanPayload(output)) = virtualized_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let output = output.clone();
        let tracker_rc = input_act.tracker();
        let count = track_next_committed(&tracker_rc)?;
        let s = match count.as_constant() {
            Some(value) if count.log_size() == 0 => {
                field_to_usize(value, "the sort output's active-row count")?
            }
            _ => {
                return Err(SnarkError::VerifierError(
                    VerifierError::VerifierCheckFailed(
                        "the sort output's active-row count is not a committed scalar".to_string(),
                    ),
                ));
            }
        };
        let activator = tracker_rc
            .borrow_mut()
            .get_or_build_contig_one_poly(output.log_size(), s)?;
        self.cache_active_rows(s);

        let mut oracles = output.tracked_oracles();
        oracles.insert(ACTIVATOR_FIELD.clone(), activator);
        let updated = TrackedTableOracle::new_with_side_cols(
            with_activator_field(output.schema_ref()),
            oracles,
            output.log_size(),
            output.side_cols(),
        );
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated)));
        Ok(())
    }
    fn initialize_gadgets(
        &self,
        id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let input_table = match virtualized_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(table)) => Some(strip_row_id_tracked_oracle(table)),
            _ => None,
        };
        let output_table = virtualized_ir
            .payload_for_node(&id)
            .and_then(|payload| match payload {
                PayloadStructure::PlanPayload(table) => Some(strip_row_id_tracked_oracle(table)),
                _ => None,
            });

        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        for key in &self.rank_keys {
            gadget_payload.insert(
                rank_super_label(key.index),
                key.base_side_verifier(virtualized_ir)?,
            );
        }
        if let Some(input) = input_table {
            gadget_payload.insert(gadget::INPUT_LABEL.to_string(), input);
        }
        if let Some(output) = output_table {
            if let Some(activator) = output.activator_tracked_poly() {
                let count = TrackedOracle::new(
                    Either::Right(B::F::from(self.cached_active_rows() as u64)),
                    activator.tracker(),
                    0,
                );
                gadget_payload.insert(
                    contig_sort::ACTIVE_ROWS_LABEL.to_string(),
                    TrackedTableOracle::single_column_with_activator(
                        contig_sort::active_rows_field(),
                        count,
                        None,
                    ),
                );
            }
            gadget_payload.insert(gadget::OUTPUT_LABEL.to_string(), output);
        }

        if !gadget_payload.is_empty() {
            virtualized_ir.set_payload_for_node(
                self.gadget.id(),
                Some(PayloadStructure::GadgetPayload(gadget_payload)),
            );
        }
        Ok(())
    }
    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let input_hint_df = match planned_ir.payload_for_node(&self.input.id()) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df.clone(),
            _ => return Ok(()),
        };
        if sorts_on_characters(&self.keys) {
            return Ok(());
        }

        let sort_exprs_hint = self.sort_keys_hint_verifier(&input_hint_df)?;

        let mut gadget_payload = match planned_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(gadget::INPUT_SORT_EXPRS.to_string(), sort_exprs_hint);
        planned_ir.set_payload_for_node(
            self.gadget.id(),
            Some(PayloadStructure::GadgetPayload(gadget_payload)),
        );
        Ok(())
    }
}

fn strip_row_id_tracked_table<B: SnarkBackend>(table: &TrackedTable<B>) -> TrackedTable<B> {
    let Some(schema) = table.schema_ref() else {
        return table.clone();
    };
    if !schema
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME)
    {
        return table.clone();
    }

    // Row-id is only used for deterministic ordering, so omit it from payload
    // tables. The side columns stay: the String Sort Check reads the input's.
    let mut cols = IndexMap::new();
    for (field, poly) in table.tracked_polys_iter() {
        if field.name() != ROW_ID_COL_NAME {
            cols.insert(field.clone(), poly.clone());
        }
    }
    let fields: Vec<Field> = cols.keys().map(|field| field.as_ref().clone()).collect();
    let schema = Some(Schema::new_with_metadata(fields, schema.metadata().clone()));
    TrackedTable::new_with_side_cols(schema, cols, table.log_size(), table.side_cols())
}

fn strip_row_id_tracked_oracle<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
) -> TrackedTableOracle<B> {
    let Some(schema) = table.schema_ref() else {
        return table.clone();
    };
    if !schema
        .fields()
        .iter()
        .any(|field| field.name() == ROW_ID_COL_NAME)
    {
        return table.clone();
    }

    // Row-id is only used for deterministic ordering, so omit it from payload tables.
    let mut cols = IndexMap::new();
    for (field, oracle) in table.tracked_oracles_iter() {
        if field.name() != ROW_ID_COL_NAME {
            cols.insert(field.clone(), oracle.clone());
        }
    }
    let fields: Vec<Field> = cols.keys().map(|field| field.as_ref().clone()).collect();
    let schema = Some(Schema::new_with_metadata(fields, schema.metadata().clone()));
    TrackedTableOracle::new_with_side_cols(schema, cols, table.log_size(), table.side_cols())
}

impl<B: SnarkBackend> IsPlanNode<B> for LpNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        Some(self.gadget.as_ref().clone())
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsProverPlanNode<B> for LpNode<B> {
    fn output(&self) -> HintDF {
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsProverPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Sort input cannot be a gadget node"),
        };

        let output_df = output::sort_df(input_hint_df.data_frame(), &self.sort);
        hint_with_virtual_activator(output_df)
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for LpNode<B> {
    fn output(&self) -> HintDF {
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Sort input cannot be a gadget node"),
        };

        // A projection of the schema-only input, not a fresh schema: the
        // qualifiers keep same-named columns (a self-join's) apart.
        let input_df = input_hint_df.data_frame();
        let output_columns = input_df
            .schema()
            .iter()
            .filter(|(_, field)| field.name() != ROW_ID_COL_NAME)
            .map(|(qualifier, field)| Expr::Column(Column::new(qualifier.cloned(), field.name())))
            .collect::<Vec<_>>();
        let output_df = input_df
            .clone()
            .select(output_columns)
            .expect("the sort output's schema projection should succeed");
        hint_with_virtual_activator(output_df)
    }
}

/// The output's columns, all committed except the activator, which
/// `add_virtual_witness` installs, and `__row_id__`, which only orders hints.
fn hint_with_virtual_activator(output_df: datafusion::prelude::DataFrame) -> HintDF {
    let should_materialize = output_df
        .schema()
        .fields()
        .iter()
        .map(|field| {
            let name = field.name();
            (
                field.clone(),
                name != ACTIVATOR_COL_NAME && name != ROW_ID_COL_NAME,
            )
        })
        .collect();
    HintDF::new(output_df, should_materialize)
}

impl<B: SnarkBackend> LpNode<B> {
    fn cache_active_rows(&self, s: usize) {
        *self.active_rows.lock().expect("Sort active-row lock") = Some(s);
    }

    fn cached_active_rows(&self) -> usize {
        self.active_rows
            .lock()
            .expect("Sort active-row lock")
            .expect("the Sort output's active rows are set in add_virtual_witness")
    }
}

fn with_activator_field(schema: Option<&Schema>) -> Option<Schema> {
    schema.map(|schema| {
        let mut fields: Vec<_> = schema.fields().iter().cloned().collect();
        fields.push(ACTIVATOR_FIELD.as_ref().clone().into());
        Schema::new_with_metadata(fields, schema.metadata().clone())
    })
}

impl<B: SnarkBackend> IsLpNode<B> for LpNode<B> {
    fn from_lp(plan: LogicalPlan, _self_ref: std::sync::Weak<Node<B>>) -> Self
    where
        Self: Sized,
    {
        let sort = match plan {
            LogicalPlan::Sort(sort) => sort,
            _ => panic!("Expected LogicalPlan::Sort"),
        };

        let input = Tree::<B>::from_logical_plan(&sort.input).root().clone();
        let input_schema = sort.input.schema();
        let lexicographic = string_order() == StringOrder::Lexicographic;

        let mut keys = Vec::with_capacity(sort.expr.len());
        let mut rank_keys = Vec::new();
        let mut character_columns = Vec::new();
        for (index, expr) in sort.expr.iter().enumerate() {
            let position = sort_key_position(&sort, index).unwrap_or_else(|e| panic!("{e}"));
            let field = input_schema.field(position);
            let order = match (is_string_type(field.data_type()), lexicographic) {
                (false, _) => KeyOrder::Value,
                (true, false) => KeyOrder::Rank,
                (true, true) => KeyOrder::Characters,
            };
            let base = || {
                base_column(&sort.input, position)
                    .expect("sort_key_position resolved the key's lineage")
            };
            match order {
                KeyOrder::Value => {}
                KeyOrder::Characters => character_columns.push(base().column),
                KeyOrder::Rank => {
                    let base = base();
                    let scan = find_scan(&input, base.scan).unwrap_or_else(|| {
                        panic!(
                            "ORDER BY {}: no scan of {} on its lineage in the sort's input",
                            expr.expr, base.table
                        )
                    });
                    rank_keys.push(RankKey {
                        index,
                        table: base.table,
                        column: base.column,
                        scan,
                    });
                }
            }
            let (qualifier, _) = input_schema.qualified_field(position);
            keys.push(SortKey {
                column: Column::new(qualifier.cloned(), field.name()),
                asc: expr.asc,
                order,
            });
        }

        let gadget = Arc::new(Node::<B>::Gadget(Arc::new(gadget::GadgetNode::new(
            keys.clone(),
        ))));

        Self {
            sort,
            input,
            keys,
            rank_keys,
            character_columns,
            gadget,
            active_rows: Mutex::new(None),
        }
    }

    fn lp(&self) -> LogicalPlan {
        LogicalPlan::Sort(self.sort.clone())
    }
}

/// The table scan in `root`'s subtree whose plan is `scan`. Equal scans
/// (a self-join's) are interchangeable: they read the same committed table.
fn find_scan<B: SnarkBackend>(root: &Arc<Node<B>>, scan: &LogicalPlan) -> Option<Arc<Node<B>>> {
    if let Some(node) = table_scan::LpNode::of(root)
        && &<table_scan::LpNode as IsLpNode<B>>::lp(node) == scan
    {
        return Some(root.clone());
    }
    root.children()
        .iter()
        .find_map(|child| find_scan(child, scan))
}

fn missing_scan<B: SnarkBackend>(key: &RankKey<B>) -> SnarkError {
    SnarkError::DataTypeError(DataTypeError::NotSupported(format!(
        "the scan of the base column {} of ORDER BY key {} has no table",
        key.column, key.index
    )))
}

impl<B: SnarkBackend> RankKey<B> {
    /// The scan's hash slots, `__length` and rank of the base column, under
    /// the scan's activator: the lookup's base side.
    fn base_side_prover(
        &self,
        virtualized_ir: &ProverVirtualizedIr<B>,
    ) -> SnarkResult<TrackedTable<B>> {
        let (rank_id, num_vars) = self.cached_rank()?;
        let Some(PayloadStructure::PlanPayload(scan)) =
            virtualized_ir.payload_for_node(&self.scan.id())
        else {
            return Err(missing_scan(self));
        };
        let (field, column) = scan
            .tracked_cols_iter()
            .find(|(field, _)| field.name() == &self.column)
            .ok_or_else(|| missing_scan(self))?;
        let mut columns = gadget::string_identity_prover(column, field.data_type())?;
        let tracker = columns[0].tracker();
        columns.push(TrackedPoly::new(Either::Left(rank_id), num_vars, tracker));
        Ok(gadget::lookup_table_prover(
            columns,
            scan.activator_tracked_poly(),
            scan.log_size(),
        ))
    }

    fn base_side_verifier(
        &self,
        virtualized_ir: &VerifierVirtualizedIr<B>,
    ) -> SnarkResult<TrackedTableOracle<B>> {
        let (rank_id, num_vars) = self.cached_rank()?;
        let Some(PayloadStructure::PlanPayload(scan)) =
            virtualized_ir.payload_for_node(&self.scan.id())
        else {
            return Err(missing_scan(self));
        };
        let (field, column) = scan
            .tracked_col_oracles_iter()
            .find(|(field, _)| field.name() == &self.column)
            .ok_or_else(|| missing_scan(self))?;
        let mut columns = gadget::string_identity_verifier(column, field.data_type())?;
        let tracker = columns[0].tracker();
        columns.push(TrackedOracle::new(Either::Left(rank_id), tracker, num_vars));
        Ok(gadget::lookup_table_verifier(
            columns,
            scan.activator_tracked_poly(),
            scan.log_size(),
        ))
    }

    /// The rank segment the scan took out of its payload.
    fn cached_rank(&self) -> SnarkResult<(ark_piop::types::TrackerID, usize)> {
        table_scan::LpNode::of(&self.scan)
            .and_then(|scan| scan.rank_poly(&self.column))
            .ok_or_else(|| {
                SnarkError::DataTypeError(DataTypeError::NotSupported(format!(
                    "the table scan carries no rank of {}",
                    self.column
                )))
            })
    }
}

impl<B: SnarkBackend> LpNode<B> {
    /// The verifier's [`gadget::INPUT_SORT_EXPRS`] hint: the prover's key
    /// columns, rank keys as UInt32, then the input's system columns.
    fn sort_keys_hint_verifier(&self, input_hint_df: &HintDF) -> SnarkResult<HintDF> {
        let schema = input_hint_df.data_frame().schema();
        let data_fields: Vec<(Option<String>, &Field)> = schema
            .iter()
            .filter(|(_, field)| !is_system_column(field.name()))
            .map(|(qualifier, field)| (gadget::column_qualifier(qualifier, field), field.as_ref()))
            .collect();
        let mut fields = Vec::with_capacity(self.keys.len() + 2);
        for (index, key) in self.keys.iter().enumerate() {
            let (_, field) = data_fields[key.index_in(
                data_fields
                    .iter()
                    .map(|(qualifier, field)| (qualifier.clone(), field.name().as_str())),
            )?];
            let data_type = if key.order == KeyOrder::Rank {
                DataType::UInt32
            } else {
                field.data_type().clone()
            };
            fields.push(Field::new(sort_key_name(index), data_type, true));
        }
        fields.extend(
            schema
                .fields()
                .iter()
                .filter(|field| {
                    field.name() == ACTIVATOR_COL_NAME || field.name() == ROW_ID_COL_NAME
                })
                .map(|field| field.as_ref().clone()),
        );
        Ok(HintDF::new_virtual(
            crate::irs::nodes::hints::schema_only_df(fields),
        ))
    }
}
