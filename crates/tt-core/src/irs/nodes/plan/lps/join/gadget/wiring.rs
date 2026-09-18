use std::sync::Arc;

use crate::irs::nodes::plan::lps::join::gadget::{
    GadgetNode, SRC_LEFT_COL_NAME, SRC_RIGHT_COL_NAME,
};
use crate::irs::{
    nodes::utils::{
        bool, match_pair_check, nodup, validate_tracked_oracle_table_row_domain,
        validate_tracked_table_row_domain,
    },
    payloads::PayloadStructure,
};
use arithmetic::{
    ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, ROW_ID_COL_NAME,
    col::{PolyBundle, TrackedCol},
    col_oracle::{OracleBundle, TrackedColOracle},
    table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use datafusion_common::Column;
use datafusion_expr::Expr;
use indexmap::IndexMap;

struct MatchPairTables<T> {
    input_left: T,
    input_right: T,
    output_left_keys: T,
    output_right_keys: T,
    output_activator: T,
}

impl<B: SnarkBackend> GadgetNode<B> {
    const QUALIFIER_METADATA_KEY: &'static str = "tt.qualifier";

    fn bool_table_from_output_prover(output: &TrackedTable<B>) -> TrackedTable<B> {
        let activator = output
            .activator_tracked_poly()
            .expect("Join output should carry an activator column");
        let field = Arc::new(Field::new("data", DataType::Boolean, false));
        let mut tracked_polys = IndexMap::new();
        tracked_polys.insert(field.clone(), activator);
        let schema = Some(Schema::new(vec![field.as_ref().clone()]));
        TrackedTable::new(schema, tracked_polys, output.log_size())
    }

    fn bool_table_from_output_verifier(output: &TrackedTableOracle<B>) -> TrackedTableOracle<B> {
        let activator = output
            .activator_tracked_poly()
            .expect("Join output should carry an activator column");
        let field = Arc::new(Field::new("data", DataType::Boolean, false));
        let mut tracked_oracles = IndexMap::new();
        tracked_oracles.insert(field.clone(), activator);
        let schema = Some(Schema::new(vec![field.as_ref().clone()]));
        TrackedTableOracle::new(schema, tracked_oracles, output.log_size())
    }

    fn nodup_table_from_output_prover(
        output: &TrackedTable<B>,
        left_src: &TrackedTable<B>,
        right_src: &TrackedTable<B>,
    ) -> ark_piop::errors::SnarkResult<TrackedTable<B>> {
        validate_tracked_table_row_domain(output, "join output")?;
        validate_tracked_table_row_domain(left_src, "join src-left")?;
        validate_tracked_table_row_domain(right_src, "join src-right")?;
        if left_src.log_size() != output.log_size() || right_src.log_size() != output.log_size() {
            return Err(super::join_wiring_error(
                "source-index tables and join output must share one row domain",
            ));
        }
        let activator = output
            .activator_tracked_poly()
            .ok_or_else(|| super::join_wiring_error("join output is missing its activator"))?;

        let left_indices = left_src.data_tracked_polys_indices();
        if left_indices.len() != 1 {
            return Err(super::join_wiring_error(
                "join src-left must have exactly one data column",
            ));
        }
        let right_indices = right_src.data_tracked_polys_indices();
        if right_indices.len() != 1 {
            return Err(super::join_wiring_error(
                "join src-right must have exactly one data column",
            ));
        }

        let left_cols = left_src.tracked_polys();
        let (_, left_poly) = left_cols
            .get_index(left_indices[0])
            .ok_or_else(|| super::join_wiring_error("join src-left data column is missing"))?;
        let right_cols = right_src.tracked_polys();
        let (_, right_poly) = right_cols
            .get_index(right_indices[0])
            .ok_or_else(|| super::join_wiring_error("join src-right data column is missing"))?;
        if !activator.same_tracker(left_poly) || !activator.same_tracker(right_poly) {
            return Err(super::join_wiring_error(
                "output activator and source indices belong to different proof trackers",
            ));
        }

        // Rebind both coordinates to fixed, distinct internal names. Source
        // table schemas are prover-controlled; using their field keys here
        // could let equal names collapse one coordinate in the IndexMap and
        // reduce pairwise NoDup to a one-sided check.
        let left_field = Arc::new(Field::new(SRC_LEFT_COL_NAME, DataType::Int64, false));
        let right_field = Arc::new(Field::new(SRC_RIGHT_COL_NAME, DataType::Int64, false));
        let mut tracked_polys = IndexMap::new();
        tracked_polys.insert(ACTIVATOR_FIELD.clone(), activator);
        tracked_polys.insert(left_field.clone(), left_poly.clone());
        tracked_polys.insert(right_field.clone(), right_poly.clone());

        let schema = Some(Schema::new(vec![
            ACTIVATOR_FIELD.as_ref().clone(),
            left_field.as_ref().clone(),
            right_field.as_ref().clone(),
        ]));
        Ok(TrackedTable::new(schema, tracked_polys, output.log_size()))
    }

    fn nodup_table_from_output_verifier(
        output: &TrackedTableOracle<B>,
        left_src: &TrackedTableOracle<B>,
        right_src: &TrackedTableOracle<B>,
    ) -> ark_piop::errors::SnarkResult<TrackedTableOracle<B>> {
        validate_tracked_oracle_table_row_domain(output, "join output")?;
        validate_tracked_oracle_table_row_domain(left_src, "join src-left")?;
        validate_tracked_oracle_table_row_domain(right_src, "join src-right")?;
        if left_src.log_size() != output.log_size() || right_src.log_size() != output.log_size() {
            return Err(super::join_wiring_error(
                "source-index oracle tables and join output must share one row domain",
            ));
        }
        let activator = output
            .activator_tracked_poly()
            .ok_or_else(|| super::join_wiring_error("join output is missing its activator"))?;

        let left_indices = left_src.data_tracked_oracles_indices();
        if left_indices.len() != 1 {
            return Err(super::join_wiring_error(
                "join src-left must have exactly one data column",
            ));
        }
        let right_indices = right_src.data_tracked_oracles_indices();
        if right_indices.len() != 1 {
            return Err(super::join_wiring_error(
                "join src-right must have exactly one data column",
            ));
        }

        let left_cols = left_src.tracked_oracles();
        let (_, left_oracle) = left_cols
            .get_index(left_indices[0])
            .ok_or_else(|| super::join_wiring_error("join src-left data column is missing"))?;
        let right_cols = right_src.tracked_oracles();
        let (_, right_oracle) = right_cols
            .get_index(right_indices[0])
            .ok_or_else(|| super::join_wiring_error("join src-right data column is missing"))?;
        if !activator.same_tracker(left_oracle) || !activator.same_tracker(right_oracle) {
            return Err(super::join_wiring_error(
                "output activator and source-index oracles belong to different proof trackers",
            ));
        }

        let left_field = Arc::new(Field::new(SRC_LEFT_COL_NAME, DataType::Int64, false));
        let right_field = Arc::new(Field::new(SRC_RIGHT_COL_NAME, DataType::Int64, false));
        let mut tracked_oracles = IndexMap::new();
        tracked_oracles.insert(ACTIVATOR_FIELD.clone(), activator);
        tracked_oracles.insert(left_field.clone(), left_oracle.clone());
        tracked_oracles.insert(right_field.clone(), right_oracle.clone());

        let schema = Some(Schema::new(vec![
            ACTIVATOR_FIELD.as_ref().clone(),
            left_field.as_ref().clone(),
            right_field.as_ref().clone(),
        ]));
        Ok(TrackedTableOracle::new(
            schema,
            tracked_oracles,
            output.log_size(),
        ))
    }

    pub(super) fn wire_prover_bool_payload(
        &self,
        output: &TrackedTable<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) {
        let Some(gadgets) = self.many_to_many_gadgets() else {
            return;
        };
        let bool_table = Self::bool_table_from_output_prover(output);
        let mut bool_payload = match virtualized_ir.payload_for_node(&gadgets.bool_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        bool_payload.insert(bool::TABLE_LABEL.to_string(), bool_table);
        virtualized_ir.set_payload_for_node(
            gadgets.bool_gadget.id(),
            Some(PayloadStructure::GadgetPayload(bool_payload)),
        );
    }

    pub(super) fn wire_prover_nodup_payload(
        &self,
        output: &TrackedTable<B>,
        left_src: &TrackedTable<B>,
        right_src: &TrackedTable<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(gadgets) = self.many_to_many_gadgets() else {
            return Ok(());
        };
        let nodup_table = Self::nodup_table_from_output_prover(output, left_src, right_src)?;
        let mut nodup_payload = match virtualized_ir.payload_for_node(&gadgets.nodup_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        // Planning supplies a materialization hint for NoDup, but the proved
        // relation must use the exact source-index polynomials that also feed
        // the two output-to-input provenance lookups. Never retain an
        // independently committed planning table here: it could be distinct
        // while the real output repeats a source pair.
        nodup_payload.insert(nodup::INPUT_LABEL.to_string(), nodup_table);
        virtualized_ir.set_payload_for_node(
            gadgets.nodup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(nodup_payload)),
        );
        Ok(())
    }
    fn ordered_join_columns(
        mut keys: Vec<Column>,
        include_row_id: bool,
        include_activator: bool,
    ) -> Vec<Column> {
        if include_row_id && !keys.iter().any(|col| col.name == ROW_ID_COL_NAME) {
            keys.push(Column::new_unqualified(ROW_ID_COL_NAME));
        }
        if include_activator && !keys.iter().any(|col| col.name == ACTIVATOR_COL_NAME) {
            keys.push(Column::new_unqualified(ACTIVATOR_COL_NAME));
        }
        keys
    }
    fn join_key_columns(join: &datafusion_expr::Join, use_left: bool) -> Vec<Column> {
        join.on
            .iter()
            .map(|(left, right)| {
                let expr = if use_left { left } else { right };
                match expr {
                    Expr::Column(col) => col.clone(),
                    _ => panic!("Join match-pair keys must be column expressions"),
                }
            })
            .collect()
    }

    fn field_matches_column(field: &Arc<Field>, col: &Column) -> bool {
        if field.name() != col.name.as_str() {
            return false;
        }
        let Some(relation) = col.relation.as_ref() else {
            return true;
        };
        field
            .metadata()
            .get(Self::QUALIFIER_METADATA_KEY)
            .map(|qualifier| qualifier == &relation.to_string())
            .unwrap_or(false)
    }

    fn rebind_tracked_col(col: &TrackedCol<B>, field: FieldRef) -> TrackedCol<B> {
        let mut row_segments = col.segments_iter();
        let (primary_suffix, primary, primary_active) = row_segments
            .next()
            .expect("tracked column must have a primary segment");
        debug_assert!(primary_suffix.is_none());
        let primary_bundle = PolyBundle::new(primary.clone(), primary_active.cloned());
        let row_aux = row_segments
            .map(|(suffix, poly, active)| {
                (
                    suffix
                        .expect("non-primary row segment must have a suffix")
                        .to_string(),
                    PolyBundle::new(poly.clone(), active.cloned()),
                )
            })
            .collect::<Vec<_>>();
        let side_aux = col
            .side_segments_iter()
            .map(|(suffix, bundle)| (suffix.to_string(), bundle.clone()))
            .collect::<Vec<_>>();
        if row_aux.is_empty() && side_aux.is_empty() {
            TrackedCol::new(primary.clone(), primary_active.cloned(), Some(field))
        } else {
            TrackedCol::new_multi_split(primary_bundle, row_aux, side_aux, Some(field))
        }
    }

    fn rebind_tracked_col_oracle(
        col: &TrackedColOracle<B>,
        field: FieldRef,
    ) -> TrackedColOracle<B> {
        let mut row_segments = col.segments_iter();
        let (primary_suffix, primary, primary_active) = row_segments
            .next()
            .expect("tracked column oracle must have a primary segment");
        debug_assert!(primary_suffix.is_none());
        let primary_bundle = OracleBundle::new(primary.clone(), primary_active.cloned());
        let row_aux = row_segments
            .map(|(suffix, oracle, active)| {
                (
                    suffix
                        .expect("non-primary row segment must have a suffix")
                        .to_string(),
                    OracleBundle::new(oracle.clone(), active.cloned()),
                )
            })
            .collect::<Vec<_>>();
        let side_aux = col
            .side_segments_iter()
            .map(|(suffix, bundle)| (suffix.to_string(), bundle.clone()))
            .collect::<Vec<_>>();
        if row_aux.is_empty() && side_aux.is_empty() {
            TrackedColOracle::new(primary.clone(), primary_active.cloned(), Some(field))
        } else {
            TrackedColOracle::new_multi_split(primary_bundle, row_aux, side_aux, Some(field))
        }
    }

    fn matching_col<'a, T>(
        cols: &'a IndexMap<FieldRef, T>,
        column: &Column,
        side: &str,
    ) -> ark_piop::errors::SnarkResult<(&'a FieldRef, &'a T)> {
        let matches = cols
            .iter()
            .filter(|(field, _)| Self::field_matches_column(field, column))
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [(field, value)] => Ok((*field, *value)),
            [] => Err(super::join_wiring_error(format!(
                "join {side} table is missing column {}",
                column.flat_name()
            ))),
            _ => Err(super::join_wiring_error(format!(
                "join {side} column {} is ambiguous ({} candidates)",
                column.flat_name(),
                matches.len()
            ))),
        }
    }

    fn select_tracked_columns(
        table: &TrackedTable<B>,
        columns: &[Column],
        side: &str,
    ) -> ark_piop::errors::SnarkResult<TrackedTable<B>> {
        let cols = table.tracked_cols();
        let mut selected = IndexMap::new();
        let mut key_index = 0usize;
        for col in columns {
            let (field, tracked_col) = Self::matching_col(&cols, col, side)?;
            let (selected_field, selected_col) = if arithmetic::is_system_column(field.name()) {
                (field.clone(), tracked_col.clone())
            } else {
                let alias = Arc::new(Field::new(
                    format!("__mp_key_{key_index}"),
                    field.data_type().clone(),
                    field.is_nullable(),
                ));
                key_index += 1;
                let rebound = Self::rebind_tracked_col(tracked_col, alias.clone());
                (alias, rebound)
            };
            selected.insert(selected_field, selected_col);
        }
        let mut result = TrackedTable::new_from_cols(None, selected, table.log_size());
        let fields = result
            .tracked_polys()
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        let metadata = table
            .schema_ref()
            .map(|schema| schema.metadata().clone())
            .unwrap_or_default();
        result.set_schema(Some(Schema::new_with_metadata(fields, metadata)));
        Ok(result)
    }

    fn select_tracked_oracles(
        table: &TrackedTableOracle<B>,
        columns: &[Column],
        side: &str,
    ) -> ark_piop::errors::SnarkResult<TrackedTableOracle<B>> {
        let cols = table.tracked_col_oracles();
        let mut selected = IndexMap::new();
        let mut key_index = 0usize;
        for col in columns {
            let (field, tracked_col) = Self::matching_col(&cols, col, side)?;
            let (selected_field, selected_col) = if arithmetic::is_system_column(field.name()) {
                (field.clone(), tracked_col.clone())
            } else {
                let alias = Arc::new(Field::new(
                    format!("__mp_key_{key_index}"),
                    field.data_type().clone(),
                    field.is_nullable(),
                ));
                key_index += 1;
                let rebound = Self::rebind_tracked_col_oracle(tracked_col, alias.clone());
                (alias, rebound)
            };
            selected.insert(selected_field, selected_col);
        }
        let result = TrackedTableOracle::new_from_col_oracles(None, selected, table.log_size());
        let fields = result
            .tracked_oracles()
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        let metadata = table
            .schema_ref()
            .map(|schema| schema.metadata().clone())
            .unwrap_or_default();
        Ok(TrackedTableOracle::new_from_col_oracles(
            Some(Schema::new_with_metadata(fields, metadata)),
            result.tracked_col_oracles(),
            table.log_size(),
        ))
    }

    /// Select output-side join keys in `join.on` order and give every key a
    /// position-derived name. Position aliases preserve repeated key columns
    /// in composite joins instead of letting an `IndexMap` silently collapse
    /// them. The grouped-column representation also retains every row-domain
    /// encoding segment (for example a string's hash and length).
    fn select_output_join_keys_prover(
        table: &TrackedTable<B>,
        columns: &[Column],
        side: &str,
    ) -> ark_piop::errors::SnarkResult<TrackedTable<B>> {
        let cols = table.tracked_cols();
        let mut selected = IndexMap::new();
        for (key_index, column) in columns.iter().enumerate() {
            let (field, tracked_col) =
                Self::matching_col(&cols, column, &format!("output-{side}"))?;
            let alias = Arc::new(Field::new(
                format!("__mp_output_key_{key_index}"),
                field.data_type().clone(),
                field.is_nullable(),
            ));
            selected.insert(alias.clone(), Self::rebind_tracked_col(tracked_col, alias));
        }
        let mut result = TrackedTable::new_from_cols(None, selected, table.log_size());
        let fields = result
            .tracked_polys()
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        result.set_schema(Some(Schema::new(fields)));
        Ok(result)
    }

    /// Verifier mirror of [`Self::select_output_join_keys_prover`].
    fn select_output_join_keys_verifier(
        table: &TrackedTableOracle<B>,
        columns: &[Column],
        side: &str,
    ) -> ark_piop::errors::SnarkResult<TrackedTableOracle<B>> {
        let cols = table.tracked_col_oracles();
        let mut selected = IndexMap::new();
        for (key_index, column) in columns.iter().enumerate() {
            let (field, tracked_col) =
                Self::matching_col(&cols, column, &format!("output-{side}"))?;
            let alias = Arc::new(Field::new(
                format!("__mp_output_key_{key_index}"),
                field.data_type().clone(),
                field.is_nullable(),
            ));
            selected.insert(
                alias.clone(),
                Self::rebind_tracked_col_oracle(tracked_col, alias),
            );
        }
        let result = TrackedTableOracle::new_from_col_oracles(None, selected, table.log_size());
        let fields = result
            .tracked_oracles()
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<_>>();
        Ok(TrackedTableOracle::new_from_col_oracles(
            Some(Schema::new(fields)),
            result.tracked_col_oracles(),
            table.log_size(),
        ))
    }

    fn output_activator_table(output: &TrackedTable<B>) -> TrackedTable<B> {
        let activator = output
            .tracked_polys()
            .iter()
            .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
            .map(|(field, poly)| (field.clone(), poly.clone()))
            .unwrap_or_else(|| panic!("Join output missing activator column"));
        let mut selected = IndexMap::new();
        selected.insert(activator.0.clone(), activator.1);
        let schema = Some(Schema::new(vec![activator.0.as_ref().clone()]));
        TrackedTable::new(schema, selected, output.log_size())
    }

    fn output_activator_table_oracle(output: &TrackedTableOracle<B>) -> TrackedTableOracle<B> {
        let activator = output
            .tracked_oracles()
            .iter()
            .find(|(field, _)| field.name() == ACTIVATOR_COL_NAME)
            .map(|(field, oracle)| (field.clone(), oracle.clone()))
            .unwrap_or_else(|| panic!("Join output missing activator column"));
        let mut selected = IndexMap::new();
        selected.insert(activator.0.clone(), activator.1);
        let schema = Some(Schema::new(vec![activator.0.as_ref().clone()]));
        TrackedTableOracle::new(schema, selected, output.log_size())
    }

    fn build_match_pair_tables_prover(
        join: &datafusion_expr::Join,
        output: &TrackedTable<B>,
        left_table: &TrackedTable<B>,
        right_table: &TrackedTable<B>,
    ) -> ark_piop::errors::SnarkResult<MatchPairTables<TrackedTable<B>>> {
        validate_tracked_table_row_domain(output, "join output")?;
        validate_tracked_table_row_domain(left_table, "join left input")?;
        validate_tracked_table_row_domain(right_table, "join right input")?;
        let include_left_row_id = left_table
            .tracked_polys()
            .keys()
            .any(|field| field.name() == ROW_ID_COL_NAME);
        let include_right_row_id = right_table
            .tracked_polys()
            .keys()
            .any(|field| field.name() == ROW_ID_COL_NAME);
        let include_left_activator = left_table
            .tracked_polys()
            .keys()
            .any(|field| field.name() == ACTIVATOR_COL_NAME);
        let include_right_activator = right_table
            .tracked_polys()
            .keys()
            .any(|field| field.name() == ACTIVATOR_COL_NAME);
        if !include_left_activator {
            return Err(super::join_wiring_error(format!(
                "join left table is missing column {ACTIVATOR_COL_NAME}"
            )));
        }
        if !include_right_activator {
            return Err(super::join_wiring_error(format!(
                "join right table is missing column {ACTIVATOR_COL_NAME}"
            )));
        }
        let left_join_keys = Self::join_key_columns(join, true);
        let right_join_keys = Self::join_key_columns(join, false);
        let left_keys =
            Self::ordered_join_columns(left_join_keys.clone(), include_left_row_id, true);
        let right_keys =
            Self::ordered_join_columns(right_join_keys.clone(), include_right_row_id, true);

        let left_selected = Self::select_tracked_columns(left_table, &left_keys, "left")?;
        let right_selected = Self::select_tracked_columns(right_table, &right_keys, "right")?;
        let output_left_base =
            super::output_lookup_base_from_output(output, left_table, right_table, true)?;
        let output_right_base =
            super::output_lookup_base_from_output(output, left_table, right_table, false)?;
        let output_left_keys =
            Self::select_output_join_keys_prover(&output_left_base, &left_join_keys, "left")?;
        let output_right_keys =
            Self::select_output_join_keys_prover(&output_right_base, &right_join_keys, "right")?;
        let out_selected = Self::output_activator_table(output);

        Ok(MatchPairTables {
            input_left: left_selected,
            input_right: right_selected,
            output_left_keys,
            output_right_keys,
            output_activator: out_selected,
        })
    }

    fn build_match_pair_tables_verifier(
        join: &datafusion_expr::Join,
        output: &TrackedTableOracle<B>,
        left_table: &TrackedTableOracle<B>,
        right_table: &TrackedTableOracle<B>,
    ) -> ark_piop::errors::SnarkResult<MatchPairTables<TrackedTableOracle<B>>> {
        validate_tracked_oracle_table_row_domain(output, "join output")?;
        validate_tracked_oracle_table_row_domain(left_table, "join left input")?;
        validate_tracked_oracle_table_row_domain(right_table, "join right input")?;
        let include_left_row_id = left_table
            .tracked_oracles()
            .keys()
            .any(|field| field.name() == ROW_ID_COL_NAME);
        let include_right_row_id = right_table
            .tracked_oracles()
            .keys()
            .any(|field| field.name() == ROW_ID_COL_NAME);
        let include_left_activator = left_table
            .tracked_oracles()
            .keys()
            .any(|field| field.name() == ACTIVATOR_COL_NAME);
        let include_right_activator = right_table
            .tracked_oracles()
            .keys()
            .any(|field| field.name() == ACTIVATOR_COL_NAME);
        if !include_left_activator {
            return Err(super::join_wiring_error(format!(
                "join left table is missing column {ACTIVATOR_COL_NAME}"
            )));
        }
        if !include_right_activator {
            return Err(super::join_wiring_error(format!(
                "join right table is missing column {ACTIVATOR_COL_NAME}"
            )));
        }
        let left_join_keys = Self::join_key_columns(join, true);
        let right_join_keys = Self::join_key_columns(join, false);
        let left_keys =
            Self::ordered_join_columns(left_join_keys.clone(), include_left_row_id, true);
        let right_keys =
            Self::ordered_join_columns(right_join_keys.clone(), include_right_row_id, true);

        let left_selected = Self::select_tracked_oracles(left_table, &left_keys, "left")?;
        let right_selected = Self::select_tracked_oracles(right_table, &right_keys, "right")?;
        let output_left_base =
            super::output_lookup_base_from_output_oracle(output, left_table, right_table, true)?;
        let output_right_base =
            super::output_lookup_base_from_output_oracle(output, left_table, right_table, false)?;
        let output_left_keys =
            Self::select_output_join_keys_verifier(&output_left_base, &left_join_keys, "left")?;
        let output_right_keys =
            Self::select_output_join_keys_verifier(&output_right_base, &right_join_keys, "right")?;
        let out_selected = Self::output_activator_table_oracle(output);

        Ok(MatchPairTables {
            input_left: left_selected,
            input_right: right_selected,
            output_left_keys,
            output_right_keys,
            output_activator: out_selected,
        })
    }

    pub(super) fn wire_prover_match_pair_payload(
        &self,
        output: &TrackedTable<B>,
        left: &TrackedTable<B>,
        right: &TrackedTable<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(gadgets) = self.many_to_many_gadgets() else {
            return Ok(());
        };
        let match_tables = Self::build_match_pair_tables_prover(&self.join, output, left, right)?;
        let mut match_payload =
            match virtualized_ir.payload_for_node(&gadgets.match_pair_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
        match_payload.insert(
            match_pair_check::LEFT_LABEL.to_string(),
            match_tables.input_left,
        );
        match_payload.insert(
            match_pair_check::RIGHT_LABEL.to_string(),
            match_tables.input_right,
        );
        match_payload.insert(
            match_pair_check::OUTPUT_LEFT_KEYS_LABEL.to_string(),
            match_tables.output_left_keys,
        );
        match_payload.insert(
            match_pair_check::OUTPUT_RIGHT_KEYS_LABEL.to_string(),
            match_tables.output_right_keys,
        );
        match_payload.insert(
            match_pair_check::OUT_LABEL.to_string(),
            match_tables.output_activator,
        );
        virtualized_ir.set_payload_for_node(
            gadgets.match_pair_gadget.id(),
            Some(PayloadStructure::GadgetPayload(match_payload)),
        );
        Ok(())
    }

    pub(super) fn wire_verifier_bool_payload(
        &self,
        output: &TrackedTableOracle<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) {
        let Some(gadgets) = self.many_to_many_gadgets() else {
            return;
        };
        let bool_table = Self::bool_table_from_output_verifier(output);
        let mut bool_payload = match virtualized_ir.payload_for_node(&gadgets.bool_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        bool_payload.insert(bool::TABLE_LABEL.to_string(), bool_table);
        virtualized_ir.set_payload_for_node(
            gadgets.bool_gadget.id(),
            Some(PayloadStructure::GadgetPayload(bool_payload)),
        );
    }

    pub(super) fn wire_verifier_nodup_payload(
        &self,
        output: &TrackedTableOracle<B>,
        left_src: &TrackedTableOracle<B>,
        right_src: &TrackedTableOracle<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(gadgets) = self.many_to_many_gadgets() else {
            return Ok(());
        };
        let nodup_table = Self::nodup_table_from_output_verifier(output, left_src, right_src)?;
        let mut nodup_payload = match virtualized_ir.payload_for_node(&gadgets.nodup_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        // Mirror the prover: bind NoDup to the actual lookup source oracles,
        // replacing the independent planning hint.
        nodup_payload.insert(nodup::INPUT_LABEL.to_string(), nodup_table);
        virtualized_ir.set_payload_for_node(
            gadgets.nodup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(nodup_payload)),
        );
        Ok(())
    }

    pub(super) fn wire_verifier_match_pair_payload(
        &self,
        output: &TrackedTableOracle<B>,
        left: &TrackedTableOracle<B>,
        right: &TrackedTableOracle<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(gadgets) = self.many_to_many_gadgets() else {
            return Ok(());
        };
        let match_tables = Self::build_match_pair_tables_verifier(&self.join, output, left, right)?;
        let mut match_payload =
            match virtualized_ir.payload_for_node(&gadgets.match_pair_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
        match_payload.insert(
            match_pair_check::LEFT_LABEL.to_string(),
            match_tables.input_left,
        );
        match_payload.insert(
            match_pair_check::RIGHT_LABEL.to_string(),
            match_tables.input_right,
        );
        match_payload.insert(
            match_pair_check::OUTPUT_LEFT_KEYS_LABEL.to_string(),
            match_tables.output_left_keys,
        );
        match_payload.insert(
            match_pair_check::OUTPUT_RIGHT_KEYS_LABEL.to_string(),
            match_tables.output_right_keys,
        );
        match_payload.insert(
            match_pair_check::OUT_LABEL.to_string(),
            match_tables.output_activator,
        );
        virtualized_ir.set_payload_for_node(
            gadgets.match_pair_gadget.id(),
            Some(PayloadStructure::GadgetPayload(match_payload)),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_piop::{
        DefaultSnarkBackend, SnarkBackend, arithmetic::mat_poly::mle::MLE,
        test_utils::prelude_with_vars,
    };
    use datafusion_common::TableReference;
    use std::collections::HashMap;

    type B = DefaultSnarkBackend;
    type F = <B as SnarkBackend>::F;

    fn commit_poly(
        prover: &mut ark_piop::prover::ArgProver<B>,
        values: [u64; 2],
    ) -> ark_piop::prover::structs::polynomial::TrackedPoly<B> {
        prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(
                1,
                values.into_iter().map(F::from).collect(),
            ))
            .expect("commit test polynomial")
    }

    fn qualified_field(name: &str, qualifier: &str) -> FieldRef {
        let mut metadata = HashMap::new();
        metadata.insert(
            GadgetNode::<B>::QUALIFIER_METADATA_KEY.to_string(),
            qualifier.to_string(),
        );
        Arc::new(Field::new(name, DataType::Utf8, false).with_metadata(metadata))
    }

    #[test]
    fn match_pair_input_selection_preserves_repeated_multisegment_keys() {
        let (mut prover, _) = prelude_with_vars::<B>(3).expect("SRS setup");
        let key_field = qualified_field("key", "left");
        let key = TrackedCol::new_multi_split(
            PolyBundle::new(commit_poly(&mut prover, [3, 5]), None),
            vec![(
                "__length".to_string(),
                PolyBundle::new(commit_poly(&mut prover, [1, 1]), None),
            )],
            vec![(
                "__chars".to_string(),
                PolyBundle::new(commit_poly(&mut prover, [97, 98]), None),
            )],
            Some(key_field.clone()),
        );
        let row_id = TrackedCol::new(
            commit_poly(&mut prover, [0, 1]),
            None,
            Some(arithmetic::ROW_ID_FIELD.clone()),
        );
        let activator = TrackedCol::new(
            commit_poly(&mut prover, [1, 1]),
            None,
            Some(arithmetic::ACTIVATOR_FIELD.clone()),
        );
        let mut cols = IndexMap::new();
        cols.insert(key_field, key);
        cols.insert(arithmetic::ROW_ID_FIELD.clone(), row_id);
        cols.insert(arithmetic::ACTIVATOR_FIELD.clone(), activator);
        let table = TrackedTable::new_from_cols(None, cols, 1);

        let repeated = Column::new(Some(TableReference::bare("left")), "key");
        let selected = GadgetNode::<B>::select_tracked_columns(
            &table,
            &[
                repeated.clone(),
                repeated,
                Column::new_unqualified(ROW_ID_COL_NAME),
                Column::new_unqualified(ACTIVATOR_COL_NAME),
            ],
            "left",
        )
        .expect("select repeated grouped keys");

        let selected_cols = selected.tracked_cols();
        for index in 0..2 {
            let expected_name = format!("__mp_key_{index}");
            let field = selected_cols
                .keys()
                .find(|field| field.name().as_str() == expected_name.as_str())
                .expect("positionally aliased repeated key");
            let col = selected_cols.get(field).expect("selected key column");
            assert_eq!(col.segments_iter().count(), 2);
            assert_eq!(col.side_segments_iter().count(), 1);
        }
        assert_eq!(selected.num_data_tracked_cols(), 4);
    }

    #[test]
    fn qualified_key_selection_never_falls_back_by_name() {
        let (mut prover, _) = prelude_with_vars::<B>(2).expect("SRS setup");
        let field = qualified_field("key", "left");
        let key = TrackedCol::new(commit_poly(&mut prover, [1, 2]), None, Some(field.clone()));
        let table = TrackedTable::new_from_cols(None, IndexMap::from([(field, key)]), 1);
        assert!(
            GadgetNode::<B>::select_tracked_columns(
                &table,
                &[Column::new(Some(TableReference::bare("wrong")), "key")],
                "left",
            )
            .is_err(),
            "a qualified key must not select a unique same-named column from another source"
        );
    }
}
