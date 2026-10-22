use crate::irs::nodes::hints::{QUALIFIER_METADATA_KEY, table_name_from_qualifier};

use crate::irs::nodes::plan::lps::join::gadget::GadgetNode;
use crate::irs::{
    nodes::utils::{match_pair_check, nodup},
    payloads::PayloadStructure,
};
use arithmetic::{
    ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, ROW_ID_COL_NAME, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{Field, FieldRef, Schema};
use datafusion_common::{Column, TableReference};
use datafusion_expr::Expr;
use indexmap::IndexMap;

impl<B: SnarkBackend> GadgetNode<B> {
    fn nodup_table_from_output_prover(
        output: &TrackedTable<B>,
        left_src: &TrackedTable<B>,
        right_src: &TrackedTable<B>,
    ) -> TrackedTable<B> {
        let activator = output
            .activator_tracked_poly()
            .expect("Join output should carry an activator column");

        let left_indices = left_src.data_tracked_polys_indices();
        assert_eq!(
            left_indices.len(),
            1,
            "Join src-left should have exactly one data column"
        );
        let right_indices = right_src.data_tracked_polys_indices();
        assert_eq!(
            right_indices.len(),
            1,
            "Join src-right should have exactly one data column"
        );

        let left_cols = left_src.tracked_polys();
        let (left_field, left_poly) = left_cols
            .get_index(left_indices[0])
            .expect("Join src-left data column missing");
        let right_cols = right_src.tracked_polys();
        let (right_field, right_poly) = right_cols
            .get_index(right_indices[0])
            .expect("Join src-right data column missing");

        let mut tracked_polys = IndexMap::new();
        tracked_polys.insert(ACTIVATOR_FIELD.clone(), activator);
        tracked_polys.insert(left_field.clone(), left_poly.clone());
        tracked_polys.insert(right_field.clone(), right_poly.clone());

        let schema = Some(Schema::new(vec![
            ACTIVATOR_FIELD.as_ref().clone(),
            left_field.as_ref().clone(),
            right_field.as_ref().clone(),
        ]));
        TrackedTable::new(schema, tracked_polys, output.log_size())
    }

    fn nodup_table_from_output_verifier(
        output: &TrackedTableOracle<B>,
        left_src: &TrackedTableOracle<B>,
        right_src: &TrackedTableOracle<B>,
    ) -> TrackedTableOracle<B> {
        let activator = output
            .activator_tracked_poly()
            .expect("Join output should carry an activator column");

        let left_indices = left_src.data_tracked_oracles_indices();
        assert_eq!(
            left_indices.len(),
            1,
            "Join src-left should have exactly one data column"
        );
        let right_indices = right_src.data_tracked_oracles_indices();
        assert_eq!(
            right_indices.len(),
            1,
            "Join src-right should have exactly one data column"
        );

        let left_cols = left_src.tracked_oracles();
        let (left_field, left_oracle) = left_cols
            .get_index(left_indices[0])
            .expect("Join src-left data column missing");
        let right_cols = right_src.tracked_oracles();
        let (right_field, right_oracle) = right_cols
            .get_index(right_indices[0])
            .expect("Join src-right data column missing");

        let mut tracked_oracles = IndexMap::new();
        tracked_oracles.insert(ACTIVATOR_FIELD.clone(), activator);
        tracked_oracles.insert(left_field.clone(), left_oracle.clone());
        tracked_oracles.insert(right_field.clone(), right_oracle.clone());

        let schema = Some(Schema::new(vec![
            ACTIVATOR_FIELD.as_ref().clone(),
            left_field.as_ref().clone(),
            right_field.as_ref().clone(),
        ]));
        TrackedTableOracle::new(schema, tracked_oracles, output.log_size())
    }

    pub(super) fn wire_prover_nodup_payload(
        &self,
        output: &TrackedTable<B>,
        left_src: &TrackedTable<B>,
        right_src: &TrackedTable<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) {
        let Some(gadgets) = self.many_to_many_gadgets() else {
            return;
        };
        let nodup_table = Self::nodup_table_from_output_prover(output, left_src, right_src);
        let mut nodup_payload = match virtualized_ir.payload_for_node(&gadgets.nodup_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        // The source pairs the provenance lookups use (paper PIOP 18, step 5),
        // replacing the planning hint, which only seeds the sort hints.
        nodup_payload.insert(nodup::INPUT_LABEL.to_string(), nodup_table);
        virtualized_ir.set_payload_for_node(
            gadgets.nodup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(nodup_payload)),
        );
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

    fn select_tracked_columns(
        table: &TrackedTable<B>,
        columns: &[Column],
        side: &str,
    ) -> TrackedTable<B> {
        let cols = table.tracked_polys();
        let mut selected = IndexMap::new();
        for col in columns {
            let fields = key_fields(cols.keys(), col)
                .unwrap_or_else(|msg| panic!("Join {side} table: {msg}"));
            for field in fields {
                let poly = cols[&field].clone();
                selected.insert(field, poly);
            }
        }
        let schema = table.schema_ref().map(|schema| {
            let fields: Vec<Field> = selected
                .keys()
                .map(|field| field.as_ref().clone())
                .collect();
            Schema::new_with_metadata(fields, schema.metadata().clone())
        });
        let schema = schema.or_else(|| {
            let fields: Vec<Field> = selected
                .keys()
                .map(|field| field.as_ref().clone())
                .collect();
            Some(Schema::new(fields))
        });
        TrackedTable::new(schema, selected, table.log_size())
    }

    fn select_tracked_oracles(
        table: &TrackedTableOracle<B>,
        columns: &[Column],
        side: &str,
    ) -> TrackedTableOracle<B> {
        let cols = table.tracked_oracles();
        let mut selected = IndexMap::new();
        for col in columns {
            let fields = key_fields(cols.keys(), col)
                .unwrap_or_else(|msg| panic!("Join {side} table: {msg}"));
            for field in fields {
                let oracle = cols[&field].clone();
                selected.insert(field, oracle);
            }
        }
        let schema = table.schema_ref().map(|schema| {
            let fields: Vec<Field> = selected
                .keys()
                .map(|field| field.as_ref().clone())
                .collect();
            Schema::new_with_metadata(fields, schema.metadata().clone())
        });
        let schema = schema.or_else(|| {
            let fields: Vec<Field> = selected
                .keys()
                .map(|field| field.as_ref().clone())
                .collect();
            Some(Schema::new(fields))
        });
        TrackedTableOracle::new(schema, selected, table.log_size())
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
    ) -> Option<(TrackedTable<B>, TrackedTable<B>, TrackedTable<B>)> {
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
            panic!("Join left table missing column {ACTIVATOR_COL_NAME}");
        }
        if !include_right_activator {
            panic!("Join right table missing column {ACTIVATOR_COL_NAME}");
        }
        let left_keys = Self::ordered_join_columns(
            Self::join_key_columns(join, true),
            include_left_row_id,
            true,
        );
        let right_keys = Self::ordered_join_columns(
            Self::join_key_columns(join, false),
            include_right_row_id,
            true,
        );

        let left_selected = Self::select_tracked_columns(left_table, &left_keys, "left");
        let right_selected = Self::select_tracked_columns(right_table, &right_keys, "right");
        let out_selected = Self::output_activator_table(output);

        Some((left_selected, right_selected, out_selected))
    }

    fn build_match_pair_tables_verifier(
        join: &datafusion_expr::Join,
        output: &TrackedTableOracle<B>,
        left_table: &TrackedTableOracle<B>,
        right_table: &TrackedTableOracle<B>,
    ) -> Option<(
        TrackedTableOracle<B>,
        TrackedTableOracle<B>,
        TrackedTableOracle<B>,
    )> {
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
            panic!("Join left table missing column {ACTIVATOR_COL_NAME}");
        }
        if !include_right_activator {
            panic!("Join right table missing column {ACTIVATOR_COL_NAME}");
        }
        let left_keys = Self::ordered_join_columns(
            Self::join_key_columns(join, true),
            include_left_row_id,
            true,
        );
        let right_keys = Self::ordered_join_columns(
            Self::join_key_columns(join, false),
            include_right_row_id,
            true,
        );

        let left_selected = Self::select_tracked_oracles(left_table, &left_keys, "left");
        let right_selected = Self::select_tracked_oracles(right_table, &right_keys, "right");
        let out_selected = Self::output_activator_table_oracle(output);

        Some((left_selected, right_selected, out_selected))
    }

    pub(super) fn wire_prover_match_pair_payload(
        &self,
        output: &TrackedTable<B>,
        left: &TrackedTable<B>,
        right: &TrackedTable<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) {
        let Some(gadgets) = self.many_to_many_gadgets() else {
            return;
        };
        let match_tables = Self::build_match_pair_tables_prover(&self.join, output, left, right)
            .unwrap_or_else(|| {
                panic!("Match-pair tables require left/right/output for Join gadget");
            });
        let mut match_payload =
            match virtualized_ir.payload_for_node(&gadgets.match_pair_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
        match_payload.insert(match_pair_check::LEFT_LABEL.to_string(), match_tables.0);
        match_payload.insert(match_pair_check::RIGHT_LABEL.to_string(), match_tables.1);
        match_payload.insert(match_pair_check::OUT_LABEL.to_string(), match_tables.2);
        virtualized_ir.set_payload_for_node(
            gadgets.match_pair_gadget.id(),
            Some(PayloadStructure::GadgetPayload(match_payload)),
        );
    }

    pub(super) fn wire_verifier_nodup_payload(
        &self,
        output: &TrackedTableOracle<B>,
        left_src: &TrackedTableOracle<B>,
        right_src: &TrackedTableOracle<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) {
        let Some(gadgets) = self.many_to_many_gadgets() else {
            return;
        };
        let nodup_table = Self::nodup_table_from_output_verifier(output, left_src, right_src);
        let mut nodup_payload = match virtualized_ir.payload_for_node(&gadgets.nodup_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        // The source pairs the provenance lookups use (paper PIOP 18, step 5),
        // replacing the planning hint, which only seeds the sort hints.
        nodup_payload.insert(nodup::INPUT_LABEL.to_string(), nodup_table);
        virtualized_ir.set_payload_for_node(
            gadgets.nodup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(nodup_payload)),
        );
    }

    pub(super) fn wire_verifier_match_pair_payload(
        &self,
        output: &TrackedTableOracle<B>,
        left: &TrackedTableOracle<B>,
        right: &TrackedTableOracle<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) {
        let Some(gadgets) = self.many_to_many_gadgets() else {
            return;
        };
        let match_tables = Self::build_match_pair_tables_verifier(&self.join, output, left, right)
            .unwrap_or_else(|| {
                panic!("Match-pair tables require left/right/output for Join gadget");
            });
        let mut match_payload =
            match virtualized_ir.payload_for_node(&gadgets.match_pair_gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };
        match_payload.insert(match_pair_check::LEFT_LABEL.to_string(), match_tables.0);
        match_payload.insert(match_pair_check::RIGHT_LABEL.to_string(), match_tables.1);
        match_payload.insert(match_pair_check::OUT_LABEL.to_string(), match_tables.2);
        virtualized_ir.set_payload_for_node(
            gadgets.match_pair_gadget.id(),
            Some(PayloadStructure::GadgetPayload(match_payload)),
        );
    }
}

/// The field among `fields` that the join key `col` names, followed by its
/// value segments: a string's further hash slots and `__length`, which the
/// key union encodes too (fingerprint limbs are left out: the union has
/// none). The key is resolved by qualifier, and so are its segments: a
/// self-join puts same-named columns of two aliases on one side. A bare name
/// decides only when no field matches by qualifier and the name is unique.
pub(super) fn key_fields<'a>(
    fields: impl Iterator<Item = &'a FieldRef> + Clone,
    col: &Column,
) -> Result<Vec<FieldRef>, String> {
    let exact = fields
        .clone()
        .filter(|field| field_matches_column(field, col))
        .collect::<Vec<_>>();
    let candidates = if exact.is_empty() {
        fields
            .clone()
            .filter(|field| field.name() == col.name.as_str())
            .collect()
    } else {
        exact
    };
    let key = match candidates.as_slice() {
        [key] => *key,
        [] => return Err(format!("missing column {}", col.flat_name())),
        _ => {
            return Err(format!(
                "ambiguous column {} ({} candidates)",
                col.flat_name(),
                candidates.len()
            ));
        }
    };
    let qualifier = key.metadata().get(QUALIFIER_METADATA_KEY);
    let mut out = vec![key.clone()];
    out.extend(
        fields
            .filter(|field| {
                field.name() != key.name()
                    && arithmetic::encoding::is_segment_of(field.name(), key.name())
                    && !field.name()[key.name().len()..]
                        .starts_with(arithmetic::encoding::STRING_FINGERPRINT_LIMB_PREFIX)
                    && !matches!(
                        (qualifier, field.metadata().get(QUALIFIER_METADATA_KEY)),
                        (Some(key_q), Some(seg_q)) if key_q != seg_q
                    )
            })
            .cloned(),
    );
    Ok(out)
}

fn field_matches_column(field: &Field, col: &Column) -> bool {
    if field.name() != col.name.as_str() {
        return false;
    }
    let Some(relation) = col.relation.as_ref() else {
        return true;
    };
    let expected = table_name_from_relation(relation);
    field
        .metadata()
        .get(QUALIFIER_METADATA_KEY)
        .map(|qualifier| table_name_from_qualifier(qualifier) == expected)
        .unwrap_or(false)
}

fn table_name_from_relation(relation: &TableReference) -> String {
    table_name_from_qualifier(&relation.to_string())
}
