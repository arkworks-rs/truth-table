use std::sync::Arc;

use crate::irs::nodes::gadget::lps::join::GadgetNode;
use crate::irs::{
    nodes::gadget::utils::{bool, match_pair_check, nodup},
    payloads::PayloadStructure,
};
use arithmetic::{
    ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, ROW_ID_COL_NAME, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion_common::{Column, TableReference};
use datafusion_expr::Expr;
use indexmap::IndexMap;

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
    ) {
        let Some(gadgets) = self.many_to_many_gadgets() else {
            return;
        };
        let nodup_table = Self::nodup_table_from_output_prover(output, left_src, right_src);
        let mut nodup_payload = match virtualized_ir.payload_for_node(&gadgets.nodup_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        nodup_payload
            .entry(nodup::INPUT_LABEL.to_string())
            .or_insert(nodup_table);
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

    fn table_name_from_relation(relation: &TableReference) -> String {
        Self::table_name_from_qualifier(&relation.to_string())
    }

    fn table_name_from_qualifier(qualifier: &str) -> String {
        qualifier
            .rsplit('.')
            .next()
            .unwrap_or(qualifier)
            .trim_matches('"')
            .trim_matches('`')
            .to_lowercase()
    }

    fn field_matches_column(field: &Arc<Field>, col: &Column) -> bool {
        if field.name() != col.name.as_str() {
            return false;
        }
        let Some(relation) = col.relation.as_ref() else {
            return true;
        };
        let expected = Self::table_name_from_relation(relation);
        field
            .metadata()
            .get(Self::QUALIFIER_METADATA_KEY)
            .map(|qualifier| Self::table_name_from_qualifier(qualifier) == expected)
            .unwrap_or(false)
    }

    fn select_tracked_columns(
        table: &TrackedTable<B>,
        columns: &[Column],
        side: &str,
    ) -> TrackedTable<B> {
        let cols = table.tracked_polys();
        let mut selected = IndexMap::new();
        for col in columns {
            let exact = cols
                .iter()
                .filter(|(field, _)| Self::field_matches_column(field, col))
                .collect::<Vec<_>>();
            let (field, poly) = if exact.len() == 1 {
                (exact[0].0, exact[0].1)
            } else {
                let by_name = cols
                    .iter()
                    .filter(|(field, _)| field.name() == col.name.as_str())
                    .collect::<Vec<_>>();
                if by_name.len() == 1 {
                    (by_name[0].0, by_name[0].1)
                } else if by_name.is_empty() {
                    panic!("Join {side} table missing column {}", col.flat_name())
                } else {
                    panic!(
                        "Join {side} table has ambiguous column {} ({} candidates)",
                        col.flat_name(),
                        by_name.len()
                    )
                }
            };
            selected.insert(field.clone(), poly.clone());
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
            let exact = cols
                .iter()
                .filter(|(field, _)| Self::field_matches_column(field, col))
                .collect::<Vec<_>>();
            let (field, oracle) = if exact.len() == 1 {
                (exact[0].0, exact[0].1)
            } else {
                let by_name = cols
                    .iter()
                    .filter(|(field, _)| field.name() == col.name.as_str())
                    .collect::<Vec<_>>();
                if by_name.len() == 1 {
                    (by_name[0].0, by_name[0].1)
                } else if by_name.is_empty() {
                    panic!("Join {side} table missing column {}", col.flat_name())
                } else {
                    panic!(
                        "Join {side} table has ambiguous column {} ({} candidates)",
                        col.flat_name(),
                        by_name.len()
                    )
                }
            };
            selected.insert(field.clone(), oracle.clone());
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
    ) {
        let Some(gadgets) = self.many_to_many_gadgets() else {
            return;
        };
        let nodup_table = Self::nodup_table_from_output_verifier(output, left_src, right_src);
        let mut nodup_payload = match virtualized_ir.payload_for_node(&gadgets.nodup_gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        nodup_payload
            .entry(nodup::INPUT_LABEL.to_string())
            .or_insert(nodup_table);
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
