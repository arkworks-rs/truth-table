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
use datafusion_expr::Expr;
use indexmap::IndexMap;

impl<B: SnarkBackend> GadgetNode<B> {
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
        nodup_payload.insert(nodup::INPUT_LABEL.to_string(), nodup_table);
        virtualized_ir.set_payload_for_node(
            gadgets.nodup_gadget.id(),
            Some(PayloadStructure::GadgetPayload(nodup_payload)),
        );
    }
    fn ordered_column_names(
        mut keys: Vec<String>,
        include_row_id: bool,
        include_activator: bool,
    ) -> Vec<String> {
        if include_row_id && !keys.iter().any(|name| name == ROW_ID_COL_NAME) {
            keys.push(ROW_ID_COL_NAME.to_string());
        }
        if include_activator && !keys.iter().any(|name| name == ACTIVATOR_COL_NAME) {
            keys.push(ACTIVATOR_COL_NAME.to_string());
        }
        keys
    }
    fn join_key_names(join: &datafusion_expr::Join, use_left: bool) -> Vec<String> {
        join.on
            .iter()
            .map(|(left, right)| {
                let expr = if use_left { left } else { right };
                match expr {
                    Expr::Column(col) => col.name.clone(),
                    _ => panic!("Join match-pair keys must be column expressions"),
                }
            })
            .collect()
    }

    fn select_tracked_columns(
        table: &TrackedTable<B>,
        column_names: &[String],
        side: &str,
    ) -> TrackedTable<B> {
        let cols = table.tracked_polys();
        let mut selected = IndexMap::new();
        for name in column_names {
            let (field, poly) = cols
                .iter()
                .find(|(field, _)| field.name() == name)
                .unwrap_or_else(|| panic!("Join {side} table missing column {name}"));
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
        column_names: &[String],
        side: &str,
    ) -> TrackedTableOracle<B> {
        let cols = table.tracked_oracles();
        let mut selected = IndexMap::new();
        for name in column_names {
            let (field, oracle) = cols
                .iter()
                .find(|(field, _)| field.name() == name)
                .unwrap_or_else(|| panic!("Join {side} table missing column {name}"));
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
        let left_keys =
            Self::ordered_column_names(Self::join_key_names(join, true), include_left_row_id, true);
        let right_keys = Self::ordered_column_names(
            Self::join_key_names(join, false),
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
        let left_keys =
            Self::ordered_column_names(Self::join_key_names(join, true), include_left_row_id, true);
        let right_keys = Self::ordered_column_names(
            Self::join_key_names(join, false),
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
