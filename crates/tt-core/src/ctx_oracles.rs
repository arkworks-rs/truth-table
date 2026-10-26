use std::collections::BTreeSet;

use arithmetic::ROW_ID_COL_NAME;
use arithmetic::encoding::STRING_RANK_SUFFIX;
use arithmetic::table_oracle::ArithTableOracle;
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::Schema;
use datafusion_common::DataFusionError;
use datafusion_expr::LogicalPlan;
use derivative::Derivative;
use indexmap::IndexMap;

use crate::errors::TTResult;
use crate::irs::lineage::is_string_type;
use crate::irs::nodes::{Node, PlanNode};
use crate::irs::tree::Tree;

#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""), Debug(bound = ""))]
pub struct CtxOracles<B: SnarkBackend> {
    table_oracles: IndexMap<Schema, ArithTableOracle<B>>,
    table_oracles_by_name: IndexMap<String, ArithTableOracle<B>>,
}

impl<B: SnarkBackend> CtxOracles<B> {
    pub fn new(table_oracles: IndexMap<Schema, ArithTableOracle<B>>) -> Self {
        Self::with_named_oracles(table_oracles, IndexMap::new())
    }

    pub fn with_named_oracles(
        table_oracles: IndexMap<Schema, ArithTableOracle<B>>,
        mut named_oracles: IndexMap<String, ArithTableOracle<B>>,
    ) -> Self {
        for (schema, oracle) in &table_oracles {
            if let Some(name) =
                infer_table_name(schema).or_else(|| oracle.schema_ref().and_then(infer_table_name))
            {
                named_oracles.entry(name).or_insert_with(|| oracle.clone());
            }
        }
        Self {
            table_oracles,
            table_oracles_by_name: named_oracles,
        }
    }

    pub fn table_oracle(&self, schema: &Schema) -> Option<&ArithTableOracle<B>> {
        self.table_oracles.get(schema)
    }

    pub fn table_oracle_by_name(&self, table_name: &str) -> Option<&ArithTableOracle<B>> {
        self.table_oracles_by_name.get(table_name)
    }

    pub fn table_oracle_for_schema(&self, schema: &Schema) -> Option<&ArithTableOracle<B>> {
        self.table_oracle(schema)
            .or_else(|| infer_table_name(schema).and_then(|name| self.table_oracle_by_name(&name)))
            .or_else(|| {
                self.table_oracles
                    .iter()
                    .find_map(|(oracle_schema, oracle)| {
                        schema_matches_table_scan(schema, oracle_schema).then_some(oracle)
                    })
            })
    }

    pub fn table_oracles(&self) -> &IndexMap<Schema, ArithTableOracle<B>> {
        &self.table_oracles
    }

    /// Every table scan in `tree` of a `(table, column)` in `rank_columns`
    /// has an oracle committing that column's rank. A rank is owner data: a
    /// scan with no oracle would take it from the prover.
    pub fn ensure_rank_columns(
        &self,
        tree: &Tree<B>,
        rank_columns: &BTreeSet<(String, String)>,
    ) -> TTResult<()> {
        if rank_columns.is_empty() {
            return Ok(());
        }
        for node in tree.arena().values() {
            let Node::Plan(PlanNode::LpBased(lp_node)) = node.as_ref() else {
                continue;
            };
            let LogicalPlan::TableScan(scan) = lp_node.lp() else {
                continue;
            };
            let table = scan.table_name.table();
            for field in scan.projected_schema.fields() {
                let column = field.name();
                if !is_string_type(field.data_type())
                    || !rank_columns.contains(&(table.to_string(), column.clone()))
                {
                    continue;
                }
                let Some(oracle) = self.table_oracle_by_name(table) else {
                    return Err(DataFusionError::Plan(format!(
                        "column {column} of table {table} needs its committed rank, \
                         but the table has no oracle"
                    ))
                    .into());
                };
                let rank_field = format!("{column}{STRING_RANK_SUFFIX}");
                if !oracle
                    .commitments()
                    .keys()
                    .any(|field| *field.name() == rank_field)
                {
                    return Err(DataFusionError::Plan(format!(
                        "table {table} has no rank for column {column}; re-commit it with ranks"
                    ))
                    .into());
                }
            }
        }
        Ok(())
    }
}

impl<B: SnarkBackend> Default for CtxOracles<B> {
    fn default() -> Self {
        Self {
            table_oracles: IndexMap::new(),
            table_oracles_by_name: IndexMap::new(),
        }
    }
}

fn infer_table_name(schema: &Schema) -> Option<String> {
    schema.fields().iter().find_map(|field| {
        if field.name() == arithmetic::ACTIVATOR_COL_NAME
            || field.name() == arithmetic::ROW_ID_COL_NAME
        {
            return None;
        }
        field
            .metadata()
            .get("tt.qualifier")
            .map(|qualifier| table_name_from_qualifier(qualifier))
    })
}

fn table_name_from_qualifier(qualifier: &str) -> String {
    qualifier
        .rsplit('.')
        .next()
        .unwrap_or(qualifier)
        .to_string()
}

fn schema_matches_table_scan(scan_schema: &Schema, oracle_schema: &Schema) -> bool {
    let scan_fields = scan_schema
        .fields()
        .iter()
        .filter(|field| field.name() != ROW_ID_COL_NAME)
        .map(|field| (field.name(), field.data_type()))
        .collect::<Vec<_>>();
    let oracle_fields = oracle_schema
        .fields()
        .iter()
        .filter(|field| field.name() != ROW_ID_COL_NAME)
        .map(|field| (field.name(), field.data_type()))
        .collect::<Vec<_>>();
    scan_fields == oracle_fields
}
