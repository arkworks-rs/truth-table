use arithmetic::ROW_ID_COL_NAME;
use arithmetic::table_oracle::ArithTableOracle;
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::Schema;
use derivative::Derivative;
use indexmap::IndexMap;

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
            if let Some(name) = infer_table_name(schema)
                .or_else(|| oracle.schema_ref().and_then(infer_table_name))
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
                self.table_oracles.iter().find_map(|(oracle_schema, oracle)| {
                    schema_matches_table_scan(schema, oracle_schema).then_some(oracle)
                })
            })
    }

    pub fn table_oracles(&self) -> &IndexMap<Schema, ArithTableOracle<B>> {
        &self.table_oracles
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
    schema
        .fields()
        .iter()
        .find_map(|field| {
            if field.name() == arithmetic::ACTIVATOR_COL_NAME || field.name() == arithmetic::ROW_ID_COL_NAME {
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
