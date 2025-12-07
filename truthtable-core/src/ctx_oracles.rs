use arithmetic::table_oracle::ArithTableOracle;
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::Schema;
use derivative::Derivative;
use indexmap::IndexMap;

#[derive(Derivative)]
#[derivative(Clone(bound = ""), PartialEq(bound = ""), Debug(bound = ""))]
pub struct CtxOracles<B: SnarkBackend> {
    table_oracles: IndexMap<Schema, ArithTableOracle<B>>,
}

impl<B: SnarkBackend> CtxOracles<B> {
    pub fn new(table_oracles: IndexMap<Schema, ArithTableOracle<B>>) -> Self {
        Self { table_oracles }
    }

    pub fn table_oracle(&self, schema: &Schema) -> Option<&ArithTableOracle<B>> {
        self.table_oracles.get(schema)
    }

    pub fn table_oracles(&self) -> &IndexMap<Schema, ArithTableOracle<B>> {
        &self.table_oracles
    }
}

impl<B: SnarkBackend> Default for CtxOracles<B> {
    fn default() -> Self {
        Self {
            table_oracles: IndexMap::new(),
        }
    }
}
