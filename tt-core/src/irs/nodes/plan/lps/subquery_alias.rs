use std::sync::{Arc, Weak};

use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{Field, Schema};
use datafusion_expr::{LogicalPlan, SubqueryAlias};
use indexmap::IndexMap;

use crate::irs::{
    nodes::{IsLpNode, IsNode, IsPlanNode, Node, ProverNodeOps, VerifierNodeOps},
    payloads::PayloadStructure,
    tree::Tree,
};
use arithmetic::{
    ACTIVATOR_COL_NAME, ROW_ID_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle,
};

const QUALIFIER_METADATA_KEY: &str = "tt.qualifier";

pub struct LpNode<B>
where
    B: SnarkBackend,
{
    input: Arc<Node<B>>,
    subquery_alias: SubqueryAlias,
}

impl<B: SnarkBackend> IsNode<B> for LpNode<B> {
    fn name(&self) -> String {
        "Subquery Alias".to_string()
    }

    fn display(&self) -> String {
        format!(
            "Subquery Alias\nInput: {}, alias: {}",
            self.input.name(),
            self.subquery_alias.alias
        )
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        vec![self.input.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for LpNode<B> {
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let input_id = self.input.id();
        let input_table = match virtualized_ir.payload_for_node(&input_id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };
        let alias = self.subquery_alias.alias.to_string();
        let aliased_table = qualify_tracked_table(input_table, &alias);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(aliased_table)));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for LpNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        None
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("Subquery alias input cannot be a gadget node"),
        };

        let aliased_df = input_hint_df
            .data_frame()
            .clone()
            .alias(&self.subquery_alias.alias.to_string())
            .expect("subquery alias should succeed");
        let aliased_df = crate::irs::nodes::hints::sort_by_row_id_if_present(aliased_df)
            .expect("subquery alias output sort should succeed");
        crate::irs::nodes::hints::HintDF::new_virtual(aliased_df)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for LpNode<B> {
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let input_id = self.input.id();
        let input_table = match virtualized_ir.payload_for_node(&input_id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => return Ok(()),
        };
        let alias = self.subquery_alias.alias.to_string();
        let aliased_table = qualify_tracked_table_oracle(input_table, &alias);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(aliased_table)));
        Ok(())
    }
    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

fn qualify_field(field: &Field, alias: &str) -> Field {
    if field.name() == ACTIVATOR_COL_NAME || field.name() == ROW_ID_COL_NAME {
        return field.clone();
    }
    let mut updated = field.clone();
    // Record alias in metadata so self-joins can distinguish identical column names.
    let mut metadata = updated.metadata().clone();
    metadata.insert(QUALIFIER_METADATA_KEY.to_string(), alias.to_string());
    updated.with_metadata(metadata)
}

fn qualify_tracked_table<B: SnarkBackend>(table: TrackedTable<B>, alias: &str) -> TrackedTable<B> {
    let tracked_polys = table.tracked_polys();
    let mut qualified = IndexMap::with_capacity(tracked_polys.len());
    for (field, poly) in tracked_polys.into_iter() {
        let updated = Arc::new(qualify_field(field.as_ref(), alias));
        qualified.insert(updated, poly);
    }
    let schema = table.schema_ref().map(|schema| {
        let fields: Vec<Field> = schema
            .fields()
            .iter()
            .map(|f| qualify_field(f.as_ref(), alias))
            .collect();
        Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    let schema = schema.or_else(|| {
        Some(Schema::new(
            qualified
                .keys()
                .map(|f| f.as_ref().clone())
                .collect::<Vec<_>>(),
        ))
    });
    TrackedTable::new(schema, qualified, table.log_size())
}

fn qualify_tracked_table_oracle<B: SnarkBackend>(
    table: TrackedTableOracle<B>,
    alias: &str,
) -> TrackedTableOracle<B> {
    let tracked_oracles = table.tracked_oracles();
    let mut qualified = IndexMap::with_capacity(tracked_oracles.len());
    for (field, oracle) in tracked_oracles.into_iter() {
        let updated = Arc::new(qualify_field(field.as_ref(), alias));
        qualified.insert(updated, oracle);
    }
    let schema = table.schema_ref().map(|schema| {
        let fields: Vec<Field> = schema
            .fields()
            .iter()
            .map(|f| qualify_field(f.as_ref(), alias))
            .collect();
        Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    let schema = schema.or_else(|| {
        Some(Schema::new(
            qualified
                .keys()
                .map(|f| f.as_ref().clone())
                .collect::<Vec<_>>(),
        ))
    });
    TrackedTableOracle::new(schema, qualified, table.log_size())
}

impl<B: SnarkBackend> IsLpNode<B> for LpNode<B> {
    fn from_lp(plan: datafusion_expr::LogicalPlan, _self_ref: Weak<Node<B>>) -> Self
    where
        Self: Sized,
    {
        let subquery_alias =
            if let datafusion_expr::LogicalPlan::SubqueryAlias(subquery_alias) = plan {
                subquery_alias
            } else {
                panic!("Expected LogicalPlan::SubqueryAlias");
            };

        let input = Tree::<B>::from_logical_plan(&subquery_alias.input)
            .root()
            .clone();
        LpNode {
            input,
            subquery_alias,
        }
    }

    fn lp(&self) -> LogicalPlan {
        LogicalPlan::SubqueryAlias(self.subquery_alias.clone())
    }
}
