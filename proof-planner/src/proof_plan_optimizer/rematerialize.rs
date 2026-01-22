use std::collections::HashSet;

use super::ProofPlanOptimizerRule;
use arithmetic::ACTIVATOR_COL_NAME;
use ark_piop::SnarkBackend;
use datafusion::arrow::array::BooleanArray;
use datafusion::datasource::TableProvider;
use datafusion_expr::{Filter, LogicalPlan};
use tt_core::irs::nodes::plan::rematerialize::wrap_logical_plan;
use tt_core::irs::{
    nodes::{IsNode, Node, PlanNode},
    payloads::PayloadStructure,
    shared_ir::InitialIr,
    shared_passes::{GadgetPlanningPass, OutputPlanningPass},
    tree::Tree,
};
use tt_core::prover::{
    irs::MaterializedIr, passes::materialization::MaterializationPass, payloads::MaterializedTable,
};
pub struct RematerializeRule {
    active_threshold_num: usize,
    active_threshold_den: usize,
}

impl RematerializeRule {
    pub fn new() -> Self {
        Self {
            active_threshold_num: 1,
            active_threshold_den: 2,
        }
    }
}

impl<B: SnarkBackend> ProofPlanOptimizerRule<B> for RematerializeRule {
    fn name(&self) -> &'static str {
        "rematerialize"
    }

    fn optimize(&self, ir: InitialIr<B>) -> InitialIr<B> {
        let output_planned = ir.apply_local_pass_parallel(&OutputPlanningPass::new());
        let gadget_planned =
            output_planned.apply_local_pass_sequential(&GadgetPlanningPass::new(&output_planned));
        let materialized = gadget_planned.apply_local_pass_parallel(&MaterializationPass::new());

        let remat_keys = rematerialize_filter_keys(&materialized, self);
        if remat_keys.is_empty() {
            return ir;
        }

        let root_lp = match ir.tree().root().as_ref() {
            Node::Plan(PlanNode::LpBased(node)) => node.lp(),
            _ => return ir,
        };
        let rewritten = rewrite_logical_plan(&root_lp, &remat_keys);
        let tree: Tree<B> = Tree::from_logical_plan(&rewritten);
        InitialIr::new_empty(tree)
    }
}

fn rematerialize_filter_keys<B: SnarkBackend>(
    materialized: &MaterializedIr<B>,
    rule: &RematerializeRule,
) -> HashSet<String> {
    let mut keys = HashSet::new();
    for (id, node) in materialized.tree().arena() {
        let Node::Plan(PlanNode::LpBased(lp_node)) = node.as_ref() else {
            continue;
        };
        if node.name() != "Filter" {
            continue;
        }
        let LogicalPlan::Filter(filter) = lp_node.lp() else {
            continue;
        };
        let payload = materialized.payload_for_node(id);
        let Some(PayloadStructure::PlanPayload(table)) = payload else {
            continue;
        };
        let Some((active, total)) = count_active_rows(table) else {
            continue;
        };
        if total == 0 {
            continue;
        }
        if active * rule.active_threshold_den <= total * rule.active_threshold_num {
            keys.insert(filter_key(&filter));
        }
    }
    keys
}

fn count_active_rows(table: &MaterializedTable) -> Option<(usize, usize)> {
    let batches = table.batches().ok()?;
    let schema = table.mem_table().schema();
    let activator_idx = schema.index_of(ACTIVATOR_COL_NAME).ok()?;
    let mut active = 0usize;
    for batch in batches {
        let col = batch.column(activator_idx);
        let arr = col.as_any().downcast_ref::<BooleanArray>()?;
        active += arr.iter().filter(|v| v.unwrap_or(false)).count();
    }
    Some((active, table.row_count()))
}

fn filter_key(filter: &Filter) -> String {
    format!("{:?}", filter.predicate)
}

fn rewrite_logical_plan(plan: &LogicalPlan, remat_keys: &HashSet<String>) -> LogicalPlan {
    let inputs: Vec<LogicalPlan> = plan
        .inputs()
        .into_iter()
        .map(|child| rewrite_logical_plan(child, remat_keys))
        .collect();
    let exprs = plan.expressions();
    let mut new_plan = plan
        .with_new_exprs(exprs, inputs)
        .expect("logical plan rewrite should succeed");

    if let LogicalPlan::Filter(filter) = &new_plan {
        if remat_keys.contains(&filter_key(filter)) {
            new_plan = wrap_logical_plan(new_plan);
        }
    }

    new_plan
}

#[cfg(test)]
mod tests {
    use super::RematerializeRule;
    use crate::proof_plan_optimizer::ProofPlanOptimizerRule;
    use arithmetic::ACTIVATOR_COL_NAME;
    use ark_piop::DefaultSnarkBackend;
    use datafusion::arrow::{
        array::{ArrayRef, BooleanArray, Int32Array},
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    };
    use datafusion::datasource::{provider_as_source, MemTable};
    use datafusion_expr::logical_plan::builder::LogicalPlanBuilder;
    use datafusion_expr::{col, lit, Expr};
    use std::sync::Arc;
    use tt_core::irs::nodes::IsNode;
    use tt_core::irs::{shared_ir::InitialIr, tree::Tree};

    type Backend = DefaultSnarkBackend;

    fn run_rule_test(values: &[i32], predicate: Expr, expected_remat: usize) {
        let schema = Arc::new(Schema::new(vec![
            Field::new("a", DataType::Int32, false),
            Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int32Array::from(values.to_vec())) as ArrayRef,
                Arc::new(BooleanArray::from(vec![true; values.len()])) as ArrayRef,
            ],
        )
        .expect("test batch should build");
        let mem_table =
            MemTable::try_new(schema.clone(), vec![vec![batch]]).expect("memtable should build");
        let table_source = provider_as_source(Arc::new(mem_table));
        let plan = LogicalPlanBuilder::scan("t", table_source, None)
            .expect("scan should build")
            .filter(predicate)
            .expect("filter should build")
            .build()
            .expect("plan should build");
        let tree = Tree::<Backend>::from_logical_plan(&plan);
        let initial_ir = InitialIr::<Backend>::new_empty(tree);

        let optimized = RematerializeRule::new().optimize(initial_ir);
        let remat_count = optimized
            .tree()
            .arena()
            .values()
            .filter(|node| node.name() == "Rematerialize")
            .count();
        assert_eq!(remat_count, expected_remat);
    }

    #[test]
    fn rematerialize_inserted_at_threshold() {
        run_rule_test(&[1, 2, 3, 4], col("a").gt(lit(2)), 1);
    }

    #[test]
    fn rematerialize_skipped_above_threshold() {
        run_rule_test(&[1, 2, 3, 4], col("a").gt(lit(1)), 0);
    }
}
