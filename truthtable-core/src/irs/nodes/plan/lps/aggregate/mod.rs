use std::sync::Arc;

use ark_ff::PrimeField;
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion_expr::Aggregate;

use crate::irs::nodes::Node;

mod hints;
pub struct ProverAggregateNode<B>
where
    B: SnarkBackend,
{
    // The aggregate information from datafusion
    aggregate: Aggregate,
    // The prover plan children nodes for the group by expressions
    input: Node<B>,
    group_exprs: Vec<Node<B>>,
    aggr_exprs: Vec<Node<B>>,
}

// impl<B> ProverPlanNode<B> for ProverAggregateNode<B>
// where
//     F: PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
// {
//     fn node_id(&self) -> NodeId {
//         NodeId::LP(LogicalPlan::Aggregate(self.aggregate.clone()))
//     }
//     fn arithmetic_post_process(&self) {
//         todo!()
//     }

//     fn add_virtual_witness(&self, prover: &mut ArgProver<B>) {

//         // Fetch the current output table tracked by this aggregate node
//         // This should contain only the materialized columns; i.e. the new activator and
//         // the aggregate expression columns
//         // It remains to attach the grouping expression columns at the front
//         // let Some(existing_materialized_output_table) = piop_tree
//         //     .tracked_table(&self.node_id, OUTPUT_PLAN_KEY)
//         //     .cloned()
//         // else {
//         //     panic!("missing output plan table for the current aggregate node");
//         // };
//         // // Separate aggregate value columns and the activator from the current output
//         // // table.
//         // let group_col_count = aggregate_plan.group_expr.len();
//         // let aggregate_col_count = aggregate_plan.aggr_expr.len();
//         // let agg_schema = aggregate_plan.schema.as_ref();
//         // let aggr_field_names: Vec<_> = (0..aggregate_col_count)
//         //     .map(|idx| agg_schema.field(group_col_count + idx).name().clone())
//         //     .collect();

//         // let mut aggregate_entries: IndexMap<String, (FieldRef, TrackedPoly<B>)> =
//         //     IndexMap::with_capacity(aggregate_col_count);
//         // let mut activator_entry = None;
//         // for (field, poly) in existing_materialized_output_table.tracked_polys() {
//         //     if field.name() == ACTIVATOR_COL_NAME {
//         //         activator_entry = Some((field.clone(), poly.clone()));
//         //     } else if aggr_field_names.iter().any(|name| name == field.name()) {
//         //         aggregate_entries.insert(field.name().clone(), (field.clone(), poly.clone()));
//         //     }
//         // }

//         // if !self.aggr_expr_proof_tree_roots.is_empty() {
//         //     if aggregate_entries.len() != self.aggr_expr_proof_tree_roots.len() {
//         //         panic!(
//         //             "aggregate expressions count mismatch: expected {}, found {}",
//         //             self.aggr_expr_proof_tree_roots.len(),
//         //             aggregate_entries.len()
//         //         );
//         //     }

//         //     let (activator_field, activator_poly) = activator_entry
//         //         .as_ref()
//         //         .unwrap_or_else(|| panic!("aggregate output missing activator column"));

//         //     for (idx, aggr_node) in self.aggr_expr_proof_tree_roots.iter().enumerate() {
//         //         let field_name = &aggr_field_names[idx];
//         //         let (agg_field, agg_poly) = aggregate_entries
//         //             .get(field_name)
//         //             .cloned()
//         //             .unwrap_or_else(|| panic!("missing aggregate entry for {}", aggr_node.name()));

//         //         let mut columns = IndexMap::with_capacity(2);
//         //         columns.insert(agg_field, agg_poly);
//         //         columns.insert(activator_field.clone(), activator_poly.clone());

//         //         let agg_child_table =
//         //             TrackedTable::new(None, columns, existing_materialized_output_table.log_size());

//         //         piop_tree.add_table(
//         //             aggr_node.node_id(),
//         //             OUTPUT_PLAN_KEY.to_string(),
//         //             agg_child_table,
//         //         );
//         //     }
//         // }

//         // // Rebuild the output table so grouping columns, aggregate columns and the
//         // // activator are materialized on this node.
//         // let mut group_entries: Vec<(FieldRef, TrackedPoly<B>)> =
//         //     Vec::with_capacity(group_col_count);
//         // for group_node in self.group_expr_proof_tree_roots.iter() {
//         //     let group_table = piop_tree
//         //         .tracked_table(&group_node.node_id(), OUTPUT_PLAN_KEY)
//         //         .unwrap_or_else(|| {
//         //             panic!(
//         //                 "missing output_plan table for group expr {}",
//         //                 group_node.name()
//         //             )
//         //         });
//         //     assert_eq!(
//         //         group_table.log_size(),
//         //         existing_materialized_output_table.log_size(),
//         //         "group expression table log size mismatch for aggregate output"
//         //     );

//         //     let (field_ref, group_poly) = group_table
//         //         .tracked_polys()
//         //         .iter()
//         //         .find_map(|(field, poly)| {
//         //             (field.name() != ACTIVATOR_COL_NAME).then(|| (field.clone(), poly.clone()))
//         //         })
//         //         .unwrap_or_else(|| {
//         //             panic!(
//         //                 "group expr {} did not produce a data column",
//         //                 group_node.name()
//         //             )
//         //         });

//         //     group_entries.push((field_ref, group_poly));
//         // }

//         // let mut combined_columns = IndexMap::with_capacity(
//         //     group_entries.len() + aggregate_entries.len() + usize::from(activator_entry.is_some()),
//         // );
//         // for (field, poly) in group_entries {
//         //     combined_columns.insert(field, poly);
//         // }
//         // for field_name in &aggr_field_names {
//         //     if let Some((field, poly)) = aggregate_entries.get(field_name) {
//         //         combined_columns.insert(field.clone(), poly.clone());
//         //     }
//         // }
//         // if let Some((field, poly)) = activator_entry {
//         //     combined_columns.insert(field, poly);
//         // }

//         // let schema_fields = combined_columns
//         //     .keys()
//         //     .map(|field_ref| field_ref.as_ref().clone())
//         //     .collect::<Vec<_>>();
//         // let updated_table = TrackedTable::new(
//         //     Some(Schema::new(schema_fields)),
//         //     combined_columns,
//         //     existing_materialized_output_table.log_size(),
//         // );

//         // piop_tree.add_table(
//         //     self.node_id.clone(),
//         //     OUTPUT_PLAN_KEY.to_string(),
//         //     updated_table,
//         // );
//     }

//     fn cost(
//         &self,
//         statistics: datafusion::common::Statistics,
//         schema: datafusion::arrow::datatypes::SchemaRef,
//     ) -> crate::nodes::cost::ProvingCost {
//         todo!()
//     }

//     fn output(&self, proof_tree: &ProverProofTree<B>) -> HintDF {
//         // Get the output of the child node as the input hint generation plan
//         let input_hint_generation_plan = self.input.output(proof_tree);
//         // Extract the data frame from the input hint generation plan
//         let input = input_hint_generation_plan.data_frame();
//         let output = hints::build_output_dataframe(input, &self.aggregate);
//         HintDF::new_virtual(output)
//     }

//     fn ctx_lp_node(
//         &self,
//         _proof_tree: &ProverProofTree<B>,
//     ) -> Arc<dyn ProverPlanNode<B>> {
//         self.input.clone()
//     }

//     fn children(&self) -> Vec<Arc<dyn ProverPlanNode<B>>> {
//         let mut children: Vec<Arc<dyn ProverPlanNode<B>>> = vec![];
//         children.push(self.input.clone());
//         self.group_exprs
//             .iter()
//             .for_each(|e| children.push(e.clone()));
//         self.aggr_exprs
//             .iter()
//             .for_each(|e| children.push(e.clone()));
//         children
//     }

//     fn gadget_tree(&self) -> crate::prover::trees::gadget_tree::GadgetTree<B> {
//         todo!()
//     }
// }

// impl<B> ProverLpNode<B> for ProverAggregateNode<B>
// where
//     F: PrimeField,
//     MvPCS: PCS<F, Poly = MLE<F>> + 'static + Sync + Send,
//     UvPCS: PCS<F, Poly = LDE<F>> + 'static + Sync + Send,
// {
//     fn from_lp(
//         ctx: &SessionContext,
//         prover_ctx: arithmetic::ctx::SharedCtx<B>,
//         plan: LogicalPlan,
//         parent_node_id: NodeId,
//     ) -> Self
//     where
//         Self: Sized,
//     {
//         // Get the aggregate object from the logical plan
//         let aggregate = match &plan {
//             LogicalPlan::Aggregate(p) => p,
//             _ => panic!("expected aggregate logical plan"),
//         }
//         .clone();
//         // Build the node id for this aggregate node
//         let node_id = NodeId::LP(plan.clone());
//         // Recurse into the input subtree and fetch the logical plan that feeds this
//         // aggregate.
//         let input_prover_node = ProverProofTree::<B>::from_lp(
//             ctx,
//             prover_ctx.clone(),
//             &aggregate.input,
//             &Some(node_id.clone()),
//         )
//         .root()
//         .clone();

//         // Recursively build prover nodes for each group expression
//         let group_exprs = aggregate
//             .group_expr
//             .iter()
//             .map(|expr| {
//                 ProverProofTree::<B>::from_expr(
//                     ctx,
//                     prover_ctx.clone(),
//                     expr.clone(),
//                     &Some(node_id.clone()),
//                 )
//                 .root()
//                 .clone()
//             })
//             .collect::<Vec<_>>();

//         // Recursively build prover nodes for each aggregate expression
//         let aggr_exprs = aggregate
//             .aggr_expr
//             .iter()
//             .map(|expr| {
//                 ProverProofTree::<B>::from_expr(
//                     ctx,
//                     prover_ctx.clone(),
//                     expr.clone(),
//                     &Some(node_id.clone()),
//                 )
//                 .root()
//                 .clone()
//             })
//             .collect::<Vec<_>>();

//         Self {
//             group_exprs,
//             aggr_exprs,
//             input: input_prover_node,
//             aggregate,
//         }
//     }
// }
