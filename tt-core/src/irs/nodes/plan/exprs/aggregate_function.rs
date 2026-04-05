use std::{collections::HashSet, sync::Arc};

use arithmetic::{ACTIVATOR_FIELD, is_system_column};
use ark_ff::One;
use ark_piop::{
    SnarkBackend, prover::structs::polynomial::TrackedPoly,
    verifier::structs::oracle::TrackedOracle,
};
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use datafusion_common::{Column, Statistics};
use datafusion_expr::{Expr, LogicalPlan, expr::AggregateFunction};
use either::Either;
use indexmap::IndexMap;

use crate::irs::{
    nodes::{
        IsExprNode, IsNode, IsPlanNode, Node, NodeId, PlanNode, ProverNodeOps, VerifierNodeOps,
        gadget::exprs::aggregate_function,
    },
    payloads::PayloadStructure,
    tree::Tree,
};
pub const OUTPUT_AGGR_EXPR_LABEL: &str = "__output-aggr-expr__";
pub const INPUT_AGGR_EXPR_LABEL: &str = "__input-aggr-expr__";
pub const OUTPUT_GROUPS_LABEL: &str = "__input-groups__";
#[derive(Clone)]
pub struct ExprNode<B: SnarkBackend> {
    pub aggregate_function: AggregateFunction,
    pub scope: Vec<std::sync::Weak<Node<B>>>,
    pub parent: Option<std::sync::Weak<Node<B>>>,
    pub args: Vec<Arc<Node<B>>>,
    pub gadget: Option<Arc<Node<B>>>,
}

impl<B: SnarkBackend> ExprNode<B> {
    fn output_column_name(&self) -> String {
        Expr::AggregateFunction(self.aggregate_function.clone())
            .schema_name()
            .to_string()
    }

    // Resolve the aggregate output name as it appears in the parent Aggregate plan
    // (handles aliases like `sum(...) AS volume`).
    fn output_column_name_in_parent(&self) -> String {
        let parent_plan = self.parent();
        if let crate::irs::nodes::PlanNode::LpBased(lp_node) = parent_plan
            && let LogicalPlan::Aggregate(aggregate) = lp_node.lp()
        {
            let target = Expr::AggregateFunction(self.aggregate_function.clone());
            for expr in &aggregate.aggr_expr {
                match expr {
                    Expr::Alias(alias) if *alias.expr == target => {
                        return alias.name.clone();
                    }
                    Expr::AggregateFunction(func) if *func == self.aggregate_function => {
                        return Expr::AggregateFunction(func.clone())
                            .schema_name()
                            .to_string();
                    }
                    _ => {}
                }
            }
        }
        self.output_column_name()
    }
    fn dispatch_gadget(aggregate_function: &AggregateFunction) -> Option<Arc<Node<B>>> {
        match aggregate_function.func.name() {
            "count" => None,
            "sum" => Some(Arc::new(Node::<B>::Gadget(Arc::new(
                aggregate_function::sum::GadgetNode::new(),
            )))),
            "max" => Some(Arc::new(Node::<B>::Gadget(Arc::new(
                aggregate_function::max::GadgetNode::new(),
            )))),
            "min" => Some(Arc::new(Node::<B>::Gadget(Arc::new(
                aggregate_function::min::GadgetNode::new(),
            )))),
            "avg" => Some(Arc::new(Node::<B>::Gadget(Arc::new(
                aggregate_function::avg::GadgetNode::new(),
            )))),
            _ => panic!("Unsupported aggregate function gadget"),
        }
    }
}

impl<B: SnarkBackend> IsNode<B> for ExprNode<B> {
    fn name(&self) -> String {
        "AggregateFunction".to_string()
    }

    fn display(&self) -> String {
        let args = if self.args.is_empty() {
            "none".to_string()
        } else {
            self.args
                .iter()
                .map(|node| node.name())
                .collect::<Vec<_>>()
                .join(", ")
        };
        format!(
            "AggregateFunction\nScope: {}, func: {}, args: {}",
            self.scope()[0].name(),
            self.aggregate_function.func.name(),
            args
        )
    }

    fn cost(
        &self,
        _statistics: Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        let mut children = self.args.clone();
        if let Some(gadget) = &self.gadget {
            children.push(gadget.clone());
        }
        children
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ExprNode<B> {
    fn initialize_gadget_plans(
        &self,
        id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        fn dedup_exprs(exprs: Vec<Expr>) -> Vec<Expr> {
            let mut seen = HashSet::new();
            let mut unique = Vec::with_capacity(exprs.len());
            for expr in exprs {
                let name = expr.schema_name().to_string();
                if seen.insert(name) {
                    unique.push(expr);
                }
            }
            unique
        }

        let parent_node = self
            .parent
            .as_ref()
            .and_then(|weak_ref| weak_ref.upgrade())
            .expect("AggregateFunction node must have a parent");
        let plan_node = match parent_node.as_ref() {
            Node::Plan(plan_node) => plan_node.clone(),
            Node::Gadget(_) => return Ok(()),
        };
        let aggregate = match plan_node {
            PlanNode::LpBased(lp_node) => match lp_node.lp() {
                LogicalPlan::Aggregate(aggregate) => aggregate,
                _ => return Ok(()),
            },
            PlanNode::ExprBased(_) => return Ok(()),
        };

        let input_node = match parent_node.children().first() {
            Some(node) => node.clone(),
            None => return Ok(()),
        };
        let input_hint_df = match planned_ir.payload_for_node(&input_node.id()) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df.clone(),
            _ => return Ok(()),
        };
        let output_hint_df = match planned_ir.payload_for_node(&parent_node.id()) {
            Some(PayloadStructure::PlanPayload(hint_df)) => hint_df.clone(),
            _ => return Ok(()),
        };

        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(input_hint_df.data_frame().clone())
                .expect("aggregate function input row-id sort should succeed");

        let mut input_exprs = aggregate.group_expr.clone();
        input_exprs.extend(self.aggregate_function.params.args.clone());
        crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut input_exprs);
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut input_exprs);

        let output_df = crate::irs::nodes::hints::sort_by_row_id_if_present(
            output_hint_df.data_frame().clone(),
        )
        .expect("aggregate function output row-id sort should succeed");

        let mut output_exprs = aggregate.group_expr.clone();
        output_exprs.push(Expr::Column(Column::from_name(
            self.output_column_name_in_parent(),
        )));
        crate::irs::nodes::hints::append_activator_exprs_if_present(&output_df, &mut output_exprs);
        crate::irs::nodes::hints::append_row_id_expr_if_present(&output_df, &mut output_exprs);
        let output_projected = output_df
            .select(dedup_exprs(output_exprs))
            .expect("aggregate function output projection should succeed");
        let output_projected =
            crate::irs::nodes::hints::sort_by_row_id_if_present(output_projected)
                .expect("aggregate function output sort should succeed");

        let output_hint_df = crate::irs::nodes::hints::HintDF::new_virtual(output_projected);

        let mut gadget_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(
            crate::irs::nodes::gadget::exprs::aggregate_function::OUTPUT_LABEL.to_string(),
            output_hint_df,
        );
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));
        Ok(())
    }
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        if self.aggregate_function.func.name() == "count" {
            // Special case for COUNT: reuse lookup super-multiplicities instead of
            // materializing the aggregate output column. This saves a materialization
            // by treating multiplicity as the count result.
            let parent_node = self
                .parent
                .as_ref()
                .and_then(|weak_ref| weak_ref.upgrade())
                .expect("AggregateFunction node must have a parent");
            if let Some(lookup_node) = lookup_child_from_aggregate_parent(&parent_node)
                && let Some(PayloadStructure::GadgetPayload(lookup_payload)) =
                    virtualized_ir.payload_for_node(&lookup_node.id())
                && let Some(multiplicities_table) = lookup_payload
                    .get(crate::irs::nodes::gadget::utils::lookup::SUPER_MULTIPLICITIES_LABEL)
            {
                let count_table = count_table_from_multiplicities(
                    multiplicities_table,
                    &self.output_column_name_in_parent(),
                );
                // Emit a virtual table named after the COUNT output column, backed by
                // the multiplicity polynomial (plus system columns).
                virtualized_ir
                    .set_payload_for_node(id, Some(PayloadStructure::PlanPayload(count_table)));
                return Ok(());
            }
            // If there is no lookup (e.g., COUNT(*) over a base table), fall back to
            // a constant-one column aligned with the parent input activator.
            let parent_payload = virtualized_ir.payload_for_node(&parent_node.id()).and_then(
                |payload| match payload {
                    PayloadStructure::PlanPayload(table) => Some(table.clone()),
                    _ => None,
                },
            );
            if let Some(parent_table) = parent_payload {
                let count_table =
                    constant_one_table::<B>(&parent_table, &self.output_column_name_in_parent());
                virtualized_ir
                    .set_payload_for_node(id, Some(PayloadStructure::PlanPayload(count_table)));
                return Ok(());
            }
        }

        let parent_node = self
            .parent
            .as_ref()
            .and_then(|weak_ref| weak_ref.upgrade())
            .expect("AggregateFunction node must have a parent");
        let parent_id = parent_node.id();
        let parent_payload = virtualized_ir.payload_for_node(&parent_id);
        let column_name = self.output_column_name_in_parent();

        let try_build_subtable =
            |table: &arithmetic::table::TrackedTable<B>, column_name: &str| -> Option<_> {
                let col_idx = tracked_table_index_of_name(table, column_name)?;
                Some(table.tracked_subtable_by_indices(&[col_idx]))
            };

        if let Some(PayloadStructure::PlanPayload(table)) = parent_payload
            && let Some(subtable) = try_build_subtable(table, &column_name)
        {
            virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(subtable)));
            return Ok(());
        }

        panic!(
            "AggregateFunction node could not find its column '{}' in parent node {:?}",
            column_name, parent_id
        );
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let parent_node = self
            .parent
            .as_ref()
            .and_then(|weak_ref| weak_ref.upgrade())
            .expect("AggregateFunction node must have a parent");

        let aggr_expr_table = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            Some(PayloadStructure::GadgetPayload(map)) => {
                map.get(INPUT_AGGR_EXPR_LABEL).cloned().unwrap_or_else(|| {
                    panic!("AggregateFunction payload missing INPUT_AGGR_EXPR_LABEL")
                })
            }
            _ => panic!("AggregateFunction payload missing"),
        };

        let (orig_rlc, super_rlc) = if let Some(supp_node) =
            supp_child_from_aggregate_parent(&parent_node)
        {
            let supp_payload = virtualized_ir
                .payload_for_node(&supp_node.id())
                .unwrap_or_else(|| panic!("Supp gadget payload missing for AggregateFunction"));
            let supp_payload = match supp_payload {
                PayloadStructure::GadgetPayload(map) => map,
                _ => panic!("Supp payload must be a GadgetPayload for AggregateFunction"),
            };
            let orig_rlc = supp_payload
                .get(crate::irs::nodes::gadget::utils::supp::ORIG_RLC_LABEL)
                .cloned()
                .unwrap_or_else(|| {
                    panic!("Supp payload missing ORIG_RLC_LABEL for AggregateFunction")
                });
            let super_rlc = supp_payload
                .get(crate::irs::nodes::gadget::utils::supp::SUPER_RLC_LABEL)
                .cloned()
                .unwrap_or_else(|| {
                    panic!("Supp payload missing SUPER_RLC_LABEL for AggregateFunction")
                });
            (orig_rlc, super_rlc)
        } else if self.aggregate_function.func.name() == "sum" {
            // For SUM, the input selector must come from the input table,
            // while the output selector comes from the output table.
            let input_table = self
                .args
                .first()
                .and_then(
                    |arg_node| match virtualized_ir.payload_for_node(&arg_node.id()) {
                        Some(PayloadStructure::PlanPayload(table)) => Some(table.clone()),
                        _ => None,
                    },
                )
                .unwrap_or_else(|| panic!("Sum AggregateFunction expects an input table payload"));
            (
                constant_one_table::<B>(
                    &input_table,
                    crate::irs::nodes::gadget::exprs::aggregate_function::INPUT_RLC_LABEL,
                ),
                constant_one_table::<B>(
                    &aggr_expr_table,
                    crate::irs::nodes::gadget::exprs::aggregate_function::OUTPUT_RLC_LABEL,
                ),
            )
        } else {
            (
                constant_one_table::<B>(
                    &aggr_expr_table,
                    crate::irs::nodes::gadget::exprs::aggregate_function::INPUT_RLC_LABEL,
                ),
                constant_one_table::<B>(
                    &aggr_expr_table,
                    crate::irs::nodes::gadget::exprs::aggregate_function::OUTPUT_RLC_LABEL,
                ),
            )
        };

        if let Some(gadget) = &self.gadget {
            let mut gadget_payload = match virtualized_ir.payload_for_node(&gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };

            for (idx, arg_node) in self.args.iter().enumerate() {
                let arg_payload = virtualized_ir
                    .payload_for_node(&arg_node.id())
                    .unwrap_or_else(|| {
                        panic!("AggregateFunction arg payload missing for arg {}", idx)
                    });
                let arg_table = match arg_payload {
                    PayloadStructure::PlanPayload(table) => table.clone(),
                    _ => panic!(
                        "AggregateFunction arg payload must be PlanPayload for arg {}",
                        idx
                    ),
                };
                gadget_payload.insert(
                    crate::irs::nodes::gadget::exprs::aggregate_function::input_label(idx),
                    arg_table,
                );
            }

            gadget_payload.insert(
                crate::irs::nodes::gadget::exprs::aggregate_function::OUTPUT_LABEL.to_string(),
                aggr_expr_table,
            );
            gadget_payload.insert(
                crate::irs::nodes::gadget::exprs::aggregate_function::INPUT_RLC_LABEL.to_string(),
                orig_rlc,
            );
            gadget_payload.insert(
                crate::irs::nodes::gadget::exprs::aggregate_function::OUTPUT_RLC_LABEL.to_string(),
                super_rlc,
            );

            if !gadget_payload.is_empty() {
                virtualized_ir.set_payload_for_node(
                    gadget.id(),
                    Some(PayloadStructure::GadgetPayload(gadget_payload)),
                );
            }
        }

        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ExprNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        None
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsProverPlanNode<B> for ExprNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let parent_hint_df =
            <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsProverPlanNode<B>>::output(
                &self.parent(),
            );
        let column_name = self.output_column_name_in_parent();
        let input_df = crate::irs::nodes::hints::sort_by_row_id_if_present(
            parent_hint_df.data_frame().clone(),
        )
        .expect("aggregate function row-id sort should succeed");

        let mut exprs = vec![Expr::Column(Column::from_name(column_name))];
        crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut exprs);
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);

        let projected = input_df
            .select(exprs)
            .expect("aggregate function projection should succeed");

        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("aggregate function output sort should succeed");
        crate::irs::nodes::hints::HintDF::new_virtual(projected)
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for ExprNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let parent_hint_df =
            <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                &self.parent(),
            );
        let column_name = self.output_column_name_in_parent();
        let parent_schema = parent_hint_df.data_frame().schema();
        let mut selected_field: Option<Field> = None;
        let mut activator_field: Option<Field> = None;
        let mut row_id_field: Option<Field> = None;
        for field in parent_schema.fields() {
            let field_name = field.name();
            if selected_field.is_none() && field_name == &column_name {
                selected_field = Some(field.as_ref().clone());
            } else if activator_field.is_none() && field_name == arithmetic::ACTIVATOR_COL_NAME {
                activator_field = Some(field.as_ref().clone());
            } else if row_id_field.is_none() && field_name == arithmetic::ROW_ID_COL_NAME {
                row_id_field = Some(field.as_ref().clone());
            }
        }

        let mut fields: Vec<Field> = Vec::new();
        if let Some(field) = selected_field {
            fields.push(field);
        } else {
            panic!(
                "AggregateFunction output could not find column '{}' in parent schema",
                column_name
            );
        }
        if let Some(field) = activator_field {
            fields.push(field);
        }
        if let Some(field) = row_id_field {
            fields.push(field);
        }

        // Verifier planning needs only schema/materialization shape.
        let projected = crate::irs::nodes::hints::schema_only_df(fields);
        crate::irs::nodes::hints::HintDF::new_virtual(projected)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ExprNode<B> {
    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        if self.aggregate_function.func.name() == "count" {
            // Special case for COUNT: reuse lookup super-multiplicities instead of
            // materializing the aggregate output column. This saves a materialization
            // by treating multiplicity as the count result.
            let parent_node = self
                .parent
                .as_ref()
                .and_then(|weak_ref| weak_ref.upgrade())
                .expect("AggregateFunction node must have a parent");
            if let Some(lookup_node) = lookup_child_from_aggregate_parent(&parent_node)
                && let Some(PayloadStructure::GadgetPayload(lookup_payload)) =
                    virtualized_ir.payload_for_node(&lookup_node.id())
                && let Some(multiplicities_table) = lookup_payload
                    .get(crate::irs::nodes::gadget::utils::lookup::SUPER_MULTIPLICITIES_LABEL)
            {
                let count_table = count_table_from_multiplicities_oracle(
                    multiplicities_table,
                    &self.output_column_name_in_parent(),
                );
                // Emit a virtual table named after the COUNT output column, backed by
                // the multiplicity oracle (plus system columns).
                virtualized_ir
                    .set_payload_for_node(id, Some(PayloadStructure::PlanPayload(count_table)));
                return Ok(());
            }
            // If there is no lookup (e.g., COUNT(*) over a base table), fall back to
            // a constant-one oracle aligned with the parent input activator.
            let parent_payload = virtualized_ir.payload_for_node(&parent_node.id()).and_then(
                |payload| match payload {
                    PayloadStructure::PlanPayload(table) => Some(table),
                    _ => None,
                },
            );
            if let Some(parent_table) = parent_payload {
                let count_table = constant_one_table_oracle::<B>(
                    parent_table,
                    &self.output_column_name_in_parent(),
                );
                virtualized_ir
                    .set_payload_for_node(id, Some(PayloadStructure::PlanPayload(count_table)));
                return Ok(());
            }
        }

        let parent_node = self
            .parent
            .as_ref()
            .and_then(|weak_ref| weak_ref.upgrade())
            .expect("AggregateFunction node must have a parent");
        let parent_id = parent_node.id();
        let parent_payload = virtualized_ir.payload_for_node(&parent_id);
        let column_name = self.output_column_name_in_parent();

        let try_build_subtable = |table: &arithmetic::table_oracle::TrackedTableOracle<B>,
                                  column_name: &str| {
            let col_idx = tracked_table_oracle_index_of_name(table, column_name)?;
            Some(table.tracked_subtable_by_indices(&[col_idx]))
        };

        if let Some(PayloadStructure::PlanPayload(table)) = parent_payload
            && let Some(subtable) = try_build_subtable(table, &column_name)
        {
            virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(subtable)));
            return Ok(());
        }

        panic!(
            "AggregateFunction node could not find its column '{}' in parent node {:?}",
            column_name, parent_id
        );
    }
    fn initialize_gadgets(
        &self,
        id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let parent_node = self
            .parent
            .as_ref()
            .and_then(|weak_ref| weak_ref.upgrade())
            .expect("AggregateFunction node must have a parent");

        let aggr_expr_table = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            Some(PayloadStructure::GadgetPayload(map)) => {
                map.get(INPUT_AGGR_EXPR_LABEL).cloned().unwrap_or_else(|| {
                    panic!("AggregateFunction payload missing INPUT_AGGR_EXPR_LABEL")
                })
            }
            _ => panic!("AggregateFunction payload missing"),
        };
        let (orig_rlc, super_rlc) =
            if let Some(supp_node) = supp_child_from_aggregate_parent(&parent_node) {
                let supp_payload = virtualized_ir
                    .payload_for_node(&supp_node.id())
                    .unwrap_or_else(|| panic!("Supp gadget payload missing for AggregateFunction"));
                let supp_payload = match supp_payload {
                    PayloadStructure::GadgetPayload(map) => map,
                    _ => panic!("Supp payload must be a GadgetPayload for AggregateFunction"),
                };
                let orig_rlc = supp_payload
                    .get(crate::irs::nodes::gadget::utils::supp::ORIG_RLC_LABEL)
                    .cloned()
                    .unwrap_or_else(|| {
                        panic!("Supp payload missing ORIG_RLC_LABEL for AggregateFunction")
                    });
                let super_rlc = supp_payload
                    .get(crate::irs::nodes::gadget::utils::supp::SUPER_RLC_LABEL)
                    .cloned()
                    .unwrap_or_else(|| {
                        panic!("Supp payload missing SUPER_RLC_LABEL for AggregateFunction")
                    });
                (orig_rlc, super_rlc)
            } else if self.aggregate_function.func.name() == "sum" {
                // For SUM, the input selector must come from the input table,
                // while the output selector comes from the output table.
                let input_table = self
                    .args
                    .first()
                    .and_then(
                        |arg_node| match virtualized_ir.payload_for_node(&arg_node.id()) {
                            Some(PayloadStructure::PlanPayload(table)) => Some(table.clone()),
                            _ => None,
                        },
                    )
                    .unwrap_or_else(|| {
                        panic!("Sum AggregateFunction expects an input oracle table payload")
                    });
                (
                    constant_one_table_oracle::<B>(
                        &input_table,
                        crate::irs::nodes::gadget::exprs::aggregate_function::INPUT_RLC_LABEL,
                    ),
                    constant_one_table_oracle::<B>(
                        &aggr_expr_table,
                        crate::irs::nodes::gadget::exprs::aggregate_function::OUTPUT_RLC_LABEL,
                    ),
                )
            } else {
                (
                    constant_one_table_oracle::<B>(
                        &aggr_expr_table,
                        crate::irs::nodes::gadget::exprs::aggregate_function::INPUT_RLC_LABEL,
                    ),
                    constant_one_table_oracle::<B>(
                        &aggr_expr_table,
                        crate::irs::nodes::gadget::exprs::aggregate_function::OUTPUT_RLC_LABEL,
                    ),
                )
            };

        if let Some(gadget) = &self.gadget {
            let mut gadget_payload = match virtualized_ir.payload_for_node(&gadget.id()) {
                Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
                _ => IndexMap::new(),
            };

            for (idx, arg_node) in self.args.iter().enumerate() {
                let arg_payload = virtualized_ir
                    .payload_for_node(&arg_node.id())
                    .unwrap_or_else(|| {
                        panic!("AggregateFunction arg payload missing for arg {}", idx)
                    });
                let arg_table = match arg_payload {
                    PayloadStructure::PlanPayload(table) => table.clone(),
                    _ => panic!(
                        "AggregateFunction arg payload must be PlanPayload for arg {}",
                        idx
                    ),
                };
                gadget_payload.insert(
                    crate::irs::nodes::gadget::exprs::aggregate_function::input_label(idx),
                    arg_table,
                );
            }

            gadget_payload.insert(
                crate::irs::nodes::gadget::exprs::aggregate_function::OUTPUT_LABEL.to_string(),
                aggr_expr_table,
            );
            gadget_payload.insert(
                crate::irs::nodes::gadget::exprs::aggregate_function::INPUT_RLC_LABEL.to_string(),
                orig_rlc,
            );
            gadget_payload.insert(
                crate::irs::nodes::gadget::exprs::aggregate_function::OUTPUT_RLC_LABEL.to_string(),
                super_rlc,
            );

            if !gadget_payload.is_empty() {
                virtualized_ir.set_payload_for_node(
                    gadget.id(),
                    Some(PayloadStructure::GadgetPayload(gadget_payload)),
                );
            }
        }
        Ok(())
    }
}

fn supp_child_from_aggregate_parent<B: SnarkBackend>(
    parent_node: &Arc<Node<B>>,
) -> Option<Arc<Node<B>>> {
    let Node::Plan(plan_node) = parent_node.as_ref() else {
        return None;
    };
    let aggregate_gadget = plan_node.gadget()?;
    aggregate_gadget.children().into_iter().next()
}

fn folded_field_from_schema(schema: Option<&Schema>, label: &str) -> FieldRef {
    if let Some(schema) = schema
        && let Some(field) = schema.fields().iter().find(|f| !is_system_column(f.name()))
    {
        return Arc::new(Field::new(
            label,
            field.data_type().clone(),
            field.is_nullable(),
        ));
    }
    Arc::new(Field::new(label, DataType::UInt64, false))
}

fn constant_one_table<B: SnarkBackend>(
    base: &arithmetic::table::TrackedTable<B>,
    label: &str,
) -> arithmetic::table::TrackedTable<B> {
    let tracker = base
        .tracked_polys_iter()
        .next()
        .map(|(_, poly)| poly.tracker())
        .expect("AggregateFunction expects a non-empty table");
    let log_size = base.log_size();
    let one_poly = TrackedPoly::new(Either::Right(B::F::one()), log_size, tracker);

    let data_field = folded_field_from_schema(base.schema_ref(), label);
    let mut tracked_polys = IndexMap::new();
    tracked_polys.insert(data_field.clone(), one_poly);
    if let Some(activator) = base.activator_tracked_poly() {
        tracked_polys.insert(ACTIVATOR_FIELD.clone(), activator);
    }
    arithmetic::table::TrackedTable::new(
        Some(Schema::new(
            tracked_polys
                .keys()
                .map(|field| field.as_ref().clone())
                .collect::<Vec<Field>>(),
        )),
        tracked_polys,
        log_size,
    )
}

fn constant_one_table_oracle<B: SnarkBackend>(
    base: &arithmetic::table_oracle::TrackedTableOracle<B>,
    label: &str,
) -> arithmetic::table_oracle::TrackedTableOracle<B> {
    let tracker = base
        .tracked_oracles_iter()
        .next()
        .map(|(_, oracle)| oracle.tracker())
        .expect("AggregateFunction expects a non-empty oracle table");
    let log_size = base.log_size();
    let one_oracle = TrackedOracle::new(Either::Right(B::F::one()), tracker, log_size);

    let data_field = folded_field_from_schema(base.schema_ref(), label);
    let mut tracked_oracles = IndexMap::new();
    tracked_oracles.insert(data_field.clone(), one_oracle);
    if let Some(activator) = base.activator_tracked_poly() {
        tracked_oracles.insert(ACTIVATOR_FIELD.clone(), activator);
    }
    arithmetic::table_oracle::TrackedTableOracle::new(
        Some(Schema::new(
            tracked_oracles
                .keys()
                .map(|field| field.as_ref().clone())
                .collect::<Vec<Field>>(),
        )),
        tracked_oracles,
        log_size,
    )
}

fn lookup_child_from_aggregate_parent<B: SnarkBackend>(
    parent_node: &Arc<Node<B>>,
) -> Option<Arc<Node<B>>> {
    let supp_node = supp_child_from_aggregate_parent(parent_node)?;
    supp_node
        .children()
        .into_iter()
        .find(|child| child.name() == "Lookup")
}

fn count_table_from_multiplicities<B: SnarkBackend>(
    multiplicities: &arithmetic::table::TrackedTable<B>,
    output_name: &str,
) -> arithmetic::table::TrackedTable<B> {
    let data_indices = multiplicities.data_tracked_polys_indices();
    if data_indices.len() != 1 {
        panic!("Lookup multiplicities must have exactly one data column");
    }
    let multiplicity_col = multiplicities.tracked_col_by_ind(data_indices[0]);
    let multiplicity_field = multiplicity_col
        .field_ref()
        .expect("Lookup multiplicity column should have field metadata");
    let output_field = Arc::new(Field::new(
        output_name,
        multiplicity_field.data_type().clone(),
        multiplicity_field.is_nullable(),
    ));

    let mut polys = IndexMap::new();
    polys.insert(output_field, multiplicity_col.data_tracked_poly());
    for (field, poly) in multiplicities.tracked_polys_iter() {
        if is_system_column(field.name()) {
            polys.entry(field.clone()).or_insert_with(|| poly.clone());
        }
    }

    let schema = multiplicities.schema_ref().map(|schema| {
        let fields = polys
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<Field>>();
        Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    arithmetic::table::TrackedTable::new(schema, polys, multiplicities.log_size())
}

fn count_table_from_multiplicities_oracle<B: SnarkBackend>(
    multiplicities: &arithmetic::table_oracle::TrackedTableOracle<B>,
    output_name: &str,
) -> arithmetic::table_oracle::TrackedTableOracle<B> {
    let data_indices = multiplicities.data_tracked_oracles_indices();
    if data_indices.len() != 1 {
        panic!("Lookup multiplicities must have exactly one data column");
    }
    let multiplicity_col = multiplicities.tracked_col_oracle_by_ind(data_indices[0]);
    let multiplicity_field = multiplicity_col
        .field_ref()
        .expect("Lookup multiplicity column should have field metadata");
    let output_field = Arc::new(Field::new(
        output_name,
        multiplicity_field.data_type().clone(),
        multiplicity_field.is_nullable(),
    ));

    let mut oracles = IndexMap::new();
    oracles.insert(output_field, multiplicity_col.data_tracked_oracle());
    for (field, oracle) in multiplicities.tracked_oracles_iter() {
        if is_system_column(field.name()) {
            oracles
                .entry(field.clone())
                .or_insert_with(|| oracle.clone());
        }
    }

    let schema = multiplicities.schema_ref().map(|schema| {
        let fields = oracles
            .keys()
            .map(|field| field.as_ref().clone())
            .collect::<Vec<Field>>();
        Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    arithmetic::table_oracle::TrackedTableOracle::new(schema, oracles, multiplicities.log_size())
}

fn tracked_table_index_of_name<B: SnarkBackend>(
    table: &arithmetic::table::TrackedTable<B>,
    column_name: &str,
) -> Option<usize> {
    table
        .tracked_polys()
        .iter()
        .position(|(field, _)| field.name() == column_name)
}

fn tracked_table_oracle_index_of_name<B: SnarkBackend>(
    table: &arithmetic::table_oracle::TrackedTableOracle<B>,
    column_name: &str,
) -> Option<usize> {
    table
        .tracked_oracles()
        .iter()
        .position(|(field, _)| field.name() == column_name)
}

impl<B: SnarkBackend> IsExprNode<B> for ExprNode<B> {
    fn from_expr(
        expr: Expr,
        self_ref: std::sync::Weak<Node<B>>,
        parent: Option<std::sync::Weak<Node<B>>>,
        scope: Vec<std::sync::Weak<Node<B>>>,
    ) -> Self
    where
        Self: Sized,
    {
        let aggregate_function = match expr {
            Expr::AggregateFunction(func) => func,
            _ => panic!("Expected AggregateFunction expression"),
        };
        let args = aggregate_function
            .params
            .args
            .iter()
            .map(|expr| {
                Tree::<B>::from_expr(expr, Some(self_ref.clone()), scope.clone())
                    .root()
                    .clone()
            })
            .collect();
        // Dispatch to the appropriate gadget node.
        let gadget = Self::dispatch_gadget(&aggregate_function);
        Self {
            aggregate_function,
            scope,
            parent,
            args,
            gadget,
        }
    }

    fn expr(&self) -> Expr {
        Expr::AggregateFunction(self.aggregate_function.clone())
    }

    fn parent(&self) -> crate::irs::nodes::PlanNode<B>
    where
        Self: Sized,
    {
        self.parent
            .as_ref()
            .and_then(|weak_ref| weak_ref.upgrade())
            .map(|arc_node| match arc_node.as_ref() {
                Node::Plan(plan_node) => plan_node.clone(),
                Node::Gadget(_) => panic!("AggregateFunction parent cannot be a gadget node"),
            })
            .expect("AggregateFunction node must have a parent")
    }

    fn scope(&self) -> Vec<std::sync::Arc<Node<B>>>
    where
        Self: Sized,
    {
        self.scope
            .iter()
            .map(|s| {
                s.upgrade()
                    .expect("ScalarFunction scope should be available")
            })
            .collect()
    }
}
