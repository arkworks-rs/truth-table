use std::{collections::HashSet, sync::Arc};

use arithmetic::ACTIVATOR_EXPR;
use ark_piop::SnarkBackend;
use datafusion_common::{Column, Statistics};
use datafusion_expr::{Expr, LogicalPlan, expr::AggregateFunction};
use indexmap::IndexMap;

use crate::irs::{
    nodes::{
        IsExprNode, IsNode, IsPlanNode, Node, NodeId, PlanNode, ProverNodeOps, VerifierNodeOps,
        gadget::exprs::aggregate_function,
    },
    payloads::PayloadStructure,
};
pub const INPUT_GROUPS_LABEL: &str = "__groups__";
pub const INPUT_AGGR_EXPR_LABEL: &str = "__aggr-expr__";
#[derive(Clone)]
pub struct ProverNode<B: SnarkBackend> {
    pub aggregate_function: AggregateFunction,
    pub scope: Arc<Node<B>>,
    pub parent: Option<std::sync::Weak<Node<B>>>,
    pub gadget: Arc<Node<B>>,
}

impl<B: SnarkBackend> ProverNode<B> {
    fn output_column_name(&self) -> String {
        Expr::AggregateFunction(self.aggregate_function.clone())
            .schema_name()
            .to_string()
    }
    fn dispatch_gadget(aggregate_function: &AggregateFunction) -> Arc<Node<B>> {
        match aggregate_function.func.name() {
            "count" => Arc::new(Node::<B>::Gadget(Arc::new(
                aggregate_function::count::GadgetNode::new(),
            ))),
            _ => panic!("Unsupported aggregate function gadget"),
        }
    }
}

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "AggregateFunction".to_string()
    }

    fn cost(
        &self,
        _statistics: Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

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
        input_exprs.push(ACTIVATOR_EXPR.clone());
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut input_exprs);
        let input_projected = input_df
            .select(dedup_exprs(input_exprs))
            .expect("aggregate function input projection should succeed");
        let input_projected = crate::irs::nodes::hints::sort_by_row_id_if_present(input_projected)
            .expect("aggregate function input sort should succeed");

        let output_df = crate::irs::nodes::hints::sort_by_row_id_if_present(
            output_hint_df.data_frame().clone(),
        )
        .expect("aggregate function output row-id sort should succeed");

        let mut output_exprs = aggregate.group_expr.clone();
        output_exprs.push(Expr::Column(Column::from_name(self.output_column_name())));
        output_exprs.push(ACTIVATOR_EXPR.clone());
        crate::irs::nodes::hints::append_row_id_expr_if_present(&output_df, &mut output_exprs);
        let output_projected = output_df
            .select(dedup_exprs(output_exprs))
            .expect("aggregate function output projection should succeed");
        let output_projected =
            crate::irs::nodes::hints::sort_by_row_id_if_present(output_projected)
                .expect("aggregate function output sort should succeed");

        let input_hint_df = crate::irs::nodes::hints::HintDF::new_virtual(input_projected);
        let output_hint_df = crate::irs::nodes::hints::HintDF::new_virtual(output_projected);

        let mut gadget_payload = match planned_ir.payload_for_node(&id) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        gadget_payload.insert(
            crate::irs::nodes::gadget::exprs::aggregate_function::INPUT_LABEL.to_string(),
            input_hint_df,
        );
        gadget_payload.insert(
            crate::irs::nodes::gadget::exprs::aggregate_function::OUTPUT_LABEL.to_string(),
            output_hint_df,
        );
        planned_ir.set_payload_for_node(id, Some(PayloadStructure::GadgetPayload(gadget_payload)));
        Ok(())
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
        vec![self.gadget.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let parent_node = self
            .parent
            .as_ref()
            .and_then(|weak_ref| weak_ref.upgrade())
            .expect("AggregateFunction node must have a parent");
        let parent_id = parent_node.id();
        let parent_payload = virtualized_ir.payload_for_node(&parent_id);
        let column_name = self.output_column_name();

        let try_build_subtable =
            |table: &arithmetic::table::TrackedTable<B>, column_name: &str| -> Option<_> {
                let schema = table.schema_ref()?;
                let col_idx = schema.index_of(column_name).ok()?;
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
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let parent_node = self
            .parent
            .as_ref()
            .and_then(|weak_ref| weak_ref.upgrade())
            .expect("AggregateFunction node must have a parent");
        let lookup_node = lookup_child_from_aggregate_parent(&parent_node);

        let super_multiplicities = lookup_node.and_then(|lookup_node| {
            virtualized_ir
                .payload_for_node(&lookup_node.id())
                .and_then(|payload| match payload {
                    PayloadStructure::GadgetPayload(map) => map
                        .get(crate::irs::nodes::gadget::utils::lookup::SUPER_MULTIPLICITIES_LABEL)
                        .cloned(),
                    _ => None,
                })
        });

        let aggr_expr_table = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => Some(table.clone()),
            Some(PayloadStructure::GadgetPayload(map)) => {
                map.get(INPUT_AGGR_EXPR_LABEL).cloned()
            }
            _ => None,
        };

        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };

        if let Some(super_multiplicities) = super_multiplicities {
            gadget_payload.insert(
                crate::irs::nodes::gadget::exprs::aggregate_function::count::SUPER_MULTIPLICITIES_LABEL
                    .to_string(),
                super_multiplicities,
            );
        }
        if let Some(aggr_expr_table) = aggr_expr_table {
            gadget_payload.insert(
                crate::irs::nodes::gadget::exprs::aggregate_function::count::COUNT_AGGR_EXPR_LABEL
                    .to_string(),
                aggr_expr_table,
            );
        }

        if !gadget_payload.is_empty() {
            virtualized_ir.set_payload_for_node(
                self.gadget.id(),
                Some(PayloadStructure::GadgetPayload(gadget_payload)),
            );
        }
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ProverNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        None
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let parent_hint_df = self.parent().output();
        let column_name = self.output_column_name();
        let input_df = crate::irs::nodes::hints::sort_by_row_id_if_present(
            parent_hint_df.data_frame().clone(),
        )
        .expect("aggregate function row-id sort should succeed");

        let mut exprs = vec![
            Expr::Column(Column::from_name(column_name)),
            ACTIVATOR_EXPR.clone(),
        ];
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);

        let projected = input_df
            .select(exprs)
            .expect("aggregate function projection should succeed");

        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("aggregate function output sort should succeed");
        crate::irs::nodes::hints::HintDF::new_virtual(projected)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let parent_node = self
            .parent
            .as_ref()
            .and_then(|weak_ref| weak_ref.upgrade())
            .expect("AggregateFunction node must have a parent");
        let parent_id = parent_node.id();
        let parent_payload = virtualized_ir.payload_for_node(&parent_id);
        let column_name = self.output_column_name();

        let try_build_subtable = |table: &arithmetic::table_oracle::TrackedTableOracle<B>,
                                  column_name: &str| {
            let schema = table.schema_ref()?;
            let col_idx = schema.index_of(column_name).ok()?;
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
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let parent_node = self
            .parent
            .as_ref()
            .and_then(|weak_ref| weak_ref.upgrade())
            .expect("AggregateFunction node must have a parent");
        let lookup_node = lookup_child_from_aggregate_parent(&parent_node);

        let super_multiplicities = lookup_node.and_then(|lookup_node| {
            virtualized_ir
                .payload_for_node(&lookup_node.id())
                .and_then(|payload| match payload {
                    PayloadStructure::GadgetPayload(map) => map
                        .get(crate::irs::nodes::gadget::utils::lookup::SUPER_MULTIPLICITIES_LABEL)
                        .cloned(),
                    _ => None,
                })
        });

        let aggr_expr_table = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => Some(table.clone()),
            Some(PayloadStructure::GadgetPayload(map)) => {
                map.get(INPUT_AGGR_EXPR_LABEL).cloned()
            }
            _ => None,
        };

        let mut gadget_payload = match virtualized_ir.payload_for_node(&self.gadget.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };

        if let Some(super_multiplicities) = super_multiplicities {
            gadget_payload.insert(
                crate::irs::nodes::gadget::exprs::aggregate_function::count::SUPER_MULTIPLICITIES_LABEL
                    .to_string(),
                super_multiplicities,
            );
        }
        if let Some(aggr_expr_table) = aggr_expr_table {
            gadget_payload.insert(
                crate::irs::nodes::gadget::exprs::aggregate_function::count::COUNT_AGGR_EXPR_LABEL
                    .to_string(),
                aggr_expr_table,
            );
        }

        if !gadget_payload.is_empty() {
            virtualized_ir.set_payload_for_node(
                self.gadget.id(),
                Some(PayloadStructure::GadgetPayload(gadget_payload)),
            );
        }
        Ok(())
    }
}

fn lookup_child_from_aggregate_parent<B: SnarkBackend>(
    parent_node: &Arc<Node<B>>,
) -> Option<Arc<Node<B>>> {
    let Node::Plan(plan_node) = parent_node.as_ref() else {
        return None;
    };
    let aggregate_gadget = plan_node.gadget()?;
    let supp_node = aggregate_gadget.children().into_iter().next()?;
    supp_node
        .children()
        .into_iter()
        .find(|child| child.name() == "Lookup")
}

impl<B: SnarkBackend> IsExprNode<B> for ProverNode<B> {
    fn from_expr(
        expr: Expr,
        _self_ref: std::sync::Weak<Node<B>>,
        parent: Option<std::sync::Weak<Node<B>>>,
        scope: Arc<Node<B>>,
    ) -> Self
    where
        Self: Sized,
    {
        let aggregate_function = match expr {
            Expr::AggregateFunction(func) => func,
            _ => panic!("Expected AggregateFunction expression"),
        };
        // Dispatch to the appropriate gadget node.
        let gadget = Self::dispatch_gadget(&aggregate_function);
        Self {
            aggregate_function,
            scope,
            parent,
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

    fn scope(&self) -> Arc<Node<B>>
    where
        Self: Sized,
    {
        self.scope.clone()
    }
}
