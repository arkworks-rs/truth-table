use std::{collections::HashSet, sync::Arc};

use arithmetic::is_system_column;
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{Field, Schema};
use datafusion_common::{Column, Statistics};
use datafusion_expr::{Expr, LogicalPlan, expr::AggregateFunction};
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
pub struct ProverNode<B: SnarkBackend> {
    pub aggregate_function: AggregateFunction,
    pub scope: Arc<Node<B>>,
    pub parent: Option<std::sync::Weak<Node<B>>>,
    pub args: Vec<Arc<Node<B>>>,
    pub gadget: Option<Arc<Node<B>>>,
}

impl<B: SnarkBackend> ProverNode<B> {
    fn output_column_name(&self) -> String {
        Expr::AggregateFunction(self.aggregate_function.clone())
            .schema_name()
            .to_string()
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

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
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
            self.scope.name(),
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
        output_exprs.push(Expr::Column(Column::from_name(self.output_column_name())));
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

    fn children(&self) -> Vec<Arc<Node<B>>> {
        let mut children = self.args.clone();
        if let Some(gadget) = &self.gadget {
            children.push(gadget.clone());
        }
        children
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ProverNode<B> {
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
            let lookup_node = lookup_child_from_aggregate_parent(&parent_node)
                .expect("AggregateFunction expects a Lookup child under the Supp gadget");
            let lookup_payload = virtualized_ir
                .payload_for_node(&lookup_node.id())
                .unwrap_or_else(|| panic!("Lookup gadget payload missing for AggregateFunction"));
            let lookup_payload = match lookup_payload {
                PayloadStructure::GadgetPayload(map) => map,
                _ => panic!("Lookup payload must be a GadgetPayload for AggregateFunction"),
            };
            let multiplicities_table = lookup_payload
                .get(crate::irs::nodes::gadget::utils::lookup::SUPER_MULTIPLICITIES_LABEL)
                .cloned()
                .unwrap_or_else(|| {
                    panic!(
                        "Lookup payload missing SUPER_MULTIPLICITIES_LABEL for AggregateFunction"
                    )
                });

            let count_table =
                count_table_from_multiplicities(&multiplicities_table, &self.output_column_name());
            // Emit a virtual table named after the COUNT output column, backed by
            // the multiplicity polynomial (plus system columns).
            virtualized_ir
                .set_payload_for_node(id, Some(PayloadStructure::PlanPayload(count_table)));
            return Ok(());
        }

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
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let parent_node = self
            .parent
            .as_ref()
            .and_then(|weak_ref| weak_ref.upgrade())
            .expect("AggregateFunction node must have a parent");

        let supp_node = supp_child_from_aggregate_parent(&parent_node)
            .expect("AggregateFunction expects a Supp gadget child under the Aggregate gadget");

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
            .unwrap_or_else(|| panic!("Supp payload missing ORIG_RLC_LABEL for AggregateFunction"));
        let super_rlc = supp_payload
            .get(crate::irs::nodes::gadget::utils::supp::SUPER_RLC_LABEL)
            .cloned()
            .unwrap_or_else(|| {
                panic!("Supp payload missing SUPER_RLC_LABEL for AggregateFunction")
            });

        let aggr_expr_table = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            Some(PayloadStructure::GadgetPayload(map)) => {
                map.get(INPUT_AGGR_EXPR_LABEL).cloned().unwrap_or_else(|| {
                    panic!("AggregateFunction payload missing INPUT_AGGR_EXPR_LABEL")
                })
            }
            _ => panic!("AggregateFunction payload missing"),
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

impl<B: SnarkBackend> VerifierNodeOps<B> for ProverNode<B> {
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
            let lookup_node = lookup_child_from_aggregate_parent(&parent_node)
                .expect("AggregateFunction expects a Lookup child under the Supp gadget");
            let lookup_payload = virtualized_ir
                .payload_for_node(&lookup_node.id())
                .unwrap_or_else(|| panic!("Lookup gadget payload missing for AggregateFunction"));
            let lookup_payload = match lookup_payload {
                PayloadStructure::GadgetPayload(map) => map,
                _ => panic!("Lookup payload must be a GadgetPayload for AggregateFunction"),
            };
            let multiplicities_table = lookup_payload
                .get(crate::irs::nodes::gadget::utils::lookup::SUPER_MULTIPLICITIES_LABEL)
                .cloned()
                .unwrap_or_else(|| {
                    panic!(
                        "Lookup payload missing SUPER_MULTIPLICITIES_LABEL for AggregateFunction"
                    )
                });

            let count_table = count_table_from_multiplicities_oracle(
                &multiplicities_table,
                &self.output_column_name(),
            );
            // Emit a virtual table named after the COUNT output column, backed by
            // the multiplicity oracle (plus system columns).
            virtualized_ir
                .set_payload_for_node(id, Some(PayloadStructure::PlanPayload(count_table)));
            return Ok(());
        }

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
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let parent_node = self
            .parent
            .as_ref()
            .and_then(|weak_ref| weak_ref.upgrade())
            .expect("AggregateFunction node must have a parent");

        let supp_node = supp_child_from_aggregate_parent(&parent_node)
            .expect("AggregateFunction expects a Supp gadget child under the Aggregate gadget");

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
            .unwrap_or_else(|| panic!("Supp payload missing ORIG_RLC_LABEL for AggregateFunction"));
        let super_rlc = supp_payload
            .get(crate::irs::nodes::gadget::utils::supp::SUPER_RLC_LABEL)
            .cloned()
            .unwrap_or_else(|| {
                panic!("Supp payload missing SUPER_RLC_LABEL for AggregateFunction")
            });

        let aggr_expr_table = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            Some(PayloadStructure::GadgetPayload(map)) => {
                map.get(INPUT_AGGR_EXPR_LABEL).cloned().unwrap_or_else(|| {
                    panic!("AggregateFunction payload missing INPUT_AGGR_EXPR_LABEL")
                })
            }
            _ => panic!("AggregateFunction payload missing"),
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

impl<B: SnarkBackend> IsExprNode<B> for ProverNode<B> {
    fn from_expr(
        expr: Expr,
        self_ref: std::sync::Weak<Node<B>>,
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

    fn scope(&self) -> Arc<Node<B>>
    where
        Self: Sized,
    {
        self.scope.clone()
    }
}
