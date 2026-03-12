// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//! [`OptimizeProjections`] identifies and eliminates unused columns

use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;

use datafusion::optimizer::{ApplyOrder, OptimizerConfig, OptimizerRule};
use datafusion_common::{
    get_required_group_by_exprs_indices, internal_datafusion_err, internal_err, Column, HashMap,
    JoinType, Result,
};
use datafusion_expr::expr::Alias;
use datafusion_expr::expr_rewriter::NamePreserver;
use datafusion_expr::Unnest;
use datafusion_expr::{
    logical_plan::LogicalPlan, projection_schema, Aggregate, Distinct, Expr, Projection, TableScan,
    Window,
};

use datafusion_common::tree_node::{Transformed, TreeNode, TreeNodeContainer, TreeNodeRecursion};

use crate::logical_plan_optimizer::customized_optimize_projections::required_indices::RequiredIndices;

/// Optimizer rule to prune unnecessary columns from intermediate schemas
/// inside the [`LogicalPlan`]. This rule:
/// - Removes unnecessary columns that do not appear at the output and/or are
///   not used during any computation step.
/// - Adds projections to decrease table column size before operators that
///   benefit from a smaller memory footprint at its input.
/// - Removes unnecessary [`LogicalPlan::Projection`]s from the [`LogicalPlan`].
///
/// `OptimizeProjections` is an optimizer rule that identifies and eliminates
/// columns from a logical plan that are not used by downstream operations.
/// This can improve query performance and reduce unnecessary data processing.
///
/// The rule analyzes the input logical plan, determines the necessary column
/// indices, and then removes any unnecessary columns. It also removes any
/// unnecessary projections from the plan tree.
#[derive(Default, Debug)]
pub struct OptimizeProjections {}

impl OptimizeProjections {
    #[allow(missing_docs)]
    pub fn new() -> Self {
        Self {}
    }
}

impl OptimizerRule for OptimizeProjections {
    fn name(&self) -> &str {
        "optimize_projections"
    }

    fn apply_order(&self) -> Option<ApplyOrder> {
        None
    }

    fn supports_rewrite(&self) -> bool {
        true
    }

    fn rewrite(
        &self,
        plan: LogicalPlan,
        config: &dyn OptimizerConfig,
    ) -> Result<Transformed<LogicalPlan>> {
        // All output fields are necessary:
        let indices = RequiredIndices::new_for_all_exprs(&plan);
        optimize_projections(plan, config, indices)
    }
}

/// Removes unnecessary columns (e.g. columns that do not appear in the output
/// schema and/or are not used during any computation step such as expression
/// evaluation) from the logical plan and its inputs.
///
/// # Parameters
///
/// - `plan`: A reference to the input `LogicalPlan` to optimize.
/// - `config`: A reference to the optimizer configuration.
/// - `indices`: A slice of column indices that represent the necessary column
///   indices for downstream (parent) plan nodes.
///
/// # Returns
///
/// A `Result` object with the following semantics:
///
/// - `Ok(Some(LogicalPlan))`: An optimized `LogicalPlan` without unnecessary
///   columns.
/// - `Ok(None)`: Signal that the given logical plan did not require any change.
/// - `Err(error)`: An error occurred during the optimization process.
#[cfg_attr(feature = "recursive_protection", recursive::recursive)]
fn optimize_projections(
    plan: LogicalPlan,
    config: &dyn OptimizerConfig,
    indices: RequiredIndices,
) -> Result<Transformed<LogicalPlan>> {
    // Conservative safety gate for truth-table system columns.
    // This customized rule can over-prune/reorder when __row_id__/__activator__
    // are in play, which later breaks gadget assumptions. We therefore skip
    // this optimization for plan nodes whose output schema already contains
    // system columns, and let the rest of the optimizer pipeline handle them.
    if has_system_columns(plan.schema()) {
        return Ok(Transformed::no(plan));
    }

    let indices = indices.with_system_columns(plan.schema());
    // Recursively rewrite any nodes that may be able to avoid computation given
    // their parents' required indices.
    match plan {
        LogicalPlan::Projection(proj) => {
            return merge_consecutive_projections(proj)?.transform_data(|proj| {
                rewrite_projection_given_requirements(proj, config, &indices)
            })
        }
        LogicalPlan::Aggregate(aggregate) => {
            // Split parent requirements to GROUP BY and aggregate sections:
            let n_group_exprs = aggregate.group_expr_len()?;
            // Offset aggregate indices so that they point to valid indices at
            // `aggregate.aggr_expr`:
            let (group_by_reqs, aggregate_reqs) = indices.split_off(n_group_exprs);

            // Get absolutely necessary GROUP BY fields:
            let group_by_expr_existing = aggregate
                .group_expr
                .iter()
                .map(|group_by_expr| group_by_expr.schema_name().to_string())
                .collect::<Vec<_>>();

            let new_group_bys = if let Some(simplest_groupby_indices) =
                get_required_group_by_exprs_indices(
                    aggregate.input.schema(),
                    &group_by_expr_existing,
                ) {
                // Some of the fields in the GROUP BY may be required by the
                // parent even if these fields are unnecessary in terms of
                // functional dependency.
                group_by_reqs
                    .append(&simplest_groupby_indices)
                    .get_at_indices(&aggregate.group_expr)
            } else {
                aggregate.group_expr
            };

            // Only use the absolutely necessary aggregate expressions required
            // by the parent:
            let mut new_aggr_expr = aggregate_reqs.get_at_indices(&aggregate.aggr_expr);

            // Aggregations always need at least one aggregate expression.
            // With a nested count, we don't require any column as input, but
            // still need to create a correct aggregate, which may be optimized
            // out later. As an example, consider the following query:
            //
            // SELECT count(*) FROM (SELECT count(*) FROM [...])
            //
            // which always returns 1.
            if new_aggr_expr.is_empty()
                && new_group_bys.is_empty()
                && !aggregate.aggr_expr.is_empty()
            {
                // take the old, first aggregate expression
                new_aggr_expr = aggregate.aggr_expr;
                new_aggr_expr.resize_with(1, || unreachable!());
            }

            let all_exprs_iter = new_group_bys.iter().chain(new_aggr_expr.iter());
            let schema = aggregate.input.schema();
            let necessary_indices = RequiredIndices::new().with_exprs(schema, all_exprs_iter);
            let necessary_exprs = necessary_indices.get_required_exprs(schema);

            return optimize_projections(
                Arc::unwrap_or_clone(aggregate.input),
                config,
                necessary_indices,
            )?
            .transform_data(|aggregate_input| {
                // Simplify the input of the aggregation by adding a projection so
                // that its input only contains absolutely necessary columns for
                // the aggregate expressions. Note that necessary_indices refer to
                // fields in `aggregate.input.schema()`.
                add_projection_on_top_if_helpful(aggregate_input, necessary_exprs)
            })?
            .map_data(|aggregate_input| {
                // Create a new aggregate plan with the updated input and only the
                // absolutely necessary fields:
                Aggregate::try_new(Arc::new(aggregate_input), new_group_bys, new_aggr_expr)
                    .map(LogicalPlan::Aggregate)
            });
        }
        LogicalPlan::Window(window) => {
            let input_schema = Arc::clone(window.input.schema());
            // Split parent requirements to child and window expression sections:
            let n_input_fields = input_schema.fields().len();
            // Offset window expression indices so that they point to valid
            // indices at `window.window_expr`:
            let (child_reqs, window_reqs) = indices.split_off(n_input_fields);

            // Only use window expressions that are absolutely necessary according
            // to parent requirements:
            let new_window_expr = window_reqs.get_at_indices(&window.window_expr);

            // Get all the required column indices at the input, either by the
            // parent or window expression requirements.
            let required_indices = child_reqs.with_exprs(&input_schema, &new_window_expr);

            return optimize_projections(
                Arc::unwrap_or_clone(window.input),
                config,
                required_indices.clone(),
            )?
            .transform_data(|window_child| {
                if new_window_expr.is_empty() {
                    // When no window expression is necessary, use the input directly:
                    Ok(Transformed::no(window_child))
                } else {
                    // Calculate required expressions at the input of the window.
                    // Please note that we use `input_schema`, because `required_indices`
                    // refers to that schema
                    let required_exprs = required_indices.get_required_exprs(&input_schema);
                    let window_child =
                        add_projection_on_top_if_helpful(window_child, required_exprs)?.data;
                    Window::try_new(new_window_expr, Arc::new(window_child))
                        .map(LogicalPlan::Window)
                        .map(Transformed::yes)
                }
            });
        }
        LogicalPlan::TableScan(table_scan) => {
            let TableScan {
                table_name,
                source,
                projection,
                filters,
                fetch,
                projected_schema: _,
            } = table_scan;

            // Get indices referred to in the original (schema with all fields)
            // given projected indices.
            let projection = match &projection {
                Some(projection) => indices.into_mapped_indices(|idx| projection[idx]),
                None => indices.into_inner(),
            };
            return TableScan::try_new(table_name, source, Some(projection), filters, fetch)
                .map(LogicalPlan::TableScan)
                .map(Transformed::yes);
        }
        // Other node types are handled below
        _ => {}
    };

    // For other plan node types, calculate indices for columns they use and
    // try to rewrite their children
    let mut child_required_indices: Vec<RequiredIndices> = match &plan {
        LogicalPlan::Sort(_)
        | LogicalPlan::Filter(_)
        | LogicalPlan::Repartition(_)
        | LogicalPlan::Union(_)
        | LogicalPlan::SubqueryAlias(_)
        | LogicalPlan::Distinct(Distinct::On(_)) => {
            // Pass index requirements from the parent as well as column indices
            // that appear in this plan's expressions to its child. All these
            // operators benefit from "small" inputs, so the projection_beneficial
            // flag is `true`.
            plan.inputs()
                .into_iter()
                .map(|input| {
                    indices
                        .clone()
                        .with_projection_beneficial()
                        .with_plan_exprs(&plan, input.schema())
                })
                .collect::<Result<_>>()?
        }
        LogicalPlan::Limit(_) => {
            // Pass index requirements from the parent as well as column indices
            // that appear in this plan's expressions to its child. These operators
            // do not benefit from "small" inputs, so the projection_beneficial
            // flag is `false`.
            plan.inputs()
                .into_iter()
                .map(|input| indices.clone().with_plan_exprs(&plan, input.schema()))
                .collect::<Result<_>>()?
        }
        LogicalPlan::Copy(_)
        | LogicalPlan::Ddl(_)
        | LogicalPlan::Dml(_)
        | LogicalPlan::Explain(_)
        | LogicalPlan::Analyze(_)
        | LogicalPlan::Subquery(_)
        | LogicalPlan::Statement(_)
        | LogicalPlan::Distinct(Distinct::All(_)) => {
            // These plans require all their fields, and their children should
            // be treated as final plans -- otherwise, we may have schema a
            // mismatch.
            // TODO: For some subquery variants (e.g. a subquery arising from an
            //       EXISTS expression), we may not need to require all indices.
            plan.inputs()
                .into_iter()
                .map(RequiredIndices::new_for_all_exprs)
                .collect()
        }
        LogicalPlan::Extension(extension) => {
            let Some(necessary_children_indices) =
                extension.node.necessary_children_exprs(indices.indices())
            else {
                // Requirements from parent cannot be routed down to user defined logical plan safely
                return Ok(Transformed::no(plan));
            };
            let children = extension.node.inputs();
            if children.len() != necessary_children_indices.len() {
                return internal_err!("Inconsistent length between children and necessary children indices. \
                Make sure `.necessary_children_exprs` implementation of the `UserDefinedLogicalNode` is \
                consistent with actual children length for the node.");
            }
            children
                .into_iter()
                .zip(necessary_children_indices)
                .map(|(child, necessary_indices)| {
                    RequiredIndices::new_from_indices(necessary_indices)
                        .with_plan_exprs(&plan, child.schema())
                })
                .collect::<Result<Vec<_>>>()?
        }
        LogicalPlan::EmptyRelation(_)
        | LogicalPlan::RecursiveQuery(_)
        | LogicalPlan::Values(_)
        | LogicalPlan::DescribeTable(_) => {
            // These operators have no inputs, so stop the optimization process.
            return Ok(Transformed::no(plan));
        }
        LogicalPlan::Join(join) => {
            let left_len = join.left.schema().fields().len();
            let (left_req_indices, right_req_indices) =
                split_join_requirements(left_len, indices, &join.join_type);
            let left_indices = left_req_indices.with_plan_exprs(&plan, join.left.schema())?;
            let right_indices = right_req_indices.with_plan_exprs(&plan, join.right.schema())?;
            // Joins benefit from "small" input tables (lower memory usage).
            // Therefore, each child benefits from projection:
            vec![
                left_indices.with_projection_beneficial(),
                right_indices.with_projection_beneficial(),
            ]
        }
        // these nodes are explicitly rewritten in the match statement above
        LogicalPlan::Projection(_)
        | LogicalPlan::Aggregate(_)
        | LogicalPlan::Window(_)
        | LogicalPlan::TableScan(_) => {
            return internal_err!(
                "OptimizeProjection: should have handled in the match statement above"
            );
        }
        LogicalPlan::Unnest(Unnest {
            dependency_indices, ..
        }) => {
            vec![RequiredIndices::new_from_indices(
                dependency_indices.clone(),
            )]
        }
    };

    // Required indices are currently ordered (child0, child1, ...)
    // but the loop pops off the last element, so we need to reverse the order
    child_required_indices.reverse();
    if child_required_indices.len() != plan.inputs().len() {
        return internal_err!(
            "OptimizeProjection: child_required_indices length mismatch with plan inputs"
        );
    }

    // Rewrite children of the plan
    let transformed_plan = plan.map_children(|child| {
        let required_indices = child_required_indices.pop().ok_or_else(|| {
            internal_datafusion_err!(
                "Unexpected number of required_indices in OptimizeProjections rule"
            )
        })?;

        let projection_beneficial = required_indices.projection_beneficial();
        let project_exprs = required_indices.get_required_exprs(child.schema());

        optimize_projections(child, config, required_indices)?.transform_data(|new_input| {
            if projection_beneficial {
                add_projection_on_top_if_helpful(new_input, project_exprs)
            } else {
                Ok(Transformed::no(new_input))
            }
        })
    })?;

    // If any of the children are transformed, we need to potentially update the plan's schema
    if transformed_plan.transformed {
        transformed_plan.map_data(|plan| plan.recompute_schema())
    } else {
        Ok(transformed_plan)
    }
}

fn has_system_columns(schema: &datafusion_common::DFSchemaRef) -> bool {
    schema.fields().iter().any(|f| {
        let name = f.name();
        name == "__activator__" || name == "__row_id__"
    })
}

/// Merges consecutive projections.
///
/// Given a projection `proj`, this function attempts to merge it with a previous
/// projection if it exists and if merging is beneficial. Merging is considered
/// beneficial when expressions in the current projection are non-trivial and
/// appear more than once in its input fields. This can act as a caching mechanism
/// for non-trivial computations.
///
/// # Parameters
///
/// * `proj` - A reference to the `Projection` to be merged.
///
/// # Returns
///
/// A `Result` object with the following semantics:
///
/// - `Ok(Some(Projection))`: Merge was beneficial and successful. Contains the
///   merged projection.
/// - `Ok(None)`: Signals that merge is not beneficial (and has not taken place).
/// - `Err(error)`: An error occurred during the function call.
fn merge_consecutive_projections(proj: Projection) -> Result<Transformed<Projection>> {
    let Projection {
        expr,
        input,
        schema,
        ..
    } = proj;
    let LogicalPlan::Projection(prev_projection) = input.as_ref() else {
        return Projection::try_new_with_schema(expr, input, schema).map(Transformed::no);
    };

    // Count usages (referrals) of each projection expression in its input fields:
    let mut column_referral_map = HashMap::<&Column, usize>::new();
    expr.iter()
        .for_each(|expr| expr.add_column_ref_counts(&mut column_referral_map));

    // If an expression is non-trivial and appears more than once, do not merge
    // them as consecutive projections will benefit from a compute-once approach.
    // For details, see: https://github.com/apache/datafusion/issues/8296
    if column_referral_map.into_iter().any(|(col, usage)| {
        usage > 1
            && !is_expr_trivial(
                &prev_projection.expr[prev_projection.schema.index_of_column(col).unwrap()],
            )
    }) {
        // no change
        return Projection::try_new_with_schema(expr, input, schema).map(Transformed::no);
    }

    let LogicalPlan::Projection(prev_projection) = Arc::unwrap_or_clone(input) else {
        // We know it is a `LogicalPlan::Projection` from check above
        unreachable!();
    };

    // Try to rewrite the expressions in the current projection using the
    // previous projection as input:
    let name_preserver = NamePreserver::new_for_projection();
    let mut original_names = vec![];
    let new_exprs = expr.map_elements(|expr| {
        original_names.push(name_preserver.save(&expr));

        // do not rewrite top level Aliases (rewriter will remove all aliases within exprs)
        match expr {
            Expr::Alias(Alias {
                expr,
                relation,
                name,
            }) => rewrite_expr(*expr, &prev_projection).map(|result| {
                result.update_data(|expr| Expr::Alias(Alias::new(expr, relation, name)))
            }),
            e => rewrite_expr(e, &prev_projection),
        }
    })?;

    // if the expressions could be rewritten, create a new projection with the
    // new expressions
    if new_exprs.transformed {
        // Add any needed aliases back to the expressions
        let new_exprs = new_exprs
            .data
            .into_iter()
            .zip(original_names)
            .map(|(expr, original_name)| original_name.restore(expr))
            .collect::<Vec<_>>();
        Projection::try_new(new_exprs, prev_projection.input).map(Transformed::yes)
    } else {
        // not rewritten, so put the projection back together
        let input = Arc::new(LogicalPlan::Projection(prev_projection));
        Projection::try_new_with_schema(new_exprs.data, input, schema).map(Transformed::no)
    }
}

// Check whether `expr` is trivial; i.e. it doesn't imply any computation.
fn is_expr_trivial(expr: &Expr) -> bool {
    matches!(expr, Expr::Column(_) | Expr::Literal(_))
}

/// Rewrites a projection expression using the projection before it (i.e. its input)
/// This is a subroutine to the `merge_consecutive_projections` function.
///
/// # Parameters
///
/// * `expr` - A reference to the expression to rewrite.
/// * `input` - A reference to the input of the projection expression (itself
///   a projection).
///
/// # Returns
///
/// A `Result` object with the following semantics:
///
/// - `Ok(Some(Expr))`: Rewrite was successful. Contains the rewritten result.
/// - `Ok(None)`: Signals that `expr` can not be rewritten.
/// - `Err(error)`: An error occurred during the function call.
///
/// # Notes
/// This rewrite also removes any unnecessary layers of aliasing.
///
/// Without trimming, we can end up with unnecessary indirections inside expressions
/// during projection merges.
///
/// Consider:
///
/// ```text
/// Projection(a1 + b1 as sum1)
/// --Projection(a as a1, b as b1)
/// ----Source(a, b)
/// ```
///
/// After merge, we want to produce:
///
/// ```text
/// Projection(a + b as sum1)
/// --Source(a, b)
/// ```
///
/// Without trimming, we would end up with:
///
/// ```text
/// Projection((a as a1 + b as b1) as sum1)
/// --Source(a, b)
/// ```
fn rewrite_expr(expr: Expr, input: &Projection) -> Result<Transformed<Expr>> {
    expr.transform_up(|expr| {
        match expr {
            //  remove any intermediate aliases
            Expr::Alias(alias) => Ok(Transformed::yes(*alias.expr)),
            Expr::Column(col) => {
                // Find index of column:
                let idx = input.schema.index_of_column(&col)?;
                // get the corresponding unaliased input expression
                //
                // For example:
                // * the input projection is [`a + b` as c, `d + e` as f]
                // * the current column is an expression "f"
                //
                // return the expression `d + e` (not `d + e` as f)
                let input_expr = input.expr[idx].clone().unalias_nested().data;
                Ok(Transformed::yes(input_expr))
            }
            // Unsupported type for consecutive projection merge analysis.
            _ => Ok(Transformed::no(expr)),
        }
    })
}

/// Accumulates outer-referenced columns by the
/// given expression, `expr`.
///
/// # Parameters
///
/// * `expr` - The expression to analyze for outer-referenced columns.
/// * `columns` - A mutable reference to a `BTreeSet<Column>` where detected
///   columns are collected.
fn outer_columns<'a>(expr: &'a Expr, columns: &mut BTreeSet<&'a Column>) {
    // inspect_expr_pre doesn't handle subquery references, so find them explicitly
    expr.apply(|expr| {
        match expr {
            Expr::OuterReferenceColumn(_, col) => {
                columns.insert(col);
            }
            Expr::ScalarSubquery(subquery) => {
                outer_columns_helper_multi(&subquery.outer_ref_columns, columns);
            }
            Expr::Exists(exists) => {
                outer_columns_helper_multi(&exists.subquery.outer_ref_columns, columns);
            }
            Expr::InSubquery(insubquery) => {
                outer_columns_helper_multi(&insubquery.subquery.outer_ref_columns, columns);
            }
            _ => {}
        };
        Ok(TreeNodeRecursion::Continue)
    })
    // unwrap: closure above never returns Err, so can not be Err here
    .unwrap();
}

/// A recursive subroutine that accumulates outer-referenced columns by the
/// given expressions (`exprs`).
///
/// # Parameters
///
/// * `exprs` - The expressions to analyze for outer-referenced columns.
/// * `columns` - A mutable reference to a `BTreeSet<Column>` where detected
///   columns are collected.
fn outer_columns_helper_multi<'a, 'b>(
    exprs: impl IntoIterator<Item = &'a Expr>,
    columns: &'b mut BTreeSet<&'a Column>,
) {
    exprs.into_iter().for_each(|e| outer_columns(e, columns));
}

/// Splits requirement indices for a join into left and right children based on
/// the join type.
///
/// This function takes the length of the left child, a slice of requirement
/// indices, and the type of join (e.g. `INNER`, `LEFT`, `RIGHT`) as arguments.
/// Depending on the join type, it divides the requirement indices into those
/// that apply to the left child and those that apply to the right child.
///
/// - For `INNER`, `LEFT`, `RIGHT` and `FULL` joins, the requirements are split
///   between left and right children. The right child indices are adjusted to
///   point to valid positions within the right child by subtracting the length
///   of the left child.
///
/// - For `LEFT ANTI`, `LEFT SEMI`, `RIGHT SEMI` and `RIGHT ANTI` joins, all
///   requirements are re-routed to either the left child or the right child
///   directly, depending on the join type.
///
/// # Parameters
///
/// * `left_len` - The length of the left child.
/// * `indices` - A slice of requirement indices.
/// * `join_type` - The type of join (e.g. `INNER`, `LEFT`, `RIGHT`).
///
/// # Returns
///
/// A tuple containing two vectors of `usize` indices: The first vector represents
/// the requirements for the left child, and the second vector represents the
/// requirements for the right child. The indices are appropriately split and
/// adjusted based on the join type.
fn split_join_requirements(
    left_len: usize,
    indices: RequiredIndices,
    join_type: &JoinType,
) -> (RequiredIndices, RequiredIndices) {
    match join_type {
        // In these cases requirements are split between left/right children:
        JoinType::Inner
        | JoinType::Left
        | JoinType::Right
        | JoinType::Full
        | JoinType::LeftMark => {
            // Decrease right side indices by `left_len` so that they point to valid
            // positions within the right child:
            indices.split_off(left_len)
        }
        // All requirements can be re-routed to left child directly.
        JoinType::LeftAnti | JoinType::LeftSemi => (indices, RequiredIndices::new()),
        // All requirements can be re-routed to right side directly.
        // No need to change index, join schema is right child schema.
        JoinType::RightSemi | JoinType::RightAnti => (RequiredIndices::new(), indices),
    }
}

/// Adds a projection on top of a logical plan if doing so reduces the number
/// of columns for the parent operator.
///
/// This function takes a `LogicalPlan` and a list of projection expressions.
/// If the projection is beneficial (it reduces the number of columns in the
/// plan) a new `LogicalPlan` with the projection is created and returned, along
/// with a `true` flag. If the projection doesn't reduce the number of columns,
/// the original plan is returned with a `false` flag.
///
/// # Parameters
///
/// * `plan` - The input `LogicalPlan` to potentially add a projection to.
/// * `project_exprs` - A list of expressions for the projection.
///
/// # Returns
///
/// A `Transformed` indicating if a projection was added
fn add_projection_on_top_if_helpful(
    plan: LogicalPlan,
    project_exprs: Vec<Expr>,
) -> Result<Transformed<LogicalPlan>> {
    // Make sure projection decreases the number of columns, otherwise it is unnecessary.
    if project_exprs.len() >= plan.schema().fields().len() {
        Ok(Transformed::no(plan))
    } else {
        Projection::try_new(project_exprs, Arc::new(plan))
            .map(LogicalPlan::Projection)
            .map(Transformed::yes)
    }
}

/// Rewrite the given projection according to the fields required by its
/// ancestors.
///
/// # Parameters
///
/// * `proj` - A reference to the original projection to rewrite.
/// * `config` - A reference to the optimizer configuration.
/// * `indices` - A slice of indices representing the columns required by the
///   ancestors of the given projection.
///
/// # Returns
///
/// A `Result` object with the following semantics:
///
/// - `Ok(Some(LogicalPlan))`: Contains the rewritten projection
/// - `Ok(None)`: No rewrite necessary.
/// - `Err(error)`: An error occurred during the function call.
fn rewrite_projection_given_requirements(
    proj: Projection,
    config: &dyn OptimizerConfig,
    indices: &RequiredIndices,
) -> Result<Transformed<LogicalPlan>> {
    let Projection { expr, input, .. } = proj;

    let exprs_used = indices.get_at_indices(&expr);

    let required_indices = RequiredIndices::new().with_exprs(input.schema(), exprs_used.iter());

    // rewrite the children projection, and if they are changed rewrite the
    // projection down
    optimize_projections(Arc::unwrap_or_clone(input), config, required_indices)?.transform_data(
        |input| {
            if is_projection_unnecessary(&input, &exprs_used)? {
                Ok(Transformed::yes(input))
            } else {
                Projection::try_new(exprs_used, Arc::new(input))
                    .map(LogicalPlan::Projection)
                    .map(Transformed::yes)
            }
        },
    )
}

/// Projection is unnecessary, when
/// - input schema of the projection, output schema of the projection are same, and
/// - all projection expressions are either Column or Literal
fn is_projection_unnecessary(input: &LogicalPlan, proj_exprs: &[Expr]) -> Result<bool> {
    let proj_schema = projection_schema(input, proj_exprs)?;
    Ok(&proj_schema == input.schema() && proj_exprs.iter().all(is_expr_trivial))
}

mod required_indices {
    // Licensed to the Apache Software Foundation (ASF) under one
    // or more contributor license agreements.  See the NOTICE file
    // distributed with this work for additional information
    // regarding copyright ownership.  The ASF licenses this file
    // to you under the Apache License, Version 2.0 (the
    // "License"); you may not use this file except in compliance
    // with the License.  You may obtain a copy of the License at
    //
    //   http://www.apache.org/licenses/LICENSE-2.0
    //
    // Unless required by applicable law or agreed to in writing,
    // software distributed under the License is distributed on an
    // "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    // KIND, either express or implied.  See the License for the
    // specific language governing permissions and limitations
    // under the License.

    //! [`RequiredIndices`] helper for OptimizeProjection

    use super::outer_columns;
    use datafusion_common::tree_node::TreeNodeRecursion;
    use datafusion_common::{Column, DFSchemaRef, Result};
    use datafusion_expr::{Expr, LogicalPlan};

    const ACTIVATOR_COL_NAME: &str = "__activator__";
    const ROW_ID_COL_NAME: &str = "__row_id__";

    /// Represents columns in a schema which are required (used) by a plan node
    ///
    /// Also carries a flag indicating if putting a projection above children is
    /// beneficial for the parent. For example `LogicalPlan::Filter` benefits from
    /// small tables. Hence for filter child this flag would be `true`. Defaults to
    /// `false`
    ///
    /// # Invariant
    ///
    /// Indices are always in order and without duplicates. For example, if these
    /// indices were added `[3, 2, 4, 3, 6, 1]`,  the instance would be represented
    /// by  `[1, 2, 3, 4, 6]`.
    #[derive(Debug, Clone, Default)]
    pub(super) struct RequiredIndices {
        /// The indices of the required columns in the
        indices: Vec<usize>,
        /// If putting a projection above children is beneficial for the parent.
        /// Defaults to false.
        projection_beneficial: bool,
    }

    impl RequiredIndices {
        /// Create a new, empty instance
        pub fn new() -> Self {
            Self::default()
        }

        /// Create a new instance that requires all columns from the specified plan
        pub fn new_for_all_exprs(plan: &LogicalPlan) -> Self {
            Self {
                indices: (0..plan.schema().fields().len()).collect(),
                projection_beneficial: false,
            }
        }

        /// Create a new instance with the specified indices as required
        pub fn new_from_indices(indices: Vec<usize>) -> Self {
            Self {
                indices,
                projection_beneficial: false,
            }
            .compact()
        }

        /// Convert the instance to its inner indices
        pub fn into_inner(self) -> Vec<usize> {
            self.indices
        }

        /// Set the projection beneficial flag
        pub fn with_projection_beneficial(mut self) -> Self {
            self.projection_beneficial = true;
            self
        }

        /// Return the value of projection beneficial flag
        pub fn projection_beneficial(&self) -> bool {
            self.projection_beneficial
        }

        /// Return a reference to the underlying indices
        pub fn indices(&self) -> &[usize] {
            &self.indices
        }

        /// Add required indices for all `exprs` used in plan
        pub fn with_plan_exprs(mut self, plan: &LogicalPlan, schema: &DFSchemaRef) -> Result<Self> {
            // Add indices of the child fields referred to by the expressions in the
            // parent
            plan.apply_expressions(|e| {
                self.add_expr(schema, e);
                Ok(TreeNodeRecursion::Continue)
            })?;
            // Do not force child system columns here: this method computes
            // *expression-derived* child requirements. Injecting row/activator
            // columns at every edge can add unintended payload columns and break
            // downstream gadget assumptions.
            Ok(self.compact())
        }

        /// Adds the indices of the fields referred to by the given expression
        /// `expr` within the given schema (`input_schema`).
        ///
        /// Self is NOT compacted (and thus this method is not pub)
        ///
        /// # Parameters
        ///
        /// * `input_schema`: The input schema to analyze for index requirements.
        /// * `expr`: An expression for which we want to find necessary field indices.
        fn add_expr(&mut self, input_schema: &DFSchemaRef, expr: &Expr) {
            // TODO could remove these clones (and visit the expression directly)
            let mut cols: std::collections::BTreeSet<&Column> =
                expr.column_refs().into_iter().collect();
            // Get outer-referenced (subquery) columns:
            outer_columns(expr, &mut cols);
            self.indices.reserve(cols.len());
            for col in cols {
                if let Some(idx) = input_schema.maybe_index_of_column(col) {
                    self.indices.push(idx);
                }
            }
        }

        /// Adds the indices of the fields referred to by the given expressions
        /// `within the given schema.
        ///
        /// # Parameters
        ///
        /// * `input_schema`: The input schema to analyze for index requirements.
        /// * `exprs`: the expressions for which we want to find field indices.
        pub fn with_exprs<'a>(
            self,
            schema: &DFSchemaRef,
            exprs: impl IntoIterator<Item = &'a Expr>,
        ) -> Self {
            exprs
                .into_iter()
                .fold(self, |mut acc, expr| {
                    acc.add_expr(schema, expr);
                    acc
                })
                // Keep this as a pure expression-to-index mapping.
                // System columns are injected only when preserving the current
                // node output schema (via `with_system_columns`).
                .compact()
        }

        /// Adds all `indices` into this instance.
        pub fn append(mut self, indices: &[usize]) -> Self {
            self.indices.extend_from_slice(indices);
            self.compact()
        }

        /// Ensure system columns are always retained when present in the schema.
        pub fn with_system_columns(self, schema: &DFSchemaRef) -> Self {
            self.add_system_columns(schema).compact()
        }

        /// Ensure system columns are always retained when present in the schema.
        fn add_system_columns(mut self, schema: &DFSchemaRef) -> Self {
            for (idx, field) in schema.fields().iter().enumerate() {
                let name = field.name();
                if name == ACTIVATOR_COL_NAME || name == ROW_ID_COL_NAME {
                    self.indices.push(idx);
                }
            }
            self
        }

        /// Splits this instance into a tuple with two instances:
        /// * The first `n` indices
        /// * The remaining indices, adjusted down by n
        pub fn split_off(self, n: usize) -> (Self, Self) {
            let (l, r) = self.partition(|idx| idx < n);
            (l, r.map_indices(|idx| idx - n))
        }

        /// Partitions the indices in this instance into two groups based on the
        /// given predicate function `f`.
        fn partition<F>(&self, f: F) -> (Self, Self)
        where
            F: Fn(usize) -> bool,
        {
            let (l, r): (Vec<usize>, Vec<usize>) = self.indices.iter().partition(|&&idx| f(idx));
            let projection_beneficial = self.projection_beneficial;

            (
                Self {
                    indices: l,
                    projection_beneficial,
                },
                Self {
                    indices: r,
                    projection_beneficial,
                },
            )
        }

        /// Map the indices in this instance to a new set of indices based on the
        /// given function `f`, returning the mapped indices
        ///
        /// Not `pub` as it might not preserve the invariant of compacted indices
        fn map_indices<F>(mut self, f: F) -> Self
        where
            F: Fn(usize) -> usize,
        {
            self.indices.iter_mut().for_each(|idx| *idx = f(*idx));
            self
        }

        /// Apply the given function `f` to each index in this instance, returning
        /// the mapped indices
        pub fn into_mapped_indices<F>(self, f: F) -> Vec<usize>
        where
            F: Fn(usize) -> usize,
        {
            self.map_indices(f).into_inner()
        }

        /// Returns the `Expr`s from `exprs` that are at the indices in this instance
        pub fn get_at_indices(&self, exprs: &[Expr]) -> Vec<Expr> {
            self.indices.iter().map(|&idx| exprs[idx].clone()).collect()
        }

        /// Generates the required expressions (columns) that reside at `indices` of
        /// the given `input_schema`.
        pub fn get_required_exprs(&self, input_schema: &DFSchemaRef) -> Vec<Expr> {
            self.indices
                .iter()
                .map(|&idx| Expr::from(Column::from(input_schema.qualified_field(idx))))
                .collect()
        }

        /// Compacts the indices of this instance so they are sorted
        /// (ascending) and deduplicated.
        fn compact(mut self) -> Self {
            self.indices.sort_unstable();
            self.indices.dedup();
            self
        }
    }
}
