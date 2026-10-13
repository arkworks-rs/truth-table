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

//! [`OptimizeProjections`] identifies and eliminates unused columns.
//!
//! A copy of DataFusion 46.0.1's `optimize_projections` rule, kept close to
//! upstream so the two can be diffed. Our change: every node keeps the system
//! columns (`__activator__`, `__row_id__`) of its own output schema, see
//! `RequiredIndices::with_system_columns`.

use std::collections::BTreeSet;
use std::sync::Arc;

use datafusion::optimizer::{ApplyOrder, OptimizerConfig, OptimizerRule};
use datafusion_common::{
    Column, HashMap, JoinType, Result, get_required_group_by_exprs_indices,
    internal_datafusion_err, internal_err,
};
use datafusion_expr::Unnest;
use datafusion_expr::expr::Alias;
use datafusion_expr::expr_rewriter::NamePreserver;
use datafusion_expr::{
    Aggregate, Distinct, Expr, Projection, TableScan, Window, logical_plan::LogicalPlan,
    projection_schema,
};

use datafusion_common::tree_node::{Transformed, TreeNode, TreeNodeContainer, TreeNodeRecursion};

use crate::lp_optimizer::customized_optimize_projections::required_indices::RequiredIndices;

/// Prunes unnecessary columns from intermediate schemas of the
/// [`LogicalPlan`]:
/// - removes columns that neither appear at the output nor are used by any
///   computation step;
/// - adds projections before operators that benefit from a narrower input;
/// - removes unnecessary [`LogicalPlan::Projection`]s.
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

/// Removes unnecessary columns from `plan` and its inputs. `indices` are the
/// columns of `plan`'s output that its parent requires.
fn optimize_projections(
    plan: LogicalPlan,
    config: &dyn OptimizerConfig,
    indices: RequiredIndices,
) -> Result<Transformed<LogicalPlan>> {
    let indices = indices.with_system_columns(plan.schema());
    // Recursively rewrite any nodes that may be able to avoid computation given
    // their parents' required indices.
    match plan {
        LogicalPlan::Projection(proj) => {
            return merge_consecutive_projections(proj)?.transform_data(|proj| {
                rewrite_projection_given_requirements(proj, config, &indices)
            });
        }
        LogicalPlan::Aggregate(aggregate) => {
            // Split parent requirements to GROUP BY and aggregate sections:
            let n_group_exprs = aggregate.group_expr_len()?;
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

            let mut new_aggr_expr = aggregate_reqs.get_at_indices(&aggregate.aggr_expr);

            // An aggregation needs at least one aggregate expression. A nested
            // count such as `SELECT count(*) FROM (SELECT count(*) FROM [...])`
            // requires no input column, so keep the first expression.
            if new_aggr_expr.is_empty()
                && new_group_bys.is_empty()
                && !aggregate.aggr_expr.is_empty()
            {
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
                // `necessary_exprs` refer to fields in `aggregate.input.schema()`.
                add_projection_on_top_if_helpful(aggregate_input, necessary_exprs)
            })?
            .map_data(|aggregate_input| {
                Aggregate::try_new(Arc::new(aggregate_input), new_group_bys, new_aggr_expr)
                    .map(LogicalPlan::Aggregate)
            });
        }
        LogicalPlan::Window(window) => {
            let input_schema = Arc::clone(window.input.schema());
            // Split parent requirements to child and window expression sections:
            let n_input_fields = input_schema.fields().len();
            let (child_reqs, window_reqs) = indices.split_off(n_input_fields);

            let new_window_expr = window_reqs.get_at_indices(&window.window_expr);

            // Input columns required by the parent or by the window expressions.
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
                    // `required_indices` refers to `input_schema`.
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

            // Map the projected indices back to the schema with all fields.
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
            // The child gets the parent's requirements plus the columns in this
            // plan's expressions. These operators benefit from "small" inputs,
            // so the projection_beneficial flag is `true`.
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
            // As above, but Limit does not benefit from "small" inputs, so the
            // projection_beneficial flag stays `false`.
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
            // These plans require all their fields, and their children are
            // treated as final plans; otherwise the schemas may mismatch.
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
                return internal_err!(
                    "Inconsistent length between children and necessary children indices. \
                Make sure `.necessary_children_exprs` implementation of the `UserDefinedLogicalNode` is \
                consistent with actual children length for the node."
                );
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
            // Joins benefit from "small" input tables, so each child benefits
            // from projection:
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

/// Merges `proj` into the projection below it, when there is one and merging
/// does not duplicate a non-trivial computation.
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

/// Rewrites a projection expression in terms of `input`, the projection below
/// it, and removes the intermediate aliases: `Projection(a1 + b1 as sum1)`
/// over `Projection(a as a1, b as b1)` becomes `Projection(a + b as sum1)`,
/// not `Projection((a as a1 + b as b1) as sum1)`.
fn rewrite_expr(expr: Expr, input: &Projection) -> Result<Transformed<Expr>> {
    expr.transform_up(|expr| {
        match expr {
            Expr::Alias(alias) => Ok(Transformed::yes(*alias.expr)),
            Expr::Column(col) => {
                let idx = input.schema.index_of_column(&col)?;
                // The unaliased input expression: for the input projection
                // [`a + b` as c, `d + e` as f] and the column "f", `d + e`.
                let input_expr = input.expr[idx].clone().unalias_nested().data;
                Ok(Transformed::yes(input_expr))
            }
            // Unsupported type for consecutive projection merge analysis.
            _ => Ok(Transformed::no(expr)),
        }
    })
}

/// Adds the columns that `expr` references from an outer query to `columns`.
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

/// [`outer_columns`] over several expressions.
fn outer_columns_helper_multi<'a, 'b>(
    exprs: impl IntoIterator<Item = &'a Expr>,
    columns: &'b mut BTreeSet<&'a Column>,
) {
    exprs.into_iter().for_each(|e| outer_columns(e, columns));
}

/// Splits the requirement `indices` of a join into those of its left and
/// right children. `left_len` is the number of fields of the left child.
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

/// Adds a projection on top of `plan` if doing so reduces the number of
/// columns for the parent operator.
fn add_projection_on_top_if_helpful(
    plan: LogicalPlan,
    project_exprs: Vec<Expr>,
) -> Result<Transformed<LogicalPlan>> {
    if project_exprs.len() >= plan.schema().fields().len() {
        Ok(Transformed::no(plan))
    } else {
        Projection::try_new(project_exprs, Arc::new(plan))
            .map(LogicalPlan::Projection)
            .map(Transformed::yes)
    }
}

/// Rewrites `proj` according to `indices`, the fields its ancestors require.
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

    /// The columns of a schema that a plan node requires, and a flag saying
    /// whether a projection above the child is beneficial for the parent (true
    /// for the child of a `LogicalPlan::Filter`, for example; false by default).
    ///
    /// Invariant: indices are in order and without duplicates.
    #[derive(Debug, Clone, Default)]
    pub(super) struct RequiredIndices {
        indices: Vec<usize>,
        projection_beneficial: bool,
    }

    impl RequiredIndices {
        pub fn new() -> Self {
            Self::default()
        }

        /// Requires all columns of `plan`'s schema.
        pub fn new_for_all_exprs(plan: &LogicalPlan) -> Self {
            Self {
                indices: (0..plan.schema().fields().len()).collect(),
                projection_beneficial: false,
            }
        }

        pub fn new_from_indices(indices: Vec<usize>) -> Self {
            Self {
                indices,
                projection_beneficial: false,
            }
            .compact()
        }

        pub fn into_inner(self) -> Vec<usize> {
            self.indices
        }

        pub fn with_projection_beneficial(mut self) -> Self {
            self.projection_beneficial = true;
            self
        }

        pub fn projection_beneficial(&self) -> bool {
            self.projection_beneficial
        }

        pub fn indices(&self) -> &[usize] {
            &self.indices
        }

        /// Adds the fields of `schema` (a child of `plan`) that `plan`'s
        /// expressions refer to.
        pub fn with_plan_exprs(mut self, plan: &LogicalPlan, schema: &DFSchemaRef) -> Result<Self> {
            plan.apply_expressions(|e| {
                self.add_expr(schema, e);
                Ok(TreeNodeRecursion::Continue)
            })?;
            // System columns are not added here: these are expression-derived
            // child requirements, and forcing row/activator columns at every
            // edge can add unintended payload columns and break downstream
            // gadget assumptions.
            Ok(self.compact())
        }

        /// Adds the indices of the fields of `input_schema` that `expr` refers
        /// to. Does not compact, and thus is not `pub`.
        fn add_expr(&mut self, input_schema: &DFSchemaRef, expr: &Expr) {
            // TODO could remove these clones (and visit the expression directly)
            let mut cols: std::collections::BTreeSet<&Column> =
                expr.column_refs().into_iter().collect();
            outer_columns(expr, &mut cols);
            self.indices.reserve(cols.len());
            for col in cols {
                if let Some(idx) = input_schema.maybe_index_of_column(col) {
                    self.indices.push(idx);
                }
            }
        }

        /// Adds the indices of the fields of `schema` that `exprs` refer to.
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
                // A pure expression-to-index mapping: system columns are added
                // only for a node's own output schema (`with_system_columns`).
                .compact()
        }

        pub fn append(mut self, indices: &[usize]) -> Self {
            self.indices.extend_from_slice(indices);
            self.compact()
        }

        /// Not in upstream: requires the system columns of `schema` when
        /// present, so that no node drops them from its output.
        pub fn with_system_columns(self, schema: &DFSchemaRef) -> Self {
            self.add_system_columns(schema).compact()
        }

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

        /// Not `pub` as it might not preserve the invariant of compacted indices
        fn map_indices<F>(mut self, f: F) -> Self
        where
            F: Fn(usize) -> usize,
        {
            self.indices.iter_mut().for_each(|idx| *idx = f(*idx));
            self
        }

        pub fn into_mapped_indices<F>(self, f: F) -> Vec<usize>
        where
            F: Fn(usize) -> usize,
        {
            self.map_indices(f).into_inner()
        }

        pub fn get_at_indices(&self, exprs: &[Expr]) -> Vec<Expr> {
            self.indices.iter().map(|&idx| exprs[idx].clone()).collect()
        }

        /// The columns of `input_schema` at these indices, as expressions.
        pub fn get_required_exprs(&self, input_schema: &DFSchemaRef) -> Vec<Expr> {
            self.indices
                .iter()
                .map(|&idx| Expr::from(Column::from(input_schema.qualified_field(idx))))
                .collect()
        }

        /// Restores the invariant: sorts (ascending) and deduplicates.
        fn compact(mut self) -> Self {
            self.indices.sort_unstable();
            self.indices.dedup();
            self
        }
    }
}
