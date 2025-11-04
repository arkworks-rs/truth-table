mod hints;
#[cfg(test)]
mod tests;
use crate::{
    proof_nodes::{
        HintGenerationPlan, OUTPUT_PLAN_KEY,
        cost::ProvingCost,
        id::NodeId,
        lps::sort::{
            self,
            hints::{
                LEX_SORTED_SORT_EXPRESSIONS_PLAN_KEY, SHIFTED_LEX_SORTED_SORT_EXPRESSIONS_PLAN_KEY,
                TIE_INDICATOR_PLAN_KEY, build_sort_hint_generation_plans,
            },
        },
        prover::ProverNode,
        verifier::VerifierNode,
    },
    prover::trees::proof_tree::ProverProofTree,
    verifier::trees::{piop_tree::VerifierPIOPTree, proof_tree::VerifierProofTree},
};
use arithmetic::{
    ACTIVATOR_COL_NAME, col::TrackedCol, table::TrackedTable, table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::structs::polynomial::TrackedPoly,
    verifier::{Verifier, structs::oracle::TrackedOracle},
};
use datafusion::{arrow::datatypes::FieldRef, prelude::SessionContext};
use datafusion_expr::LogicalPlan;
use indexmap::IndexMap;
use ra_toolbox::lp_piop::sort_check::{SortPIOP, SortPIOPProverInput, SortPIOPVerifierInput};
use std::sync::Arc;

pub struct ProverSortExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub expr: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    /// The direction of the sort
    pub asc: bool,
    /// Whether to put Nulls before all other data values
    pub nulls_first: bool,
}

pub struct VerifierSortExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub expr: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    /// The direction of the sort
    pub asc: bool,
    /// Whether to put Nulls before all other data values
    pub nulls_first: bool,
}

pub struct ProverSortNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub sort_exprs: Vec<ProverSortExprNode<F, MvPCS, UvPCS>>,
    pub input_prover_node: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
}
pub struct VerifierSortNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub sort_exprs: Vec<VerifierSortExprNode<F, MvPCS, UvPCS>>,
    pub input_verifier_node: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub node_id: NodeId,
}
impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for ProverSortNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        let mut children = vec![&self.input_prover_node];

        for sort_expr in &self.sort_exprs {
            children.push(&sort_expr.expr);
        }

        children
    }

    fn hint_generation_plans(
        &self,
        proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, HintGenerationPlan> {
        let base_plan = self
            .input_prover_node
            .hint_generation_plans(proof_tree)
            .get(OUTPUT_PLAN_KEY)
            .map(|hint| hint.plan().clone())
            .expect("input node missing OUTPUT_PLAN hint");

        let sort_lp = match self.node_id.to_lp() {
            Some(LogicalPlan::Sort(sort)) => sort,
            _ => panic!("expected sort logical plan"),
        };

        build_sort_hint_generation_plans(base_plan, sort_lp)
    }

    fn from_lp(
        ctx: &SessionContext,
        prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        _parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        let sort_lp = match &plan {
            LogicalPlan::Sort(sort) => sort,
            _ => panic!("expected sort logical plan"),
        };

        let node_id = NodeId::LP(plan.clone());

        let input_prover_node = ProverProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            prover_ctx.clone(),
            sort_lp.input.as_ref(),
            &node_id,
        )
        .root();

        let sort_exprs = sort_lp
            .expr
            .iter()
            .map(|sort_expr| {
                let expr_node = ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    sort_expr.expr.clone(),
                    &node_id,
                )
                .root();

                ProverSortExprNode {
                    expr: expr_node,
                    asc: sort_expr.asc,
                    nulls_first: sort_expr.nulls_first,
                }
            })
            .collect();

        Self {
            sort_exprs,
            input_prover_node,
            node_id,
        }
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn cost(
        &self,
        _statistics: datafusion::common::Statistics,
        _schema: datafusion::arrow::datatypes::SchemaRef,
    ) -> ProvingCost {
        todo!()
    }

    fn ctx_lp_node(
        &self,
        _proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverNode<F, MvPCS, UvPCS>> {
        self.input_prover_node.clone()
    }

    fn prove_piop(
        &self,
        prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
        piop_tree: &mut crate::prover::trees::piop_tree::ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        // Extract the sort logical plan
        let sort_lp = match self.node_id.to_lp() {
            Some(LogicalPlan::Sort(sort)) => sort.clone(),
            _ => panic!("expected sort logical plan"),
        };

        // First, we wire the actual non-sorted table, which is produced by the output
        // plan of the input node
        let tracked_table = piop_tree
            .tracked_table(&self.input_prover_node.node_id(), OUTPUT_PLAN_KEY)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "missing {} table for sort input node {}",
                    OUTPUT_PLAN_KEY,
                    self.input_prover_node.node_id()
                )
            });
        // Then, we wire the lexicographically sorted table, which is produced by the
        // output of the current sort node
        let lex_sorted_tracked_table = piop_tree
            .tracked_table(&self.node_id, OUTPUT_PLAN_KEY)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "missing {} table for sort node {}",
                    OUTPUT_PLAN_KEY, self.node_id
                )
            });
        // We also wire the lexicographically sorted version of the sort expressions,
        // assembled in a table
        let lex_sorted_sort_exprs_tracked_table = piop_tree
            .tracked_table(&self.node_id, LEX_SORTED_SORT_EXPRESSIONS_PLAN_KEY)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "missing {} table for sort node {}",
                    LEX_SORTED_SORT_EXPRESSIONS_PLAN_KEY, self.node_id
                )
            });

        // Now, let's assemble the sort expressions. Note that the evaluations of sort
        // expressions does not give us sorted columns; rather, they give us the columns
        // that were used to sort the original table.
        let mut sort_expr_cols: IndexMap<FieldRef, TrackedPoly<F, MvPCS, UvPCS>> =
            IndexMap::with_capacity(self.sort_exprs.len());
        for sort_expr_node in &self.sort_exprs {
            // Get the output table of the sort expression node
            let expr_table = piop_tree
                .tracked_table(&sort_expr_node.expr.node_id(), OUTPUT_PLAN_KEY)
                .unwrap_or_else(|| {
                    panic!(
                        "missing {} table for sort expression node {}",
                        OUTPUT_PLAN_KEY,
                        sort_expr_node.expr.node_id()
                    )
                });
            // Get the first data column produced by the sort expression node
            // Since expression nodes have only one data column, and at most one activator
            let mut data_cols = expr_table
                .tracked_polys()
                .into_iter()
                .filter(|(field, _)| field.name() != ACTIVATOR_COL_NAME);

            let (field, poly) = data_cols.next().unwrap_or_else(|| {
                panic!(
                    "sort expression node {} produced no data column",
                    sort_expr_node.expr.node_id()
                )
            });
            if data_cols.next().is_some() {
                panic!(
                    "sort expression node {} produced more than one data column",
                    sort_expr_node.expr.node_id()
                );
            }

            sort_expr_cols.insert(field.clone(), poly);
        }
        let sort_exprs_tracked_table_log_size = sort_expr_cols[0].log_size();
        let sort_exprs_tracked_table = TrackedTable::new(
            None,
            sort_expr_cols.clone(),
            sort_exprs_tracked_table_log_size,
        );

        let shifted_lex_sorted_sort_exprs_tracked_table = piop_tree
            .tracked_table(&self.node_id, SHIFTED_LEX_SORTED_SORT_EXPRESSIONS_PLAN_KEY)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "missing {} table for sort node {}",
                    SHIFTED_LEX_SORTED_SORT_EXPRESSIONS_PLAN_KEY, self.node_id
                )
            });
        dbg!(shifted_lex_sorted_sort_exprs_tracked_table.tracked_polys());

        let tie_indicators_tracked_table = if self.sort_exprs.len() == 1 {
            None
        } else {
            Some(
                piop_tree
                    .tracked_table(&self.node_id, TIE_INDICATOR_PLAN_KEY)
                    .cloned()
                    .unwrap_or_else(|| {
                        panic!(
                            "missing {} table for sort node {}",
                            TIE_INDICATOR_PLAN_KEY, self.node_id
                        )
                    }),
            )
        };

        let ascending_vec = self
            .sort_exprs
            .iter()
            .map(|expr| expr.asc)
            .collect::<Vec<bool>>();
        let null_first_vec = self
            .sort_exprs
            .iter()
            .map(|expr| expr.nulls_first)
            .collect::<Vec<bool>>();

        let sort_prover_input = SortPIOPProverInput {
            sort_lp,
            sort_exprs_tracked_table,
            lex_sorted_sort_exprs_tracked_table,
            shifted_lex_sorted_sort_exprs_tracked_table,
            tie_indicators_tracked_table,
            tracked_table,
            lex_sorted_tracked_table,
            ascending_vec,
            null_first_vec,
        };
        SortPIOP::prove(prover, sort_prover_input)?;

        Ok(())
    }
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for VerifierSortNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        let mut children = vec![&self.input_verifier_node];

        for sort_expr in &self.sort_exprs {
            children.push(&sort_expr.expr);
        }
        children
    }

    fn hint_generation_plans(
        &self,
        proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, HintGenerationPlan> {
        let input_node = proof_tree
            .node(&self.input_verifier_node.node_id())
            .expect("missing input node for sort");
        let base_plan = input_node
            .hint_generation_plans(proof_tree)
            .get(OUTPUT_PLAN_KEY)
            .map(|hint| hint.plan().clone())
            .expect("input node missing OUTPUT_PLAN hint");

        let sort_lp = match self.node_id.to_lp() {
            Some(LogicalPlan::Sort(sort)) => sort,
            _ => panic!("expected sort logical plan"),
        };

        build_sort_hint_generation_plans(base_plan, sort_lp)
    }

    fn from_lp(
        ctx: &SessionContext,
        verifier_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        let sort_lp = match &plan {
            LogicalPlan::Sort(sort) => sort,
            _ => panic!("expected sort logical plan"),
        };

        let node_id = NodeId::LP(plan.clone());

        let input_verifier_node = VerifierProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            verifier_ctx.clone(),
            sort_lp.input.as_ref(),
            &node_id,
        )
        .root();

        let sort_exprs = sort_lp
            .expr
            .iter()
            .map(|sort_expr| {
                let expr_node = VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    verifier_ctx.clone(),
                    sort_expr.expr.clone(),
                    &node_id,
                )
                .root();

                VerifierSortExprNode {
                    expr: expr_node,
                    asc: sort_expr.asc,
                    nulls_first: sort_expr.nulls_first,
                }
            })
            .collect();

        Self {
            sort_exprs,
            input_verifier_node,
            node_id,
        }
    }

    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn verify_piop(
        &self,
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        // Extract the sort logical plan
        let sort_lp = match self.node_id.to_lp() {
            Some(LogicalPlan::Sort(sort)) => sort.clone(),
            _ => panic!("expected sort logical plan"),
        };

        // First, we wire the actual non-sorted table, which is produced by the output
        // plan of the input node
        let tracked_table_oracle = piop_tree
            .tracked_table_oracle(&self.input_verifier_node.node_id(), OUTPUT_PLAN_KEY)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "missing {} table for sort input node {}",
                    OUTPUT_PLAN_KEY,
                    self.input_verifier_node.node_id()
                )
            });
        // Then, we wire the lexicographically sorted table, which is produced by the
        // output of the current sort node
        let lex_sorted_tracked_table_oracle = piop_tree
            .tracked_table_oracle(&self.node_id, OUTPUT_PLAN_KEY)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "missing {} table for sort node {}",
                    OUTPUT_PLAN_KEY, self.node_id
                )
            });
        // We also wire the lexicographically sorted version of the sort expressions,
        // assembled in a table
        let lex_sorted_sort_exprs_tracked_table_oracle = piop_tree
            .tracked_table_oracle(&self.node_id, LEX_SORTED_SORT_EXPRESSIONS_PLAN_KEY)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "missing {} table for sort node {}",
                    LEX_SORTED_SORT_EXPRESSIONS_PLAN_KEY, self.node_id
                )
            });

        // Now, let's assemble the sort expressions. Note that the evaluations of sort
        // expressions does not give us sorted columns; rather, they give us the columns
        // that were used to sort the original table.
        let mut sort_expr_cols: IndexMap<FieldRef, TrackedOracle<F, MvPCS, UvPCS>> =
            IndexMap::with_capacity(self.sort_exprs.len());
        for sort_expr_node in &self.sort_exprs {
            // Get the output table of the sort expression node
            let expr_table = piop_tree
                .tracked_table_oracle(&sort_expr_node.expr.node_id(), OUTPUT_PLAN_KEY)
                .unwrap_or_else(|| {
                    panic!(
                        "missing {} table for sort expression node {}",
                        OUTPUT_PLAN_KEY,
                        sort_expr_node.expr.node_id()
                    )
                });
            // Get the first data column produced by the sort expression node
            // Since expression nodes have only one data column, and at most one activator
            let mut data_cols = expr_table
                .tracked_oracles()
                .into_iter()
                .filter(|(field, _)| field.name() != ACTIVATOR_COL_NAME);

            let (field, poly) = data_cols.next().unwrap_or_else(|| {
                panic!(
                    "sort expression node {} produced no data column",
                    sort_expr_node.expr.node_id()
                )
            });
            if data_cols.next().is_some() {
                panic!(
                    "sort expression node {} produced more than one data column",
                    sort_expr_node.expr.node_id()
                );
            }

            sort_expr_cols.insert(field.clone(), poly);
        }
        let sort_exprs_tracked_table_log_size = sort_expr_cols[0].log_size();
        let sort_exprs_tracked_table_oracle = TrackedTableOracle::new(
            None,
            sort_expr_cols.clone(),
            sort_exprs_tracked_table_log_size,
        );

        let shifted_lex_sorted_sort_exprs_tracked_table_oracle = piop_tree
            .tracked_table_oracle(&self.node_id, SHIFTED_LEX_SORTED_SORT_EXPRESSIONS_PLAN_KEY)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "missing {} table for sort node {}",
                    SHIFTED_LEX_SORTED_SORT_EXPRESSIONS_PLAN_KEY, self.node_id
                )
            });

        let tie_indicators_tracked_table_oracle = if self.sort_exprs.len() == 1 {
            None
        } else {
            Some(
                piop_tree
                    .tracked_table_oracle(&self.node_id, TIE_INDICATOR_PLAN_KEY)
                    .cloned()
                    .unwrap_or_else(|| {
                        panic!(
                            "missing {} table for sort node {}",
                            TIE_INDICATOR_PLAN_KEY, self.node_id
                        )
                    }),
            )
        };
        let ascending_vec = self
            .sort_exprs
            .iter()
            .map(|expr| expr.asc)
            .collect::<Vec<bool>>();
        let null_first_vec = self
            .sort_exprs
            .iter()
            .map(|expr| expr.nulls_first)
            .collect::<Vec<bool>>();
        let sort_verifier_input = SortPIOPVerifierInput {
            sort_lp,
            sort_exprs_tracked_table_oracle,
            lex_sorted_sort_exprs_tracked_table_oracle,
            shifted_lex_sorted_sort_exprs_tracked_table_oracle,
            tie_indicators_tracked_table_oracle,
            tracked_table_oracle,
            lex_sorted_tracked_table_oracle,
            ascending_vec,
            null_first_vec,
        };
        SortPIOP::verify(verifier, sort_verifier_input)?;
        Ok(())
    }

    fn ctx_lp_node(
        &self,
        _proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>> {
        self.input_verifier_node.clone()
    }
}
