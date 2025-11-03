use arithmetic::{ACTIVATOR_COL_NAME, col::TrackedCol};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    prover::Prover,
};
use ra_toolbox::lp_piop::sort_check::{SortPIOP, SortPIOPProverInput};

use crate::{
    proof_nodes::{
        OUTPUT_PLAN_KEY,
        lps::sort::{
            SHIFTED_SORT_EXPRESSIONS_PLAN_KEY, SORT_EXPRESSIONS_PLAN_KEY, TIE_INDICATOR_PLAN_KEY,
        },
        prover::ProverNode,
    },
    prover::trees::piop_tree::ProverPIOPTree,
};


    pub(super) fn piop_prove_input_prep<F, MvPCS, UvPCS>(
        &self,
        prover: &mut Prover<F, MvPCS, UvPCS>,
        piop_tree: &ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SortPIOPProverInput<F, MvPCS, UvPCS>
    where
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>>,
        UvPCS: PCS<F, Poly = LDE<F>>,
    {
        // First, we wire the actual non-sorted table, which is produced by the output
        // plan of the input node
        let table = piop_tree
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
        let lex_sorted_table = piop_tree
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
        let sroted_sort_exprs_table = piop_tree
            .tracked_table(&self.node_id, SORT_EXPRESSIONS_PLAN_KEY)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "missing {} table for sort node {}",
                    SORT_EXPRESSIONS_PLAN_KEY, self.node_id
                )
            });

        // Now, let's assemble the sort expressions. Note that the evaluations of sort
        // expressions does not give us sorted columns; rather, they give us the columns
        // that were used to sort the original table.
        let mut sort_exprs: Vec<TrackedCol<F, MvPCS, UvPCS>> =
            Vec::with_capacity(self.sort_exprs.len());
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
            // Build the sort tracked column
            let sort_tracked_col = TrackedCol::new(
                poly,
                expr_table.activator_tracked_poly(),
                Some(field.clone()),
            );

            sort_exprs.push(sort_tracked_col);
        }

        let shifted_sort_exprs_table = piop_tree
            .tracked_table(&self.node_id, SHIFTED_SORT_EXPRESSIONS_PLAN_KEY)
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "missing {} table for sort node {}",
                    SHIFTED_SORT_EXPRESSIONS_PLAN_KEY, self.node_id
                )
            });

        let tie_indicator_cols = piop_tree
            .tracked_table(&self.node_id, TIE_INDICATOR_PLAN_KEY)
            .map(|table| {
                table
                    .tracked_polys()
                    .into_iter()
                    .map(|(field, poly)| TrackedCol::new(poly, None, Some(field)))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let sort_prover_input = SortPIOPProverInput {
            sort_lp,
            sort_exprs,
            sroted_sort_exprs,
            tie_indicator_cols,
            table,
            lex_sorted_table,
        };
    }
