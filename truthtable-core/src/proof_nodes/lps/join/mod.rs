mod hints;

use crate::{
    proof_nodes::{
        HintGenerationPlan, OUTPUT_PLAN_KEY,
        cost::ProvingCost,
        id::NodeId,
        lps::join::hints::{
            JOIN_ALL_KEY_SUPP, JOIN_LEFT_KEY_SOURCE, JOIN_LEFT_KEY_SUPP, JOIN_OUTPUT_KEY_SUPP,
            JOIN_RIGHT_KEY_SOURCE, JOIN_RIGHT_KEY_SUPP, build_join_hint_generation_plans,
        },
        prover::{ProverLpNode, ProverNode},
        verifier::{VerifierNode, VerifierLpNode},
    },
    prover::trees::{
        arithmetized_tree::ProverArithmetizedTree, piop_tree::ProverPIOPTree,
        proof_tree::ProverProofTree,
    },
    verifier::trees::proof_tree::VerifierProofTree,
};
use arithmetic::{
    ACTIVATOR_COL_NAME,
    table::{ArithTable, TrackedTable},
    table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::Prover,
};
use datafusion::{
    arrow::datatypes::{FieldRef, Schema},
    logical_expr::Join,
    prelude::SessionContext,
};
use datafusion_expr::{Expr, LogicalPlan};
use indexmap::IndexMap;
use ra_toolbox::lp_piop::join_check::{
    InnerJoinPIOP, InnerJoinProverInput, InnerJoinVerifierInput,
};
use std::{collections::HashSet, sync::Arc};

#[allow(clippy::type_complexity)]
pub struct ProverJoinNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub left_proof_tree_root: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub right_proof_tree_root: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    pub on_proof_tree_roots: Vec<(
        Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
        Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    )>,
    pub filter_proof_tree_root: Option<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>,
    pub node_id: NodeId,
}

#[allow(clippy::type_complexity)]
pub struct VerifierJoinNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub left_proof_tree_root: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub right_proof_tree_root: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    pub on_proof_tree_roots: Vec<(
        Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
        Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    )>,
    pub filter_proof_tree_root: Option<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>,
    pub node_id: NodeId,
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for ProverJoinNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        let mut children = vec![&self.left_proof_tree_root, &self.right_proof_tree_root];
        for (left_on_node, right_on_node) in &self.on_proof_tree_roots {
            children.push(left_on_node);
            children.push(right_on_node);
        }

        if let Some(filter_node) = &self.filter_proof_tree_root {
            children.push(filter_node);
        }
        children
    }

    fn hint_generation_plans(
        &self,
        _proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, HintGenerationPlan> {
        build_join_hint_generation_plans(self.node_id.clone())
    }


    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn ProverNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
    }

    fn child_edge_labels(&self) -> Vec<Option<String>> {
        let mut labels = Vec::with_capacity(
            2 + self.on_proof_tree_roots.len() * 2
                + usize::from(self.filter_proof_tree_root.is_some()),
        );
        labels.push(Some("left".to_string()));
        labels.push(Some("right".to_string()));
        for (idx, _) in self.on_proof_tree_roots.iter().enumerate() {
            labels.push(Some(format!("on[{idx}].lhs")));
            labels.push(Some(format!("on[{idx}].rhs")));
        }
        if self.filter_proof_tree_root.is_some() {
            labels.push(Some("filter".to_string()));
        }
        labels
    }

    fn name(&self) -> String {
        self.node_id().to_string()
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
        proof_tree: &crate::prover::trees::proof_tree::ProverProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn ProverNode<F, MvPCS, UvPCS>> {
        proof_tree
            .node(&self.node_id)
            .cloned()
            .unwrap_or_else(|| panic!("join node {} missing from proof tree", self.node_id))
    }

    fn arithmetic_post_process(
        &self,
        arithmetized_tree: &mut ProverArithmetizedTree<F, MvPCS, UvPCS>,
    ) {
        let Some(node_tables) = arithmetized_tree.arithmetized_tables_for_mut(&self.node_id) else {
            return;
        };
        let Some(all_key_supp_table) = node_tables.get(JOIN_ALL_KEY_SUPP) else {
            return;
        };

        let target_log_size = all_key_supp_table.log_size();
        let target_size = 1usize << target_log_size;

        let mut pad_table = |label: &str| {
            let Some(table) = node_tables.get_mut(label) else {
                return;
            };
            let current_size = 1usize << table.log_size();
            if current_size >= target_size {
                return;
            }

            let mut padded_polys: IndexMap<FieldRef, Arc<MLE<F>>> =
                IndexMap::with_capacity(table.polynomials().len());
            for (field_ref, poly) in table.polynomials() {
                let mut evals = poly.evaluations();
                evals.resize(target_size, F::zero());
                let padded_poly = Arc::new(MLE::from_evaluations_vec(target_log_size, evals));
                padded_polys.insert(field_ref.clone(), padded_poly);
            }

            let padded_table = ArithTable::new(table.schema(), padded_polys, target_log_size);
            *table = padded_table;
        };

        // Pad the support tables to match the union table and then drop any
        // right-key columns from the materialized output so the prover and
        // verifier commit to the same set of columns.
        pad_table(JOIN_OUTPUT_KEY_SUPP);
        pad_table(JOIN_LEFT_KEY_SUPP);
        pad_table(JOIN_RIGHT_KEY_SUPP);
        prune_output_right_keys(node_tables, &self.node_id);
    }

    fn prove_piop(
        &self,
        prover: &mut Prover<F, MvPCS, UvPCS>,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let join_plan = match self.node_id().to_lp().unwrap() {
            LogicalPlan::Join(join) => join.clone(),
            _ => panic!("expected join logical plan"),
        };
        let left_key_names = join_key_names(&join_plan, true);
        let right_key_names = join_key_names(&join_plan, false);
        ////////////////////////////////////////
        let left_tracked_table = piop_tree
            .tracked_table(&self.left_proof_tree_root.node_id(), OUTPUT_PLAN_KEY)
            .unwrap();
        let reordered_left_tracked_table =
            reorder_tracked_table_columns(left_tracked_table, &left_key_names);

        ///////////////////////////////////////
        let right_tracked_table = piop_tree
            .tracked_table(&self.right_proof_tree_root.node_id(), OUTPUT_PLAN_KEY)
            .unwrap();
        let reordered_right_tracked_table =
            reorder_tracked_table_columns(right_tracked_table, &right_key_names);
        /////////////////////////////////////////
        let out_tracked_table = piop_tree
            .tracked_table(&self.node_id(), OUTPUT_PLAN_KEY)
            .unwrap();
        let reordered_out_tracked_table =
            reorder_tracked_table_columns(out_tracked_table, &left_key_names);
        /////////////////////////////////////////
        let left_key_supprt_table = piop_tree
            .tracked_table(&self.node_id(), JOIN_LEFT_KEY_SUPP)
            .unwrap();
        let reordered_left_key_support_table =
            reorder_tracked_table_columns(left_key_supprt_table, &left_key_names);

        /////////////////////////////////////////
        let right_key_supprt_table = piop_tree
            .tracked_table(&self.node_id, JOIN_RIGHT_KEY_SUPP)
            .unwrap();
        let reordered_right_key_support_table =
            reorder_tracked_table_columns(right_key_supprt_table, &right_key_names);
        /////////////////////////////////////////
        let out_key_supprt_table = piop_tree
            .tracked_table(&self.node_id, JOIN_OUTPUT_KEY_SUPP)
            .unwrap();
        let reordered_out_key_support_table =
            reorder_tracked_table_columns(out_key_supprt_table, &left_key_names);
        /////////////////////////////////////////
        let all_key_supprt_table = piop_tree
            .tracked_table(&self.node_id, JOIN_ALL_KEY_SUPP)
            .unwrap();
        let reordered_all_key_support_table =
            reorder_tracked_table_columns(all_key_supprt_table, &left_key_names);
        /////////////////////////////////////////
        let join_left_source_tracked_table = piop_tree
            .tracked_table(&self.node_id, JOIN_LEFT_KEY_SOURCE)
            .unwrap();
        let join_left_source = join_left_source_tracked_table
            .tracked_col_by_ind(join_left_source_tracked_table.data_tracked_polys_indices()[0]);

        ///////////////////////////////////////
        let join_right_source_tracked_table = piop_tree
            .tracked_table(&self.node_id, JOIN_RIGHT_KEY_SOURCE)
            .unwrap();
        let join_right_source = join_right_source_tracked_table
            .tracked_col_by_ind(join_right_source_tracked_table.data_tracked_polys_indices()[0]);

        let inner_join_piop_prover_input = InnerJoinProverInput {
            left_table: reordered_left_tracked_table,
            right_table: reordered_right_tracked_table,
            out_table: reordered_out_tracked_table,
            left_key_support_table: reordered_left_key_support_table,
            right_key_support_table: reordered_right_key_support_table,
            out_key_support_table: reordered_out_key_support_table,
            all_key_support_table: reordered_all_key_support_table,
            join_left_source,
            join_right_source,
        };
        InnerJoinPIOP::<F, MvPCS, UvPCS>::prove(prover, inner_join_piop_prover_input)
    }
}

impl<F, MvPCS, UvPCS> ProverLpNode<F, MvPCS, UvPCS> for ProverJoinNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_lp(
        ctx: &SessionContext,
        prover_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        _parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        let join = match &plan {
            LogicalPlan::Join(join) => join,
            _ => panic!("expected join logical plan"),
        };
        let node_id = NodeId::LP(plan.clone());
        let left_proof_tree_root = ProverProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            prover_ctx.clone(),
            &join.left,
            &node_id,
        )
        .root();

        let right_proof_tree_root = ProverProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            prover_ctx.clone(),
            &join.right,
            &node_id,
        )
        .root();

        #[allow(clippy::type_complexity)]
        let on_proof_tree_roots: Vec<(
            Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
            Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
        )> = join
            .on
            .iter()
            .map(|(left_expr, right_expr)| {
                let left_tree = ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    left_expr.clone(),
                    &node_id,
                );
                let right_tree = ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    prover_ctx.clone(),
                    right_expr.clone(),
                    &node_id,
                );
                (
                    Arc::clone(&left_tree.root()),
                    Arc::clone(&right_tree.root()),
                )
            })
            .collect();

        let filter_proof_tree_root: Option<Arc<dyn ProverNode<F, MvPCS, UvPCS>>> =
            match &join.filter {
                Some(filter_expr) => {
                    let filter_tree = ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
                        ctx,
                        prover_ctx.clone(),
                        filter_expr.clone(),
                        &node_id,
                    );
                    Some(Arc::clone(&filter_tree.root()))
                }
                None => None,
            };

        Self {
            left_proof_tree_root,
            right_proof_tree_root,
            on_proof_tree_roots,
            filter_proof_tree_root,
            node_id,
        }
    }
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for VerifierJoinNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        let mut children = vec![&self.left_proof_tree_root, &self.right_proof_tree_root];
        for (left_on_node, right_on_node) in &self.on_proof_tree_roots {
            children.push(left_on_node);
            children.push(right_on_node);
        }

        if let Some(filter_node) = &self.filter_proof_tree_root {
            children.push(filter_node);
        }
        children
    }

    fn hint_generation_plans(
        &self,
        _proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, HintGenerationPlan> {
        build_join_hint_generation_plans(self.node_id.clone())
    }


    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
    }

    fn child_edge_labels(&self) -> Vec<Option<String>> {
        let mut labels = Vec::with_capacity(
            2 + self.on_proof_tree_roots.len() * 2
                + usize::from(self.filter_proof_tree_root.is_some()),
        );
        labels.push(Some("left".to_string()));
        labels.push(Some("right".to_string()));
        for (idx, _) in self.on_proof_tree_roots.iter().enumerate() {
            labels.push(Some(format!("on[{idx}].lhs")));
            labels.push(Some(format!("on[{idx}].rhs")));
        }
        if self.filter_proof_tree_root.is_some() {
            labels.push(Some("filter".to_string()));
        }
        labels
    }

    fn name(&self) -> String {
        self.node_id().to_string()
    }

    fn verify_piop(
        &self,
        verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        piop_tree: &mut crate::verifier::trees::piop_tree::VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let join_plan = match self.node_id().to_lp().unwrap() {
            LogicalPlan::Join(join) => join.clone(),
            _ => panic!("expected join logical plan"),
        };
        let left_key_names = join_key_names(&join_plan, true);
        let right_key_names = join_key_names(&join_plan, false);

        let left_tracked_table_oracle = piop_tree
            .tracked_table_oracle(&self.left_proof_tree_root.node_id(), OUTPUT_PLAN_KEY)
            .cloned()
            .expect("left join input table missing from PIOP tree");

        let reordered_left_tracked_table_oracle =
            reorder_tracked_table_oracle_columns(&left_tracked_table_oracle, &left_key_names);
        ////////////////////////////////////////////
        let right_tracked_table_oracle = piop_tree
            .tracked_table_oracle(&self.right_proof_tree_root.node_id(), OUTPUT_PLAN_KEY)
            .cloned()
            .expect("right join input table missing from PIOP tree");

        let reordered_right_tracked_table_oracle =
            reorder_tracked_table_oracle_columns(&right_tracked_table_oracle, &right_key_names);
        ////////////////////////////////////////////
        let out_tracked_table_oracle = piop_tree
            .tracked_table_oracle(&self.node_id(), OUTPUT_PLAN_KEY)
            .cloned()
            .expect("join output table missing from PIOP tree");
        let reordered_out_tracked_table_oracle =
            reorder_tracked_table_oracle_columns(&out_tracked_table_oracle, &left_key_names);
        ////////////////////////////////////////////
        let left_key_support_table_oracle = piop_tree
            .tracked_table_oracle(&self.node_id(), JOIN_LEFT_KEY_SUPP)
            .cloned()
            .expect("join left key support table missing from PIOP tree");

        let reordered_left_key_support_table_oracle =
            reorder_tracked_table_oracle_columns(&left_key_support_table_oracle, &left_key_names);

        //////////////////////////////////////////////
        let right_key_support_table_oracle = piop_tree
            .tracked_table_oracle(&self.node_id(), JOIN_RIGHT_KEY_SUPP)
            .cloned()
            .expect("join right key support table missing from PIOP tree");

        let reordered_right_key_support_table_oracle =
            reorder_tracked_table_oracle_columns(&right_key_support_table_oracle, &right_key_names);

        ////////////////////////////////////////////
        let out_key_support_table_oracle = piop_tree
            .tracked_table_oracle(&self.node_id(), JOIN_OUTPUT_KEY_SUPP)
            .cloned()
            .expect("join output key support table missing from PIOP tree");

        let reordered_out_key_support_table_oracle =
            reorder_tracked_table_oracle_columns(&out_key_support_table_oracle, &left_key_names);
        ////////////////////////////////////////////
        let all_key_support_table_oracle = piop_tree
            .tracked_table_oracle(&self.node_id(), JOIN_ALL_KEY_SUPP)
            .cloned()
            .expect("join union key support table missing from PIOP tree");

        let reordered_all_key_support_table_oracle =
            reorder_tracked_table_oracle_columns(&all_key_support_table_oracle, &left_key_names);
        ////////////////////////////////////////////
        let join_left_source_table = piop_tree
            .tracked_table_oracle(&self.node_id(), JOIN_LEFT_KEY_SOURCE)
            .cloned()
            .expect("join left source column missing from PIOP tree");
        let join_left_source_table_oracle = join_left_source_table
            .tracked_col_oracle_by_ind(join_left_source_table.data_tracked_oracles_indices()[0]);
        ////////////////////////////////////////////
        let join_right_source_table = piop_tree
            .tracked_table_oracle(&self.node_id(), JOIN_RIGHT_KEY_SOURCE)
            .cloned()
            .expect("join right source column missing from PIOP tree");
        let join_right_source_table_oracle = join_right_source_table
            .tracked_col_oracle_by_ind(join_right_source_table.data_tracked_oracles_indices()[0]);
        let verifier_input = InnerJoinVerifierInput {
            left_tracked_table_oracle: reordered_left_tracked_table_oracle,
            right_tracked_table_oracle: reordered_right_tracked_table_oracle,
            out_tracked_table_oracle: reordered_out_tracked_table_oracle,
            left_key_support_table_oracle: reordered_left_key_support_table_oracle,
            right_key_support_table_oracle: reordered_right_key_support_table_oracle,
            out_key_support_table_oracle: reordered_out_key_support_table_oracle,
            all_key_support_table_oracle: reordered_all_key_support_table_oracle,
            join_left_source_table_oracle,
            join_right_source_table_oracle,
        };

        InnerJoinPIOP::<F, MvPCS, UvPCS>::verify(verifier, verifier_input)
    }

    fn ctx_lp_node(
        &self,
        proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>> {
        proof_tree
            .node(&self.node_id)
            .cloned()
            .unwrap_or_else(|| panic!("join node {} missing from proof tree", self.node_id))
    }
}

impl<F, MvPCS, UvPCS> VerifierLpNode<F, MvPCS, UvPCS> for VerifierJoinNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_lp(
        ctx: &SessionContext,
        verifier_ctx: arithmetic::ctx::SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        _parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        let join = match &plan {
            LogicalPlan::Join(join) => join,
            _ => panic!("expected join logical plan"),
        };
        let node_id = NodeId::LP(plan.clone());
        let left_proof_tree_root = VerifierProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            verifier_ctx.clone(),
            &join.left,
            &node_id,
        )
        .root();

        let right_proof_tree_root = VerifierProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            verifier_ctx.clone(),
            &join.right,
            &node_id,
        )
        .root();

        #[allow(clippy::type_complexity)]
        let on_proof_tree_roots: Vec<(
            Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
            Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
        )> = join
            .on
            .iter()
            .map(|(left_expr, right_expr)| {
                let left_tree = VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    verifier_ctx.clone(),
                    left_expr.clone(),
                    &node_id,
                );
                let right_tree = VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
                    ctx,
                    verifier_ctx.clone(),
                    right_expr.clone(),
                    &node_id,
                );
                (
                    Arc::clone(&left_tree.root()),
                    Arc::clone(&right_tree.root()),
                )
            })
            .collect();

        let filter_proof_tree_root: Option<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> =
            match &join.filter {
                Some(filter_expr) => {
                    let filter_tree = VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
                        ctx,
                        verifier_ctx.clone(),
                        filter_expr.clone(),
                        &node_id,
                    );
                    Some(Arc::clone(&filter_tree.root()))
                }
                None => None,
            };

        Self {
            left_proof_tree_root,
            right_proof_tree_root,
            on_proof_tree_roots,
            filter_proof_tree_root,
            node_id,
        }
    }
}


fn column_name_from_expr(expr: &Expr) -> String {
    match expr {
        Expr::Column(col) => col.name.clone(),
        _ => panic!("expected column expression in join condition"),
    }
}

fn join_key_names(join: &Join, use_left: bool) -> Vec<String> {
    join.on
        .iter()
        .map(|(left_expr, right_expr)| {
            if use_left {
                column_name_from_expr(left_expr)
            } else {
                column_name_from_expr(right_expr)
            }
        })
        .collect()
}

fn reorder_tracked_table_columns<F, MvPCS, UvPCS>(
    table: &TrackedTable<F, MvPCS, UvPCS>,
    key_names: &[String],
) -> TrackedTable<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    let entries_vec: Vec<_> = table.tracked_polys().into_iter().collect();
    let ordered_entries = reorder_field_entries(&entries_vec, key_names);
    let ordered_map = ordered_entries.into_iter().collect::<IndexMap<_, _>>();

    let new_schema = table.schema().map(|schema| {
        let metadata = schema.metadata().clone();
        let fields: Vec<_> = ordered_map
            .keys()
            .map(|field| field.as_ref().clone())
            .collect();
        Schema::new_with_metadata(fields, metadata)
    });

    TrackedTable::new(new_schema, ordered_map, table.log_size())
}

fn reorder_tracked_table_oracle_columns<F, MvPCS, UvPCS>(
    table: &TrackedTableOracle<F, MvPCS, UvPCS>,
    key_names: &[String],
) -> TrackedTableOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    let entries_vec: Vec<_> = table.tracked_oracles().into_iter().collect();
    let ordered_entries = reorder_field_entries(&entries_vec, key_names);
    let ordered_map = ordered_entries.into_iter().collect::<IndexMap<_, _>>();

    let new_schema = table.schema().map(|schema| {
        let metadata = schema.metadata().clone();
        let fields: Vec<_> = ordered_map
            .keys()
            .map(|field| field.as_ref().clone())
            .collect();
        Schema::new_with_metadata(fields, metadata)
    });

    TrackedTableOracle::new(new_schema, ordered_map, table.log_size())
}

fn prune_output_right_keys<F: PrimeField>(
    tables: &mut IndexMap<String, ArithTable<F>>,
    node_id: &NodeId,
) {
    // The verifier never needs the join's right-key columns in the final
    // output table because it reconstructs those values from the right input.
    // Removing them here keeps the prover's commitment order aligned with what
    // the verifier will expect when it peeks tracker IDs.
    let Some(LogicalPlan::Join(join_plan)) = node_id.to_lp() else {
        return;
    };

    let right_key_names: HashSet<String> = join_plan
        .on
        .iter()
        .filter_map(|(_, right_expr)| match right_expr {
            Expr::Column(col) => Some(col.name.clone()),
            _ => None,
        })
        .collect();

    if right_key_names.is_empty() {
        return;
    }

    let Some(output_table) = tables.get_mut(OUTPUT_PLAN_KEY) else {
        return;
    };

    let mut filtered_polys = IndexMap::with_capacity(output_table.polynomials().len());
    let mut modified = false;
    for (field, poly) in output_table.polynomials() {
        if right_key_names.contains(field.name()) {
            modified = true;
            continue;
        }
        filtered_polys.insert(field.clone(), poly.clone());
    }

    if !modified {
        return;
    }

    let filtered_schema = output_table.schema().map(|schema| {
        let metadata = schema.metadata().clone();
        let fields: Vec<_> = schema
            .fields()
            .iter()
            .filter(|field| !right_key_names.contains(field.name()))
            .cloned()
            .collect();
        Schema::new_with_metadata(fields, metadata)
    });

    *output_table = ArithTable::new(filtered_schema, filtered_polys, output_table.log_size());
}

fn reorder_field_entries<T: Clone>(
    entries: &[(FieldRef, T)],
    key_names: &[String],
) -> Vec<(FieldRef, T)> {
    let mut used = vec![false; entries.len()];
    let mut ordered = Vec::new();

    for key in key_names {
        if let Some((idx, _)) = entries
            .iter()
            .enumerate()
            .find(|(i, (field, _))| !used[*i] && field.name() == key)
        {
            used[idx] = true;
            ordered.push((entries[idx].0.clone(), entries[idx].1.clone()));
        }
    }

    for (idx, (field, _)) in entries.iter().enumerate() {
        if used[idx] || field.name() == ACTIVATOR_COL_NAME {
            continue;
        }
        used[idx] = true;
        ordered.push((field.clone(), entries[idx].1.clone()));
    }

    for (idx, (field, _)) in entries.iter().enumerate() {
        if !used[idx] && field.name() == ACTIVATOR_COL_NAME {
            used[idx] = true;
            ordered.push((field.clone(), entries[idx].1.clone()));
        }
    }

    ordered
}
