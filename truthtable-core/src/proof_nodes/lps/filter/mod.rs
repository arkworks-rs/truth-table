use crate::{
    proof_nodes::{
        HintGenerationPlan, OUTPUT_PLAN_KEY, cost::ProvingCost, id::NodeId, prover::ProverNode,
        verifier::VerifierNode,
    },
    prover::trees::{piop_tree::ProverPIOPTree, proof_tree::ProverProofTree},
    verifier::trees::{piop_tree::VerifierPIOPTree, proof_tree::VerifierProofTree},
};
use arithmetic::{
    ACTIVATOR_COL_NAME, ctx::SharedCtx, table::TrackedTable, table_oracle::TrackedTableOracle,
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
    arrow::datatypes::{DataType, Field, FieldRef, Schema},
    logical_expr::{self as df, ExprSchemable, LogicalPlan, LogicalPlanBuilder},
    prelude::{Expr, SessionContext},
};
use indexmap::IndexMap;
use ra_toolbox::lp_piop::filter_check::{
    FilterPIOP, FilterPIOPProverInput, FilterPIOPVerifierInput,
};
use std::sync::Arc;

/// The implementation of a filter node in the prover proof tree.
pub struct ProverFilterNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// Child proof plan for the filter predicate expression.
    pub predicate_prover_node: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    /// Child proof plan for the input logical plan to be filtered.
    pub input_prover_node: Arc<dyn ProverNode<F, MvPCS, UvPCS>>,
    /// The unique identifier for this node.
    pub node_id: NodeId,
    /// The DataFusion expression representing the predicate; cached so we can
    /// rebuild logical plans without relying on node ids.
    pub predicate_expr: Expr,
}

/// The implementation of a filter node in the verification proof tree.
pub struct VerifierFilterNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// Child proof plan for the filter predicate expression.
    pub predicate_verifier_node: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    /// Child proof plan for the input logical plan to be filtered.
    pub input_verifier_node: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    /// The unique identifier for this node.
    pub node_id: NodeId,
    /// Cached predicate expression (see prover counterpart comment).
    pub predicate_expr: Expr,
}

impl<F, MvPCS, UvPCS> ProverNode<F, MvPCS, UvPCS> for ProverFilterNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_lp(
        ctx: &SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        _parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        // Get the inner filter object
        let filter = match &plan {
            df::LogicalPlan::Filter(f) => f,
            _ => panic!("expected filter logical plan"),
        };
        // Build the node id for this filter node
        let node_id = NodeId::LP(plan.clone());
        // Recursively build the prover proof node for the input logical plan
        let input_prover_node = ProverProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            prover_ctx.clone(),
            &filter.input,
            &node_id,
        )
        .root();

        // The predicate is an expr and needs to be proved
        let predicate_prover_node = ProverProofTree::<F, MvPCS, UvPCS>::from_expr(
            ctx,
            prover_ctx,
            filter.predicate.clone(),
            &node_id.clone(),
        )
        .root();
        // Building the witness generation plans map
        Self {
            predicate_prover_node,
            input_prover_node,
            node_id,
            predicate_expr: filter.predicate.clone(),
        }
    }

    fn children(&self) -> Vec<&Arc<dyn ProverNode<F, MvPCS, UvPCS>>> {
        vec![&self.input_prover_node, &self.predicate_prover_node]
    }
    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(
        &self,
        proof_tree: &ProverProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, HintGenerationPlan> {
        let input_plan = proof_tree
            .node(&self.input_prover_node.node_id())
            .unwrap()
            .hint_generation_plans(proof_tree)
            .get(OUTPUT_PLAN_KEY)
            .unwrap()
            .plan()
            .clone();
        // Determine activator's datatype from input schema
        let schema = input_plan.schema().clone();
        let activator_field = schema
            .field_with_unqualified_name(ACTIVATOR_COL_NAME)
            .unwrap_or_else(|_| panic!("'activator' column not found in input schema"));
        let activator_dtype = activator_field.data_type().clone();

        // Try boolean AND first; if types mismatch, fall back to 0/1 mask with CASE
        let predicate_expr = self.predicate_expr.clone();
        let try_bool_and = df::and(df::col(ACTIVATOR_COL_NAME), predicate_expr.clone());
        let new_activator = if try_bool_and.get_type(schema.as_ref()).is_ok() {
            try_bool_and.alias(ACTIVATOR_COL_NAME)
        } else {
            // Build a 0/1 mask of the same type as activator and bitwise-AND (or use CASE
            // if bitwise not supported)
            let one = df::lit(1)
                .cast_to(&activator_dtype, schema.as_ref())
                .unwrap();
            let zero = df::lit(0)
                .cast_to(&activator_dtype, schema.as_ref())
                .unwrap();
            let mask = df::when(predicate_expr.clone(), one.clone())
                .otherwise(zero.clone())
                .unwrap();

            // Prefer bitwise AND if valid for this dtype, otherwise fallback to CASE
            // replacement
            let try_bit_and = df::bitwise_and(df::col(ACTIVATOR_COL_NAME), mask.clone());
            if try_bit_and.get_type(schema.as_ref()).is_ok() {
                try_bit_and.alias(ACTIVATOR_COL_NAME)
            } else {
                // CASE WHEN predicate THEN activator ELSE 0
                df::when(predicate_expr, df::col(ACTIVATOR_COL_NAME))
                    .otherwise(zero)
                    .unwrap()
                    .alias(ACTIVATOR_COL_NAME)
            }
        };

        // Pass through all other columns unchanged
        let mut proj_exprs: Vec<df::Expr> = Vec::with_capacity(schema.fields().len());
        for f in schema.fields() {
            if f.name() == ACTIVATOR_COL_NAME {
                proj_exprs.push(new_activator.clone());
            } else {
                proj_exprs.push(df::col(f.name()));
            }
        }

        let output_plan = LogicalPlanBuilder::from(input_plan)
            .project(proj_exprs)
            .unwrap()
            .build()
            .unwrap();

        IndexMap::from([(
            OUTPUT_PLAN_KEY.to_string(),
            HintGenerationPlan::new_virtual(OUTPUT_PLAN_KEY.to_string(), output_plan),
        )])
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

    fn add_virtual_witness(
        &self,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
        _prover: &mut Prover<F, MvPCS, UvPCS>,
    ) {
        // Fetch the input tracked_table
        let input_table =
            match piop_tree.tracked_table(&self.input_prover_node.node_id(), OUTPUT_PLAN_KEY) {
                Some(table) => table,
                None => return,
            };
        // Fetch the predicate tracked_table
        let predicate_table =
            match piop_tree.tracked_table(&self.predicate_prover_node.node_id(), OUTPUT_PLAN_KEY) {
                Some(table) => table,
                None => return,
            };
        // Fetch the The predicate tracked colummn from the predicate table
        let predicate_tracked_col = predicate_table.tracked_col_by_ind(0);
        // Fetch the predicate tracked polynomial from the predicate tracked column
        let mut predicate_tracked_poly = predicate_tracked_col.data_tracked_poly();

        // update the predicate tracked polynomial by multiplying it with its own
        // activator
        if let Some(pred_activator) = predicate_tracked_col.activator_tracked_poly() {
            predicate_tracked_poly = &predicate_tracked_poly * &pred_activator;
        }
        // update the predicate tracked polynomial by multiplying it with the input
        // table activator
        if let Some(input_activator) = input_table.activator_tracked_poly() {
            predicate_tracked_poly = &predicate_tracked_poly * &input_activator;
        }

        // Create a field for the activator column
        let activator_field = Field::new(
            ACTIVATOR_COL_NAME,
            predicate_tracked_col
                .field_ref()
                .map(|f| f.data_type().clone())
                .unwrap_or(DataType::Boolean),
            true,
        );
        let activator_field_ref = FieldRef::new(activator_field);
        // Prepare the columns for the output table of the current filter node
        let mut columns = IndexMap::new();
        let mut activator_poly = Some(predicate_tracked_poly);
        // The output table of the current node is the same as the input table except
        // the activator is replaced with the new predicate tracked polynomial. Reuse
        // the original column ordering to keep schemas aligned.
        for (field, poly) in input_table.tracked_polys_iter() {
            if field.name() == ACTIVATOR_COL_NAME {
                let new_poly = activator_poly
                    .take()
                    .expect("activator polynomial should be present exactly once");
                columns.insert(activator_field_ref.clone(), new_poly);
            } else {
                columns.insert(field.clone(), poly.clone());
            }
        }
        if let Some(poly) = activator_poly {
            columns.insert(activator_field_ref.clone(), poly);
        }

        let output_schema = input_table.schema_ref().map(|schema| {
            let updated_fields: Vec<Field> = schema
                .fields()
                .iter()
                .map(|field| {
                    if field.name() == ACTIVATOR_COL_NAME {
                        activator_field_ref.as_ref().clone()
                    } else {
                        field.as_ref().clone()
                    }
                })
                .collect();
            Schema::new(updated_fields)
        });

        // Data columns are unchanged; the activator becomes
        // `input_activator AND predicate`.
        let output_table = TrackedTable::new(output_schema, columns, input_table.log_size());
        piop_tree.add_table(
            self.node_id.clone(),
            OUTPUT_PLAN_KEY.to_string(),
            output_table,
        );
    }
    fn prove_piop(
        &self,
        prover: &mut Prover<F, MvPCS, UvPCS>,
        piop_tree: &mut ProverPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let filter = match self.node_id().to_lp().unwrap() {
            LogicalPlan::Filter(f) => f.clone(),
            _ => panic!("expected filter logical plan"),
        };

        let predicate_col = piop_tree
            .tracked_table(&self.predicate_prover_node.node_id(), OUTPUT_PLAN_KEY)
            .unwrap()
            .tracked_col_by_ind(0);
        let input_tracked_table = piop_tree
            .tracked_table(&self.input_prover_node.node_id(), OUTPUT_PLAN_KEY)
            .unwrap()
            .clone();
        let output_tracked_table = piop_tree
            .tracked_table(&self.node_id, OUTPUT_PLAN_KEY)
            .unwrap()
            .clone();

        let filter_piop_prover_input = FilterPIOPProverInput {
            filter,
            predicate_col,
            input_tracked_table,
            output_tracked_table,
        };

        FilterPIOP::<F, MvPCS, UvPCS>::prove(prover, filter_piop_prover_input)?;
        Ok(())
    }
}

impl<F, MvPCS, UvPCS> VerifierNode<F, MvPCS, UvPCS> for VerifierFilterNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    fn from_lp(
        ctx: &SessionContext,
        prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
        plan: LogicalPlan,
        _parent_node_id: NodeId,
    ) -> Self
    where
        Self: Sized,
    {
        // Get the inner filter object
        let filter = match &plan {
            df::LogicalPlan::Filter(f) => f,
            _ => panic!("expected filter logical plan"),
        };
        // Build the node id for this filter node
        let node_id = NodeId::LP(plan.clone());
        // Recursively build the prover proof node for the input logical plan
        let input_verifier_node = VerifierProofTree::<F, MvPCS, UvPCS>::from_lp(
            ctx,
            prover_ctx.clone(),
            &filter.input,
            &node_id,
        )
        .root();
        // The predicate is an expr and needs to be proved
        let predicate_verifier_node = VerifierProofTree::<F, MvPCS, UvPCS>::from_expr(
            ctx,
            prover_ctx,
            filter.predicate.clone(),
            &node_id,
        )
        .root();
        // Building the witness generation plans map
        Self {
            predicate_verifier_node,
            input_verifier_node,
            node_id,
            predicate_expr: filter.predicate.clone(),
        }
    }

    fn children(&self) -> Vec<&Arc<dyn VerifierNode<F, MvPCS, UvPCS>>> {
        vec![&self.input_verifier_node, &self.predicate_verifier_node]
    }
    fn node_id(&self) -> NodeId {
        self.node_id.clone()
    }

    fn hint_generation_plans(
        &self,
        proof_tree: &VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> IndexMap<String, HintGenerationPlan> {
        let input_plan = proof_tree
            .node(&self.input_verifier_node.node_id())
            .unwrap()
            .hint_generation_plans(proof_tree)
            .get(OUTPUT_PLAN_KEY)
            .unwrap()
            .plan()
            .clone();
        // Determine activator's datatype from input schema
        let schema = input_plan.schema().clone();
        let activator_field = schema
            .field_with_unqualified_name(ACTIVATOR_COL_NAME)
            .unwrap_or_else(|_| panic!("'activator' column not found in input schema"));
        let activator_dtype = activator_field.data_type().clone();

        // Try boolean AND first; if types mismatch, fall back to 0/1 mask with CASE
        let predicate_expr = self.predicate_expr.clone();
        let try_bool_and = df::and(df::col(ACTIVATOR_COL_NAME), predicate_expr.clone());
        let new_activator = if try_bool_and.get_type(schema.as_ref()).is_ok() {
            try_bool_and.alias(ACTIVATOR_COL_NAME)
        } else {
            // Build a 0/1 mask of the same type as activator and bitwise-AND (or use CASE
            // if bitwise not supported)
            let one = df::lit(1)
                .cast_to(&activator_dtype, schema.as_ref())
                .unwrap();
            let zero = df::lit(0)
                .cast_to(&activator_dtype, schema.as_ref())
                .unwrap();
            let mask = df::when(predicate_expr.clone(), one.clone())
                .otherwise(zero.clone())
                .unwrap();

            // Prefer bitwise AND if valid for this dtype, otherwise fallback to CASE
            // replacement
            let try_bit_and = df::bitwise_and(df::col(ACTIVATOR_COL_NAME), mask.clone());
            if try_bit_and.get_type(schema.as_ref()).is_ok() {
                try_bit_and.alias(ACTIVATOR_COL_NAME)
            } else {
                // CASE WHEN predicate THEN activator ELSE 0
                df::when(predicate_expr, df::col(ACTIVATOR_COL_NAME))
                    .otherwise(zero)
                    .unwrap()
                    .alias(ACTIVATOR_COL_NAME)
            }
        };

        // Pass through all other columns unchanged
        let mut proj_exprs: Vec<df::Expr> = Vec::with_capacity(schema.fields().len());
        for f in schema.fields() {
            if f.name() == ACTIVATOR_COL_NAME {
                proj_exprs.push(new_activator.clone());
            } else {
                proj_exprs.push(df::col(f.name()));
            }
        }

        let output_plan = LogicalPlanBuilder::from(input_plan)
            .project(proj_exprs)
            .unwrap()
            .build()
            .unwrap();

        IndexMap::from([(
            OUTPUT_PLAN_KEY.to_string(),
            HintGenerationPlan::new_virtual(OUTPUT_PLAN_KEY.to_string(), output_plan),
        )])
    }

    fn append_sorted_descendants(&self, out: &mut Vec<Arc<dyn VerifierNode<F, MvPCS, UvPCS>>>) {
        for child in self.children() {
            child.append_sorted_descendants(out);
            out.push(Arc::clone(child));
        }
    }

    fn name(&self) -> String {
        self.node_id().to_string()
    }

    fn add_virtual_witness(
        &self,
        piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
        _verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
    ) {
        // Fetch the input tracked_table
        let input_table = match piop_tree
            .tracked_table_oracle(&self.input_verifier_node.node_id(), OUTPUT_PLAN_KEY)
        {
            Some(table) => table,
            None => return,
        };
        // Fetch the predicate tracked_table
        let predicate_table = match piop_tree
            .tracked_table_oracle(&self.predicate_verifier_node.node_id(), OUTPUT_PLAN_KEY)
        {
            Some(table) => table,
            None => return,
        };
        // Fetch the The predicate tracked colummn from the predicate table
        let predicate_col_oracle = predicate_table.tracked_col_oracle_by_ind(0);
        // Fetch the predicate tracked polynomial from the predicate tracked column
        let mut output_activator_oracle = predicate_col_oracle.data_tracked_oracle();
        // update the predicate tracked polynomial by multiplying it with its own
        // activator
        if let Some(pred_activator) = predicate_col_oracle.activator_tracked_oracle() {
            output_activator_oracle = &output_activator_oracle * &pred_activator;
        }
        // update the predicate tracked polynomial by multiplying it with the input
        // table activator
        if let Some(input_activator) = input_table.activator_tracked_poly() {
            output_activator_oracle = &output_activator_oracle * &input_activator;
        }
        // Create a field for the activator column

        let activator_field = Field::new(
            ACTIVATOR_COL_NAME,
            predicate_col_oracle
                .field_ref()
                .map(|f| f.data_type().clone())
                .unwrap_or(datafusion::arrow::datatypes::DataType::Boolean),
            true,
        );
        // Prepare the columns for the output table of the current filter node
        let activator_field_ref = datafusion::arrow::datatypes::FieldRef::new(activator_field);
        let mut columns = IndexMap::new();
        let mut activator_oracle = Some(output_activator_oracle);
        // The output table of the current node is the same as the input table except
        // the activator is replaced with the new predicate tracked polynomial.
        for (field, oracle) in input_table.tracked_oracles().iter() {
            if field.name() == ACTIVATOR_COL_NAME {
                let new_oracle = activator_oracle
                    .take()
                    .expect("activator oracle should be present exactly once");
                columns.insert(activator_field_ref.clone(), new_oracle);
            } else {
                columns.insert(field.clone(), oracle.clone());
            }
        }
        if let Some(oracle) = activator_oracle {
            columns.insert(activator_field_ref.clone(), oracle);
        }

        let output_schema = input_table.schema().map(|schema| {
            let updated_fields: Vec<Field> = schema
                .fields()
                .iter()
                .map(|field| {
                    if field.name() == ACTIVATOR_COL_NAME {
                        activator_field_ref.as_ref().clone()
                    } else {
                        field.as_ref().clone()
                    }
                })
                .collect();
            Schema::new(updated_fields)
        });

        // Data columns are unchanged; the activator becomes
        // `input_activator AND predicate`.
        let output_table = TrackedTableOracle::new(output_schema, columns, input_table.log_size());
        piop_tree.add_tracked_table_oracle(
            self.node_id.clone(),
            OUTPUT_PLAN_KEY.to_string(),
            output_table,
        );
    }
    fn verify_piop(
        &self,
        verifier: &mut ark_piop::verifier::Verifier<F, MvPCS, UvPCS>,
        piop_tree: &mut VerifierPIOPTree<F, MvPCS, UvPCS>,
    ) -> SnarkResult<()> {
        let filter = match self.node_id().to_lp().unwrap() {
            LogicalPlan::Filter(f) => f.clone(),
            _ => panic!("expected filter logical plan"),
        };

        let predicate_oracle = piop_tree
            .tracked_table_oracle(&self.predicate_verifier_node.node_id(), OUTPUT_PLAN_KEY)
            .unwrap()
            .tracked_col_oracle_by_ind(0);
        let input_tracked_table_oracle = piop_tree
            .tracked_table_oracle(&self.input_verifier_node.node_id(), OUTPUT_PLAN_KEY)
            .unwrap()
            .clone();
        let output_tracked_table_oracle = piop_tree
            .tracked_table_oracle(&self.node_id, OUTPUT_PLAN_KEY)
            .unwrap()
            .clone();

        let filter_piop_verifier_input = FilterPIOPVerifierInput {
            filter,
            predicate_oracle,
            input_tracked_table_oracle,
            output_tracked_table_oracle,
        };

        FilterPIOP::<F, MvPCS, UvPCS>::verify(verifier, filter_piop_verifier_input)?;
        Ok(())
    }

    fn ctx_lp_node(
        &self,
        _proof_tree: &crate::verifier::trees::proof_tree::VerifierProofTree<F, MvPCS, UvPCS>,
    ) -> Arc<dyn VerifierNode<F, MvPCS, UvPCS>> {
        self.input_verifier_node.clone()
    }
}
