use std::sync::Arc;

use crate::irs::{
    nodes::{IsExprNode, IsNode, IsPlanNode, Node, ProverNodeOps, VerifierNodeOps},
    payloads::PayloadStructure,
};
use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use datafusion_common::ScalarValue;
use datafusion_expr::{Expr, lit};
use indexmap::IndexMap;
use rayon::iter::Either;
pub struct ExprNode<B: SnarkBackend> {
    pub literal: ScalarValue,
    pub scope: Vec<std::sync::Weak<Node<B>>>,
}
impl<B: SnarkBackend> IsNode<B> for ExprNode<B> {
    fn name(&self) -> String {
        "Literal".to_string()
    }

    fn display(&self) -> String {
        format!(
            "Literal\nScope: {}, value: {}",
            self.scope()[0].name(),
            self.literal
        )
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<crate::irs::nodes::Node<B>>> {
        vec![]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ExprNode<B> {
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Pull the scope's tracked table to inherit activator and tracker.
        let scope = self.scope[0]
            .upgrade()
            .expect("Literal scope should be available during witness generation");
        let scope_id = scope.id();
        let scope_table = match virtualized_ir.payload_for_node(&scope_id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Literal scope missing tracked table payload"),
        };

        let log_size = scope_table.log_size();
        let activator_poly = scope_table
            .activator_tracked_poly()
            .expect("Literal scope should carry an activator column");
        let tracker = activator_poly.tracker();
        let literal_value =
            arithmetic::encoding::scalar_to_field::<<B as SnarkBackend>::F>(&self.literal)
                .expect("Unsupported literal type for virtual witness");
        let literal_poly = ark_piop::prover::structs::polynomial::TrackedPoly::new(
            Either::Right(literal_value),
            log_size,
            tracker,
        );

        // Columns: literal value, optional row_id, and activator.
        let literal_field = FieldRef::new(Field::new(
            self.literal.to_string(),
            self.literal.data_type(),
            true,
        ));
        let activator_field =
            FieldRef::new(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, true));

        let mut columns = IndexMap::new();
        columns.insert(literal_field.clone(), literal_poly);
        if let Some((row_id_field, row_id_poly)) = scope_table
            .tracked_polys()
            .iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
            .map(|(field, poly)| (field.clone(), poly.clone()))
        {
            columns.insert(row_id_field, row_id_poly);
        }
        columns.insert(activator_field.clone(), activator_poly.clone());

        let schema = Schema::new(
            columns
                .keys()
                .map(|field| field.as_ref().clone())
                .collect::<Vec<_>>(),
        );

        let updated_table = arithmetic::table::TrackedTable::new(Some(schema), columns, log_size);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
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
        // Produce a virtual DataFrame with the literal and activator columns from the scope.
        let scope = self.scope[0]
            .upgrade()
            .expect("Literal scope should be available during output");
        let scope_hint_df = match scope.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsProverPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Literal scope cannot be a gadget node"),
        };

        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(scope_hint_df.data_frame().clone())
                .expect("literal row-id sort should succeed");

        let mut exprs = vec![lit(self.literal.clone())];
        crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut exprs);
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);
        let projected = input_df
            .select(exprs)
            .expect("literal projection should succeed");

        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("literal output sort should succeed");
        crate::irs::nodes::hints::HintDF::new_virtual(projected)
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for ExprNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        todo!()
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ExprNode<B> {
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Pull the scope's tracked table oracle to inherit activator and tracker.
        let scope = self.scope[0]
            .upgrade()
            .expect("Literal scope should be available during witness generation");
        let scope_id = scope.id();
        let scope_table = match virtualized_ir.payload_for_node(&scope_id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Literal scope missing tracked table payload"),
        };

        let activator_oracle = scope_table
            .activator_tracked_poly()
            .expect("Literal scope should carry an activator column");
        let tracker = activator_oracle.tracker();
        let log_size = activator_oracle.log_size();

        let literal_value =
            arithmetic::encoding::scalar_to_field::<<B as SnarkBackend>::F>(&self.literal)
                .expect("Unsupported literal type for virtual witness");
        let literal_oracle = ark_piop::verifier::structs::oracle::TrackedOracle::new(
            Either::Right(literal_value),
            tracker.clone(),
            log_size,
        );

        // Columns: literal value, optional row_id, and activator.
        let literal_field = FieldRef::new(Field::new(
            self.literal.to_string(),
            self.literal.data_type(),
            true,
        ));
        let activator_field =
            FieldRef::new(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, true));

        let mut columns = IndexMap::new();
        columns.insert(literal_field.clone(), literal_oracle);
        if let Some((row_id_field, row_id_oracle)) = scope_table
            .tracked_oracles()
            .iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
            .map(|(field, oracle)| (field.clone(), oracle.clone()))
        {
            columns.insert(row_id_field, row_id_oracle);
        }
        columns.insert(activator_field.clone(), activator_oracle.clone());

        let schema = Schema::new(
            columns
                .keys()
                .map(|field| field.as_ref().clone())
                .collect::<Vec<_>>(),
        );

        let updated_table =
            arithmetic::table_oracle::TrackedTableOracle::new(Some(schema), columns, log_size);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }
    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        id: crate::irs::nodes::NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsExprNode<B> for ExprNode<B> {
    fn from_expr(
        _expr: datafusion_expr::Expr,
        _self_ref: std::sync::Weak<crate::irs::nodes::Node<B>>,
        _parent: Option<std::sync::Weak<crate::irs::nodes::Node<B>>>,
        scope: Vec<std::sync::Weak<crate::irs::nodes::Node<B>>>,
    ) -> Self
    where
        Self: Sized,
    {
        let literal = match _expr {
            datafusion_expr::Expr::Literal(scalar_value) => scalar_value,
            _ => panic!("Expected Expr::Literal"),
        };
        Self { literal, scope }
    }

    fn expr(&self) -> datafusion_expr::Expr {
        Expr::Literal(self.literal.clone())
    }

    fn parent(&self) -> crate::irs::nodes::PlanNode<B>
    where
        Self: Sized,
    {
        todo!()
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
