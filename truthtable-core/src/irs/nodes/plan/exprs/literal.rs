use std::sync::Arc;

use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_EXPR};
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use datafusion_common::ScalarValue;
use datafusion_expr::{Expr, lit};
use indexmap::IndexMap;
use rayon::iter::Either;

use crate::irs::{
    nodes::{IsExprNode, IsNode, IsPlanNode, Node},
    payloads::PayloadStructure,
};
pub struct ProverNode<B: SnarkBackend> {
    pub literal: ScalarValue,
    pub scope: Arc<Node<B>>,
}
impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "Literal".to_string()
    }

    fn cost(
        &self,
        statistics: datafusion_common::Statistics,
        schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<crate::irs::nodes::Node<B>>> {
        vec![]
    }

    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Pull the scope's tracked table to inherit activator and tracker.
        let scope_id = self.scope.id();
        let scope_table = match virtualized_ir.payload_for_node(&scope_id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Literal scope missing tracked table payload"),
        };

        let log_size = scope_table.log_size();
        let activator_poly = scope_table
            .activator_tracked_poly()
            .expect("Literal scope should carry an activator column");
        let tracker = activator_poly.tracker();

        let literal_value = scalar_to_field::<B>(&self.literal)
            .expect("Unsupported literal type for virtual witness");
        let literal_poly = ark_piop::prover::structs::polynomial::TrackedPoly::new(
            Either::Right(literal_value),
            log_size,
            tracker,
        );

        // Columns: literal value and activator.
        let literal_field = FieldRef::new(Field::new(
            self.literal.to_string(),
            self.literal.data_type(),
            true,
        ));
        let activator_field =
            FieldRef::new(Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, true));

        let mut columns = IndexMap::from([
            (literal_field.clone(), literal_poly),
            (activator_field.clone(), activator_poly.clone()),
        ]);

        let schema = Schema::new(vec![
            literal_field.as_ref().clone(),
            activator_field.as_ref().clone(),
        ]);

        let updated_table = arithmetic::table::TrackedTable::new(Some(schema), columns, log_size);
        virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(updated_table)));
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ProverNode<B> {
    fn gadget(&self) -> std::sync::Arc<crate::irs::nodes::Node<B>> {
        todo!()
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        // Produce a virtual DataFrame with the literal and activator columns from the scope.
        let scope_hint_df = match self.scope().as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("Literal scope cannot be a gadget node"),
        };

        let projected = scope_hint_df
            .data_frame()
            .clone()
            .select(vec![lit(self.literal.clone()), ACTIVATOR_EXPR.clone()])
            .expect("literal projection should succeed");

        crate::irs::nodes::hints::HintDF::new_virtual(projected)
    }
}

fn scalar_to_field<B: SnarkBackend>(scalar: &ScalarValue) -> Option<<B as SnarkBackend>::F> {
    use ScalarValue::*;
    let f = |i: i128| (i >= 0).then(|| <B as SnarkBackend>::F::from(i as u128));
    match scalar {
        Int8(Some(v)) => f(*v as i128),
        Int16(Some(v)) => f(*v as i128),
        Int32(Some(v)) => f(*v as i128),
        Int64(Some(v)) => f(*v as i128),
        UInt8(Some(v)) => f(*v as i128),
        UInt16(Some(v)) => f(*v as i128),
        UInt32(Some(v)) => f(*v as i128),
        UInt64(Some(v)) => f(*v as i128),
        _ => None,
    }
}

impl<B: SnarkBackend> IsExprNode<B> for ProverNode<B> {
    fn from_expr(
        _expr: datafusion_expr::Expr,
        _self_ref: std::sync::Weak<crate::irs::nodes::Node<B>>,
        _parent: Option<std::sync::Weak<crate::irs::nodes::Node<B>>>,
        scope: std::sync::Arc<crate::irs::nodes::Node<B>>,
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

    fn scope(&self) -> Arc<Node<B>>
    where
        Self: Sized,
    {
        self.scope.clone()
    }
}
