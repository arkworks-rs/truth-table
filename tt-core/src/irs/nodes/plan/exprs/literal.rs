use std::sync::Arc;

use crate::irs::{
    nodes::{IsExprNode, IsNode, IsPlanNode, Node, ProverNodeOps, VerifierNodeOps},
    payloads::PayloadStructure,
};
use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_EXPR, ROW_ID_COL_NAME};
use ark_ff::One;
use ark_ff::PrimeField;
use ark_ff::Zero;
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use datafusion_common::ScalarValue;
use datafusion_expr::{Expr, lit};
use indexmap::IndexMap;
use rayon::iter::Either;
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
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn initialize_gadget_plans(
        &self,
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn children(&self) -> Vec<std::sync::Arc<crate::irs::nodes::Node<B>>> {
        vec![]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ProverNode<B> {
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
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsPlanNode<B> for ProverNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        None
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        // Produce a virtual DataFrame with the literal and activator columns from the scope.
        let scope_hint_df = match self.scope().as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("Literal scope cannot be a gadget node"),
        };

        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(scope_hint_df.data_frame().clone())
                .expect("literal row-id sort should succeed");

        let mut exprs = vec![lit(self.literal.clone()), ACTIVATOR_EXPR.clone()];
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);
        let projected = input_df
            .select(exprs)
            .expect("literal projection should succeed");

        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("literal output sort should succeed");
        crate::irs::nodes::hints::HintDF::new_virtual(projected)
    }
}

fn scalar_to_field<B: SnarkBackend>(scalar: &ScalarValue) -> Option<<B as SnarkBackend>::F> {
    use ScalarValue::*;
    let f = |i: i128| (i >= 0).then(|| <B as SnarkBackend>::F::from(i as u128));
    let hash_bytes = |bytes: &[u8]| -> <B as SnarkBackend>::F {
        <B as SnarkBackend>::F::from_le_bytes_mod_order(&hash_to_32_bytes(bytes))
    };
    match scalar {
        Boolean(Some(v)) => Some(if *v {
            <B as SnarkBackend>::F::one()
        } else {
            <B as SnarkBackend>::F::zero()
        }),
        Float16(Some(v)) => Some(<B as SnarkBackend>::F::from_le_bytes_mod_order(
            &v.to_bits().to_le_bytes(),
        )),
        Float32(Some(v)) => Some(<B as SnarkBackend>::F::from_le_bytes_mod_order(
            &v.to_le_bytes(),
        )),
        Float64(Some(v)) => Some(<B as SnarkBackend>::F::from_le_bytes_mod_order(
            &v.to_le_bytes(),
        )),
        Decimal128(Some(v), _, _) => Some(<B as SnarkBackend>::F::from_le_bytes_mod_order(
            &v.to_le_bytes(),
        )),
        Decimal256(Some(v), _, _) => Some(<B as SnarkBackend>::F::from_le_bytes_mod_order(
            &v.to_le_bytes(),
        )),
        Int8(Some(v)) => f(*v as i128),
        Int16(Some(v)) => f(*v as i128),
        Int32(Some(v)) => f(*v as i128),
        Int64(Some(v)) => f(*v as i128),
        UInt8(Some(v)) => f(*v as i128),
        UInt16(Some(v)) => f(*v as i128),
        UInt32(Some(v)) => f(*v as i128),
        UInt64(Some(v)) => f(*v as i128),
        Utf8(Some(v)) => Some(hash_bytes(v.as_bytes())),
        Utf8View(Some(v)) => Some(hash_bytes(v.as_bytes())),
        LargeUtf8(Some(v)) => Some(hash_bytes(v.as_bytes())),
        Binary(Some(v)) => Some(hash_bytes(v)),
        BinaryView(Some(v)) => Some(hash_bytes(v)),
        FixedSizeBinary(_, Some(v)) => Some(hash_bytes(v)),
        LargeBinary(Some(v)) => Some(hash_bytes(v)),
        Date32(Some(v)) => f(*v as i128),
        Date64(Some(v)) => f(*v as i128),
        Time32Second(Some(v)) => f(*v as i128),
        Time32Millisecond(Some(v)) => f(*v as i128),
        Time64Microsecond(Some(v)) => f(*v as i128),
        Time64Nanosecond(Some(v)) => f(*v as i128),
        TimestampSecond(Some(v), _) => f(*v as i128),
        TimestampMillisecond(Some(v), _) => f(*v as i128),
        TimestampMicrosecond(Some(v), _) => f(*v as i128),
        TimestampNanosecond(Some(v), _) => f(*v as i128),
        IntervalYearMonth(Some(v)) => f(*v as i128),
        _ => None,
    }
}

fn hash_to_32_bytes(data: &[u8]) -> [u8; 32] {
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    fn fnv1a_with_seed(data: &[u8], seed: u64) -> u64 {
        let mut hash = seed;
        for &byte in data {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash
    }

    let mut out = [0u8; 32];
    let mut seed = FNV_OFFSET_BASIS;
    for i in 0..4 {
        let hash = fnv1a_with_seed(data, seed);
        out[i * 8..(i + 1) * 8].copy_from_slice(&hash.to_le_bytes());
        seed ^= hash.rotate_left(13);
    }
    out
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: crate::irs::nodes::NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Pull the scope's tracked table oracle to inherit activator and tracker.
        let scope_id = self.scope.id();
        let scope_table = match virtualized_ir.payload_for_node(&scope_id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Literal scope missing tracked table payload"),
        };

        let activator_oracle = scope_table
            .activator_tracked_poly()
            .expect("Literal scope should carry an activator column");
        let tracker = activator_oracle.tracker();
        let log_size = activator_oracle.log_size();

        let literal_value = scalar_to_field::<B>(&self.literal)
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
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
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
