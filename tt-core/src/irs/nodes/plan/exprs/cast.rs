use std::sync::Arc;

use arithmetic::encoding::encode_arrow_array_to_field;
use arithmetic::table::TrackedTable;
use arithmetic::{ACTIVATOR_COL_NAME, ACTIVATOR_EXPR, ACTIVATOR_FIELD, ROW_ID_COL_NAME};
use ark_ff::Zero;
use ark_piop::SnarkBackend;
use datafusion::arrow::datatypes::{Field, Schema};
use datafusion_common::Statistics;
use datafusion_expr::{Cast, Expr};
use indexmap::IndexMap;
use rayon::iter::Either;

use crate::irs::nodes::{
    IsExprNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
};
use crate::irs::payloads::PayloadStructure;

pub struct ProverNode<B: SnarkBackend> {
    pub scope: Arc<Node<B>>,
    pub parent: Option<std::sync::Weak<Node<B>>>,
    pub cast: Cast,
}

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "Cast".to_string()
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
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Build a virtual witness table for this cast by either:
        // - emitting a constant tracked column for literal casts, or
        // - retyping the child's tracked column for column casts.
        let cast_expr = self.cast.clone();

        // Pull the scope table to reuse its activator tracker/log size.
        let scope_id = self.scope.id();
        let scope_table = match virtualized_ir.payload_for_node(&scope_id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Cast scope missing tracked table payload"),
        };

        match cast_expr.expr.as_ref() {
            Expr::Literal(scalar) => {
                // Cast the literal to the target type and encode it into field elements.
                let scalar = scalar
                    .cast_to(&cast_expr.data_type)
                    .expect("failed to cast literal value for cast expression");
                let array = scalar
                    .to_array()
                    .expect("failed to convert scalar into arrow array");

                let mut column_values = encode_arrow_array_to_field::<B::F>(&array)
                    .expect("failed to encode literal into field elements")
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| vec![<B as SnarkBackend>::F::zero()]);

                if column_values.len() > 1 {
                    panic!("literal encoding resulted in multiple field elements");
                }

                let constant_value = column_values
                    .pop()
                    .unwrap_or_else(<B as SnarkBackend>::F::zero);

                // Reuse the scope activator tracker so the constant aligns with existing rows.
                let activator_poly = scope_table
                    .activator_tracked_poly()
                    .expect("Cast scope should carry an activator column");
                let tracker = activator_poly.tracker();
                let log_size = scope_table.log_size();

                let tracked_poly = ark_piop::prover::structs::polynomial::TrackedPoly::new(
                    Either::Right(constant_value),
                    log_size,
                    tracker,
                );

                // Build a single-column table (plus row_id/activator) with the casted literal.
                let data_type = scalar.data_type();
                let field = Arc::new(Field::new("literal", data_type.clone(), scalar.is_null()));

                let mut columns = IndexMap::from([(field.clone(), tracked_poly)]);
                if let Some((row_id_field, row_id_poly)) = scope_table
                    .tracked_polys()
                    .iter()
                    .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
                    .map(|(field, poly)| (field.clone(), poly.clone()))
                {
                    columns.insert(row_id_field, row_id_poly);
                }
                columns.insert(ACTIVATOR_FIELD.clone(), activator_poly);

                let schema = Some(Schema::new(
                    columns
                        .keys()
                        .map(|field| field.as_ref().clone())
                        .collect::<Vec<_>>(),
                ));

                let table = TrackedTable::new(schema, columns, log_size);
                virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(table)));
                Ok(())
            }
            Expr::Column(column) => {
                // Extract the source column from the scope table, keeping activator.
                let child_table = {
                    let schema = scope_table
                        .schema_ref()
                        .expect("Cast scope should have schema");
                    let col_idx = schema
                        .index_of(column.name())
                        .expect("Cast column not found in scope schema");
                    scope_table.tracked_subtable_by_indices(&[col_idx])
                };

                let target_type = cast_expr.data_type.clone();
                // Rebuild the schema/fields with the cast target type for data columns.
                let mut columns = IndexMap::with_capacity(child_table.tracked_polys().len());
                for (field, poly) in child_table.tracked_polys() {
                    let new_field =
                        if field.name() == ACTIVATOR_COL_NAME || field.name() == ROW_ID_COL_NAME {
                            field.clone()
                        } else {
                            let base = field.as_ref();
                            let mut updated =
                                Field::new(base.name(), target_type.clone(), base.is_nullable());
                            if !base.metadata().is_empty() {
                                updated = updated.with_metadata(base.metadata().clone());
                            }
                            Arc::new(updated)
                        };
                    columns.insert(new_field, poly.clone());
                }

                let new_schema = child_table.schema().map(|schema| {
                    let fields: Vec<Field> = schema
                        .fields()
                        .iter()
                        .map(|field| {
                            let base = field.as_ref();
                            if base.name() == ACTIVATOR_COL_NAME || base.name() == ROW_ID_COL_NAME {
                                base.clone()
                            } else {
                                let mut updated = Field::new(
                                    base.name(),
                                    target_type.clone(),
                                    base.is_nullable(),
                                );
                                if !base.metadata().is_empty() {
                                    updated = updated.with_metadata(base.metadata().clone());
                                }
                                updated
                            }
                        })
                        .collect();
                    let mut new_schema = Schema::new(fields);
                    if !schema.metadata().is_empty() {
                        new_schema = new_schema.with_metadata(schema.metadata().clone());
                    }
                    new_schema
                });

                let new_table = TrackedTable::new(new_schema, columns, child_table.log_size());

                // Store the updated table as this node's virtual payload.
                virtualized_ir
                    .set_payload_for_node(id, Some(PayloadStructure::PlanPayload(new_table)));
                Ok(())
            }
            _ => panic!("Cast virtual witness expects a literal or column expression"),
        }
    }

    fn initialize_gadgets(
        &self,
        _id: NodeId,
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
        let scope_hint_df = match self.scope.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("Cast scope cannot be a gadget node"),
        };

        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(scope_hint_df.data_frame().clone())
                .expect("cast row-id sort should succeed");

        let mut exprs = vec![
            datafusion_expr::Expr::Cast(self.cast.clone()),
            ACTIVATOR_EXPR.clone(),
        ];
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);
        let projected = input_df
            .select(exprs)
            .expect("cast projection should succeed");

        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("cast output sort should succeed");
        crate::irs::nodes::hints::HintDF::new_virtual(projected)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        // Mirror the prover logic, but build tracked oracles instead of polynomials.
        // Literals become constant oracles; column casts retype the field metadata.
        let cast_expr = self.cast.clone();

        // Pull the scope table oracle to reuse its tracker/log size.
        let scope_id = self.scope.id();
        let scope_table = match virtualized_ir.payload_for_node(&scope_id) {
            Some(PayloadStructure::PlanPayload(table)) => table.clone(),
            _ => panic!("Cast scope missing tracked table payload"),
        };

        match cast_expr.expr.as_ref() {
            Expr::Literal(scalar) => {
                // Cast the literal to the target type and encode it into field elements.
                let scalar = scalar
                    .cast_to(&cast_expr.data_type)
                    .expect("failed to cast literal value for cast expression");
                let array = scalar
                    .to_array()
                    .expect("failed to convert scalar into arrow array");

                let mut column_values = encode_arrow_array_to_field::<B::F>(&array)
                    .expect("failed to encode literal into field elements")
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| vec![<B as SnarkBackend>::F::zero()]);

                if column_values.len() > 1 {
                    panic!("literal encoding resulted in multiple field elements");
                }

                let constant_value = column_values
                    .pop()
                    .unwrap_or_else(<B as SnarkBackend>::F::zero);

                // Reuse the scope activator tracker so the constant aligns with existing rows.
                let activator_oracle = scope_table
                    .activator_tracked_poly()
                    .expect("Cast scope should carry an activator column");
                let tracker = activator_oracle.tracker();
                let log_size = activator_oracle.log_size();

                let tracked_oracle = ark_piop::verifier::structs::oracle::TrackedOracle::new(
                    Either::Right(constant_value),
                    tracker,
                    log_size,
                );

                // Build a single-column oracle table (plus row_id/activator) with the casted literal.
                let data_type = scalar.data_type();
                let field = Arc::new(Field::new("literal", data_type.clone(), scalar.is_null()));

                let mut columns = IndexMap::from([(field.clone(), tracked_oracle)]);
                if let Some((row_id_field, row_id_oracle)) = scope_table
                    .tracked_oracles()
                    .iter()
                    .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
                    .map(|(field, oracle)| (field.clone(), oracle.clone()))
                {
                    columns.insert(row_id_field, row_id_oracle);
                }
                columns.insert(ACTIVATOR_FIELD.clone(), activator_oracle);

                let schema = Some(Schema::new(
                    columns
                        .keys()
                        .map(|field| field.as_ref().clone())
                        .collect::<Vec<_>>(),
                ));

                let table =
                    arithmetic::table_oracle::TrackedTableOracle::new(schema, columns, log_size);
                virtualized_ir.set_payload_for_node(id, Some(PayloadStructure::PlanPayload(table)));
                Ok(())
            }
            Expr::Column(column) => {
                // Extract the source column oracle from the scope, keeping activator.
                let child_table = {
                    let schema = scope_table
                        .schema_ref()
                        .expect("Cast scope should have schema");
                    let col_idx = schema
                        .index_of(column.name())
                        .expect("Cast column not found in scope schema");
                    scope_table.tracked_subtable_by_indices(&[col_idx])
                };

                let target_type = cast_expr.data_type.clone();
                // Rebuild the schema/fields with the cast target type for data columns.
                let mut columns = IndexMap::with_capacity(child_table.tracked_oracles().len());
                for (field, oracle) in child_table.tracked_oracles() {
                    let new_field =
                        if field.name() == ACTIVATOR_COL_NAME || field.name() == ROW_ID_COL_NAME {
                            field.clone()
                        } else {
                            let base = field.as_ref();
                            let mut updated =
                                Field::new(base.name(), target_type.clone(), base.is_nullable());
                            if !base.metadata().is_empty() {
                                updated = updated.with_metadata(base.metadata().clone());
                            }
                            Arc::new(updated)
                        };
                    columns.insert(new_field, oracle.clone());
                }

                let new_schema = child_table.schema().map(|schema| {
                    let fields: Vec<Field> = schema
                        .fields()
                        .iter()
                        .map(|field| {
                            let base = field.as_ref();
                            if base.name() == ACTIVATOR_COL_NAME || base.name() == ROW_ID_COL_NAME {
                                base.clone()
                            } else {
                                let mut updated = Field::new(
                                    base.name(),
                                    target_type.clone(),
                                    base.is_nullable(),
                                );
                                if !base.metadata().is_empty() {
                                    updated = updated.with_metadata(base.metadata().clone());
                                }
                                updated
                            }
                        })
                        .collect();
                    let mut new_schema = Schema::new(fields);
                    if !schema.metadata().is_empty() {
                        new_schema = new_schema.with_metadata(schema.metadata().clone());
                    }
                    new_schema
                });

                let new_table = arithmetic::table_oracle::TrackedTableOracle::new(
                    new_schema,
                    columns,
                    child_table.log_size(),
                );

                // Store the updated oracle table as this node's virtual payload.
                virtualized_ir
                    .set_payload_for_node(id, Some(PayloadStructure::PlanPayload(new_table)));
                Ok(())
            }
            _ => panic!("Cast virtual witness expects a literal or column expression"),
        }
    }

    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsExprNode<B> for ProverNode<B> {
    fn from_expr(
        expr: datafusion_expr::Expr,
        _self_ref: std::sync::Weak<Node<B>>,
        parent: Option<std::sync::Weak<Node<B>>>,
        scope: std::sync::Arc<Node<B>>,
    ) -> Self
    where
        Self: Sized,
    {
        let cast = match expr {
            datafusion_expr::Expr::Cast(col) => col,
            _ => panic!("Expected Cast expression"),
        };
        Self {
            cast,
            scope,
            parent,
        }
    }

    fn expr(&self) -> datafusion_expr::Expr {
        todo!()
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
                Node::Gadget(_) => panic!("Cast parent cannot be a gadget node"),
            })
            .expect("Cast node must have a parent")
    }

    fn scope(&self) -> std::sync::Arc<Node<B>>
    where
        Self: Sized,
    {
        self.scope.clone()
    }
}
