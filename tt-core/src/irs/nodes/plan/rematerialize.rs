use crate::irs::nodes::{
    IsLpNode, IsNode, IsPlanNode, Node, PlanNode, ProverNodeOps, VerifierNodeOps,
};
use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
use ark_piop::SnarkBackend;
use datafusion::arrow::{
    array::{ArrayRef, BooleanArray, Int64Array},
    compute::{concat, concat_batches},
    record_batch::RecordBatch,
};
use datafusion::functions_window::expr_fn::row_number;
use datafusion::prelude::{DataFrame, SessionContext};
use datafusion_common::{
    Column, DFSchemaRef, DataFusionError, Result as DataFusionResult, ScalarValue,
};
use datafusion_expr::expr::Sort as SortExpr;
use datafusion_expr::{
    Expr, ExprFunctionExt, LogicalPlan, Operator, binary_expr, col, lit,
    logical_plan::{Extension, UserDefinedLogicalNode},
};
use std::any::Any;
use std::cmp::Ordering;
use std::hash::Hasher;
use std::sync::Arc;
use tokio::runtime::RuntimeFlavor;

pub struct ProverNode<B>
where
    B: SnarkBackend,
{
    input: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for ProverNode<B> {
    fn name(&self) -> String {
        "Rematerialize".to_string()
    }

    fn display(&self) -> String {
        format!("Rematerialize\nInput: {}", self.input.name())
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

    fn children(&self) -> Vec<Arc<Node<B>>> {
        vec![self.input.clone()]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
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
}

impl<B: SnarkBackend> IsPlanNode<B> for ProverNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        None
    }

    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let input_hint_df = match self.input.as_ref() {
            Node::Plan(plan_node) => plan_node.output(),
            Node::Gadget(_) => panic!("Rematerialize input cannot be a gadget node"),
        };
        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(input_hint_df.data_frame().clone())
                .expect("rematerialize row-id sort should succeed");
        let remat = build_output_dataframe(input_df);
        crate::irs::nodes::hints::HintDF::new_materialized(remat)
    }
}

impl<B: SnarkBackend> IsLpNode<B> for ProverNode<B> {
    fn from_lp(_plan: LogicalPlan, _self_ref: std::sync::Weak<Node<B>>) -> Self
    where
        Self: Sized,
    {
        let extension = match _plan {
            LogicalPlan::Extension(extension) => extension,
            _ => panic!("Expected LogicalPlan::Extension for Rematerialize"),
        };
        let remat = extension
            .node
            .as_any()
            .downcast_ref::<RematerializeLogicalNode>()
            .expect("Rematerialize extension node");
        let input = crate::irs::tree::Tree::<B>::from_logical_plan(remat.input())
            .root()
            .clone();
        Self::new(input)
    }

    fn lp(&self) -> LogicalPlan {
        let input_lp = match self.input.as_ref() {
            Node::Plan(PlanNode::LpBased(node)) => node.lp(),
            _ => panic!("Rematerialize input must be an LP node"),
        };
        wrap_logical_plan(input_lp)
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for ProverNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
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
}

impl<B: SnarkBackend> ProverNode<B> {
    pub fn new(input: Arc<Node<B>>) -> Self {
        Self { input }
    }
}

#[derive(Debug, Clone)]
pub struct RematerializeLogicalNode {
    input: Arc<LogicalPlan>,
    schema: DFSchemaRef,
}

impl RematerializeLogicalNode {
    pub fn new(input: LogicalPlan) -> Self {
        let schema = input.schema().clone();
        Self {
            input: Arc::new(input),
            schema,
        }
    }

    pub fn input(&self) -> &LogicalPlan {
        self.input.as_ref()
    }

    fn key(&self) -> String {
        format!("{:?}", self.input)
    }
}

impl UserDefinedLogicalNode for RematerializeLogicalNode {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn name(&self) -> &str {
        "Rematerialize"
    }

    fn inputs(&self) -> Vec<&LogicalPlan> {
        vec![self.input.as_ref()]
    }

    fn schema(&self) -> &DFSchemaRef {
        &self.schema
    }

    fn check_invariants(
        &self,
        _check: datafusion_expr::logical_plan::InvariantLevel,
        _plan: &LogicalPlan,
    ) -> datafusion_common::Result<()> {
        Ok(())
    }

    fn expressions(&self) -> Vec<Expr> {
        Vec::new()
    }

    fn fmt_for_explain(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Rematerialize")
    }

    fn with_exprs_and_inputs(
        &self,
        exprs: Vec<Expr>,
        inputs: Vec<LogicalPlan>,
    ) -> datafusion_common::Result<Arc<dyn UserDefinedLogicalNode>> {
        if !exprs.is_empty() {
            return Err(DataFusionError::Plan(
                "Rematerialize does not accept expressions".to_string(),
            ));
        }
        if inputs.len() != 1 {
            return Err(DataFusionError::Plan(
                "Rematerialize expects a single input".to_string(),
            ));
        }
        Ok(Arc::new(RematerializeLogicalNode::new(
            inputs.into_iter().next().unwrap(),
        )))
    }

    fn dyn_hash(&self, state: &mut dyn Hasher) {
        state.write(self.name().as_bytes());
        state.write(self.key().as_bytes());
    }

    fn dyn_eq(&self, other: &dyn UserDefinedLogicalNode) -> bool {
        other
            .as_any()
            .downcast_ref::<Self>()
            .map(|o| self.key() == o.key())
            .unwrap_or(false)
    }

    fn dyn_ord(&self, other: &dyn UserDefinedLogicalNode) -> Option<Ordering> {
        let other_key = other.as_any().downcast_ref::<Self>()?.key();
        Some(self.key().cmp(&other_key))
    }
}

pub fn wrap_logical_plan(input: LogicalPlan) -> LogicalPlan {
    LogicalPlan::Extension(Extension {
        node: Arc::new(RematerializeLogicalNode::new(input)),
    })
}

fn pad_to_power_of_two(df: DataFrame) -> DataFrame {
    pad_to_power_of_two_inner(df).expect("rematerialize output padding should succeed")
}

fn pad_to_power_of_two_inner(df: DataFrame) -> DataFusionResult<DataFrame> {
    let batches = collect_blocking(df.clone())?;
    if batches.is_empty() {
        return pad_empty_df(df);
    }
    let schema_ref = batches[0].schema();
    let batch_refs: Vec<&RecordBatch> = batches.iter().collect();
    let combined = concat_batches(&schema_ref, batch_refs)?;
    let row_count = combined.num_rows();
    let target = row_count.next_power_of_two();
    let pad = target - row_count;
    if pad == 0 {
        return Ok(df);
    }

    let mut output_arrays = Vec::with_capacity(schema_ref.fields().len());
    for (idx, field) in schema_ref.fields().iter().enumerate() {
        let base = combined.column(idx).clone();
        let padded = if field.name() == ACTIVATOR_COL_NAME {
            let pad_arr: ArrayRef = Arc::new(BooleanArray::from(vec![false; pad]));
            concat(&[base.as_ref(), pad_arr.as_ref()])?
        } else if field.name() == ROW_ID_COL_NAME {
            let pad_vals: Vec<i64> = (row_count as i64..target as i64).collect();
            let pad_arr: ArrayRef = Arc::new(Int64Array::from(pad_vals));
            concat(&[base.as_ref(), pad_arr.as_ref()])?
        } else {
            let last = ScalarValue::try_from_array(base.as_ref(), row_count - 1)?;
            let pad_arr = last.to_array_of_size(pad)?;
            concat(&[base.as_ref(), pad_arr.as_ref()])?
        };
        output_arrays.push(padded);
    }

    let out_batch = RecordBatch::try_new(schema_ref, output_arrays)?;
    let ctx = SessionContext::new();
    ctx.read_batch(out_batch)
}

fn pad_empty_df(df: DataFrame) -> DataFusionResult<DataFrame> {
    let schema_ref = df.schema().as_arrow();
    let target = 1;
    let mut output_arrays = Vec::with_capacity(schema_ref.fields().len());
    for field in schema_ref.fields() {
        if field.name() == ACTIVATOR_COL_NAME {
            output_arrays.push(Arc::new(BooleanArray::from(vec![false; target])) as _);
        } else if field.name() == ROW_ID_COL_NAME {
            output_arrays.push(Arc::new(Int64Array::from(vec![0; target])) as _);
        } else if field.is_nullable() {
            let null = ScalarValue::try_new_null(field.data_type())?;
            output_arrays.push(null.to_array_of_size(target)?);
        } else {
            let zero = ScalarValue::new_zero(field.data_type())
                .unwrap_or_else(|_| ScalarValue::try_new_null(field.data_type()).unwrap());
            output_arrays.push(zero.to_array_of_size(target)?);
        }
    }

    let out_batch = RecordBatch::try_new(Arc::new(schema_ref.clone()), output_arrays)?;
    let ctx = SessionContext::new();
    ctx.read_batch(out_batch)
}

fn collect_blocking(df: DataFrame) -> DataFusionResult<Vec<RecordBatch>> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => match handle.runtime_flavor() {
            RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(df.collect()))
            }
            RuntimeFlavor::CurrentThread => std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(df.collect())
            })
            .join()
            .expect("rematerialize collect thread should join"),
            _ => handle.block_on(df.collect()),
        },
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(df.collect()),
    }
}

fn build_output_dataframe(input: DataFrame) -> DataFrame {
    let filtered = input
        .filter(col(ACTIVATOR_COL_NAME).eq(lit(true)))
        .expect("rematerialize activator filter should succeed");

    let mut row_id_sort_exprs: Vec<SortExpr> = filtered
        .schema()
        .iter()
        .filter_map(|(qualifier, field)| {
            if field.name() != ROW_ID_COL_NAME {
                return None;
            }
            Some(Expr::Column(Column::new(qualifier.cloned(), ROW_ID_COL_NAME)).sort(true, true))
        })
        .collect();
    if row_id_sort_exprs.is_empty() {
        row_id_sort_exprs = Vec::new();
    }

    let mut data_exprs = Vec::new();
    for (qualifier, field) in filtered.schema().iter() {
        if field.name() == ACTIVATOR_COL_NAME || field.name() == ROW_ID_COL_NAME {
            continue;
        }
        data_exprs.push(Expr::Column(Column::new(qualifier.cloned(), field.name())));
    }

    let row_number_expr = row_number()
        .partition_by(Vec::new())
        .order_by(row_id_sort_exprs.clone())
        .build()
        .expect("rematerialize row_number window should build")
        .alias("__row_number__");

    let mut projection_exprs = data_exprs;
    projection_exprs.push(lit(true).alias(ACTIVATOR_COL_NAME));
    projection_exprs.push(row_number_expr);

    let projected = filtered
        .select(projection_exprs)
        .expect("rematerialize projection should succeed");

    let mut final_exprs = Vec::new();
    for (qualifier, field) in projected.schema().iter() {
        if field.name() == "__row_number__" {
            continue;
        }
        final_exprs.push(Expr::Column(Column::new(qualifier.cloned(), field.name())));
    }
    final_exprs.push(
        binary_expr(col("__row_number__"), Operator::Minus, lit(1_i64)).alias(ROW_ID_COL_NAME),
    );

    let remat = projected
        .select(final_exprs)
        .expect("rematerialize row_id projection should succeed");

    pad_to_power_of_two(remat)
}

#[cfg(test)]
mod tests {
    use super::build_output_dataframe;
    use arithmetic::{ACTIVATOR_COL_NAME, ROW_ID_COL_NAME};
    use datafusion::arrow::{
        array::{ArrayRef, BooleanArray, Int64Array},
        datatypes::{DataType, Field, Schema},
        record_batch::RecordBatch,
    };
    use datafusion::prelude::SessionContext;
    use std::sync::Arc;

    async fn run_rematerialize_test(
        input_columns: &[(Field, ArrayRef)],
        expected_columns: &[(Field, ArrayRef)],
    ) {
        let ctx = SessionContext::new();
        let input_schema = Arc::new(Schema::new(
            input_columns
                .iter()
                .map(|(field, _)| field.clone())
                .collect::<Vec<_>>(),
        ));
        let input_batch = RecordBatch::try_new(
            input_schema,
            input_columns
                .iter()
                .map(|(_, array)| Arc::clone(array))
                .collect(),
        )
        .expect("input batch construction should succeed");
        let input_df = ctx
            .read_batch(input_batch)
            .expect("failed to read input batch");

        let remat = build_output_dataframe(input_df);
        let batches = remat.collect().await.expect("rematerialize collect");

        let expected_schema = Arc::new(Schema::new(
            expected_columns
                .iter()
                .map(|(field, _)| field.clone())
                .collect::<Vec<_>>(),
        ));
        let expected_batch = RecordBatch::try_new(
            expected_schema,
            expected_columns
                .iter()
                .map(|(_, array)| Arc::clone(array))
                .collect(),
        )
        .expect("expected batch construction should succeed");
        assert_eq!(batches, vec![expected_batch]);
    }

    #[tokio::test]
    async fn rematerialize_filters_and_pads() {
        run_rematerialize_test(
            &[
                (
                    Field::new("val", DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![10, 20, 30, 40])),
                ),
                (
                    Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![0, 1, 2, 3])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, false, true, true])),
                ),
            ],
            &[
                (
                    Field::new("val", DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![10, 30, 40, 40])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, true, true, false])),
                ),
                (
                    Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![0, 1, 2, 3])),
                ),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn rematerialize_empty_after_filter() {
        run_rematerialize_test(
            &[
                (
                    Field::new("val", DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![5, 6])),
                ),
                (
                    Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![0, 1])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![false, false])),
                ),
            ],
            &[
                (
                    Field::new("val", DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![0])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![false])),
                ),
                (
                    Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![0])),
                ),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn rematerialize_compacts_sparse_active_rows() {
        run_rematerialize_test(
            &[
                (
                    Field::new("val", DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![10, 20, 30, 40, 50, 60, 70, 80])),
                ),
                (
                    Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![0, 1, 2, 3, 4, 5, 6, 7])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![
                        true, false, false, true, false, false, false, true,
                    ])),
                ),
            ],
            &[
                (
                    Field::new("val", DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![10, 40, 80, 80])),
                ),
                (
                    Field::new(ACTIVATOR_COL_NAME, DataType::Boolean, false),
                    Arc::new(BooleanArray::from(vec![true, true, true, false])),
                ),
                (
                    Field::new(ROW_ID_COL_NAME, DataType::Int64, false),
                    Arc::new(Int64Array::from(vec![0, 1, 2, 3])),
                ),
            ],
        )
        .await;
    }
}
