use datafusion::prelude::SessionContext;
use datafusion_common::{DataFusionError, Result as DataFusionResult};
use datafusion_expr::logical_plan::Extension;
use datafusion_expr::LogicalPlan;
use datafusion_proto::bytes::{
    logical_plan_from_bytes_with_extension_codec, logical_plan_to_bytes_with_extension_codec,
};
use datafusion_proto::logical_plan::LogicalExtensionCodec;
use tt_core::errors::TTResult;
use tt_core::irs::nodes::plan::rematerialize::RematerializeLogicalNode;

#[derive(Debug, Default)]
pub struct TTLogicalExtensionCodec;

impl LogicalExtensionCodec for TTLogicalExtensionCodec {
    fn try_decode(
        &self,
        _buf: &[u8],
        inputs: &[LogicalPlan],
        _ctx: &SessionContext,
    ) -> DataFusionResult<Extension> {
        if inputs.len() != 1 {
            return Err(DataFusionError::Plan(
                "Rematerialize expects a single input".to_string(),
            ));
        }
        Ok(Extension {
            node: std::sync::Arc::new(RematerializeLogicalNode::new(inputs[0].clone())),
        })
    }

    fn try_encode(&self, node: &Extension, _buf: &mut Vec<u8>) -> DataFusionResult<()> {
        if node.node.as_any().is::<RematerializeLogicalNode>() {
            return Ok(());
        }
        Err(DataFusionError::NotImplemented(
            "LogicalExtensionCodec missing for extension node".to_string(),
        ))
    }

    fn try_decode_table_provider(
        &self,
        _buf: &[u8],
        _table_ref: &datafusion_common::TableReference,
        _schema: std::sync::Arc<datafusion::arrow::datatypes::Schema>,
        _ctx: &SessionContext,
    ) -> DataFusionResult<std::sync::Arc<dyn datafusion::datasource::TableProvider>> {
        Err(DataFusionError::NotImplemented(
            "LogicalExtensionCodec missing for table provider".to_string(),
        ))
    }

    fn try_encode_table_provider(
        &self,
        _table_ref: &datafusion_common::TableReference,
        _node: std::sync::Arc<dyn datafusion::datasource::TableProvider>,
        _buf: &mut Vec<u8>,
    ) -> DataFusionResult<()> {
        Err(DataFusionError::NotImplemented(
            "LogicalExtensionCodec missing for table provider".to_string(),
        ))
    }
}

pub fn serialize_logical_plan(plan: &LogicalPlan) -> TTResult<Vec<u8>> {
    let codec = TTLogicalExtensionCodec::default();
    let bytes = logical_plan_to_bytes_with_extension_codec(plan, &codec)?;
    Ok(bytes.to_vec())
}

pub fn deserialize_logical_plan(bytes: &[u8]) -> TTResult<LogicalPlan> {
    let codec = TTLogicalExtensionCodec::default();
    let ctx = SessionContext::new();
    Ok(logical_plan_from_bytes_with_extension_codec(
        bytes, &ctx, &codec,
    )?)
}
