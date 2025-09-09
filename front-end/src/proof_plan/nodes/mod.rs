use super::ProofPlan;
use datafusion::logical_expr as df;

// Submodules per node
pub mod projection;
pub mod filter;
pub mod aggregate;
pub mod sort;
pub mod join;
pub mod repartition;
pub mod window;
pub mod limit;
pub mod table_scan;
pub mod union;
pub mod subquery;
pub mod subquery_alias;
pub mod distinct;
pub mod values;
pub mod explain;
pub mod analyze;
pub mod extension;
pub mod other;

// Re-exports for easy access from parent module
pub use aggregate::AggregateNode;
pub use analyze::AnalyzeNode;
pub use distinct::DistinctNode;
pub use explain::ExplainNode;
pub use filter::FilterNode;
pub use join::JoinNode;
pub use limit::LimitNode;
pub use other::OtherNode;
pub use projection::ProjectionNode;
pub use repartition::RepartitionNode;
pub use sort::SortNode;
pub use subquery::SubqueryNode;
pub use subquery_alias::SubqueryAliasNode;
pub use table_scan::TableScanNode;
pub use union::UnionNode;
pub use values::ValuesNode;
pub use window::WindowNode;
pub use extension::ExtensionNode;

/// Common interface for proof nodes to build themselves from
/// DataFusion logical nodes and to produce an IO logical plan.
pub trait ProofNode {
    type LogicalCounterpart;
    fn from_logical(lp: &Self::LogicalCounterpart) -> Self
    where
        Self: Sized;
    fn io_plan(lp: &Self::LogicalCounterpart) -> df::LogicalPlan;
}

/// The union of node variants for the proof plan
#[derive(Debug, Clone)]
pub enum ProofPlanNode {
    Projection(ProjectionNode),
    Filter(FilterNode),
    Aggregate(AggregateNode),
    Sort(SortNode),
    Join(JoinNode),
    Repartition(RepartitionNode),
    Window(WindowNode),
    Limit(LimitNode),
    TableScan(TableScanNode),
    Union(UnionNode),
    Subquery(SubqueryNode),
    SubqueryAlias(SubqueryAliasNode),
    Distinct(DistinctNode),
    Values(ValuesNode),
    Explain(ExplainNode),
    Analyze(AnalyzeNode),
    Extension(ExtensionNode),
    Other(OtherNode),
}

// Shared helper used by Projection IO plan
pub(crate) fn mask_first_col(input: &df::LogicalPlan, predicate: &df::Expr) -> df::LogicalPlan {
    use datafusion::arrow::datatypes::DataType;
    use datafusion::common::ScalarValue;
    use datafusion::logical_expr::LogicalPlanBuilder;
    use datafusion::prelude::{col, lit, when};

    let schema = input.schema();
    let mut exprs = Vec::with_capacity(schema.fields().len());
    let mut iter = schema.iter();
    if let Some((_q, first_field)) = iter.next() {
        let name = first_field.name();
        let zero_sv = match first_field.data_type() {
            DataType::Int8 => Some(ScalarValue::Int8(Some(0))),
            DataType::Int16 => Some(ScalarValue::Int16(Some(0))),
            DataType::Int32 => Some(ScalarValue::Int32(Some(0))),
            DataType::Int64 => Some(ScalarValue::Int64(Some(0))),
            DataType::UInt8 => Some(ScalarValue::UInt8(Some(0))),
            DataType::UInt16 => Some(ScalarValue::UInt16(Some(0))),
            DataType::UInt32 => Some(ScalarValue::UInt32(Some(0))),
            DataType::UInt64 => Some(ScalarValue::UInt64(Some(0))),
            DataType::Float32 => Some(ScalarValue::Float32(Some(0.0))),
            DataType::Float64 => Some(ScalarValue::Float64(Some(0.0))),
            DataType::Boolean => Some(ScalarValue::Boolean(Some(false))),
            _ => None,
        };
        if let Some(zero) = zero_sv {
            let masked = when(predicate.clone(), col(name))
                .otherwise(lit(zero))
                .expect("valid CASE WHEN expression")
                .alias(name);
            exprs.push(masked);
        } else {
            exprs.push(col(name));
        }
    }
    for (_q, field) in iter {
        exprs.push(col(field.name()));
    }
    LogicalPlanBuilder::from(std::sync::Arc::new(input.clone()))
        .project(exprs)
        .expect("projection build")
        .build()
        .expect("projection build")
}

