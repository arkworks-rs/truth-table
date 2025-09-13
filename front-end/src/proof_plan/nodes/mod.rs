use super::ProofPlan;
use datafusion::logical_expr as df;
use std::sync::Arc;

// Submodules per node
pub mod aggregate;
pub mod analyze;
pub mod distinct;
pub mod explain;
pub mod extension;
pub mod filter;
pub mod join;
pub mod limit;
pub mod other;
pub mod projection;
pub mod repartition;
pub mod sort;
pub mod subquery;
pub mod subquery_alias;
pub mod table_scan;
pub mod union;
pub mod values;
pub mod window;

// Re-exports for easy access from parent module
pub use aggregate::AggregateNode;
pub use analyze::AnalyzeNode;
pub use distinct::DistinctNode;
pub use explain::ExplainNode;
pub use extension::ExtensionNode;
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

