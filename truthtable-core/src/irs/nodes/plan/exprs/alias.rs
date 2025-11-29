use datafusion_expr::expr::Alias;

use crate::irs::nodes::NodeId;

#[derive(Clone)]
pub struct ProverAliasExprNode {
    pub parent: NodeId,
    pub alias: Alias,
}
