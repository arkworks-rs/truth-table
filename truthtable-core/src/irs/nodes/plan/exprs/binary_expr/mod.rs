use ark_piop::SnarkBackend;
use datafusion_expr::{BinaryExpr, Expr};
use derivative::Derivative;

use crate::irs::nodes::{Node, cost::ProvingCost};

pub struct ProverNode<B: SnarkBackend> {
    pub binary_expression: BinaryExpr,
    pub left: Node<B>,
    pub right: Node<B>,
}
