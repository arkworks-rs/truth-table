use datafusion::{logical_expr::LogicalPlan, prelude::Expr};
use std::fmt;

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum NodeId {
    LP(LogicalPlan),
    Expr(Expr),
    None,
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeId::LP(plan) => write!(f, "LogicalPlan({})", plan),
            NodeId::Expr(expr) => write!(f, "Expr({})", expr),
            NodeId::None => write!(f, "None"),
        }
    }
}

impl NodeId {
    pub fn to_lp(&self) -> Option<&LogicalPlan> {
        match self {
            NodeId::LP(plan) => Some(plan),
            _ => None,
        }
    }

    pub fn to_expr(&self) -> Option<&Expr> {
        match self {
            NodeId::Expr(expr) => Some(expr),
            _ => None,
        }
    }
}
