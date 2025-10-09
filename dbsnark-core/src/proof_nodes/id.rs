

use std::fmt;
use datafusion::{logical_expr::LogicalPlan, prelude::Expr};

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum NodeId {
    LP(LogicalPlan),
    Expr(Expr),
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeId::LP(plan) => write!(f, "LogicalPlan({})", plan.to_string()),
            NodeId::Expr(expr) => write!(f, "Expr({})", expr),
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
