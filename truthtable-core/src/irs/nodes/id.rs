use std::fmt;

use datafusion_expr::{Expr, LogicalPlan};

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum NodeId {
    PLAN(PlanNodeId),
    GADGET(GadgetNodeId),
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeId::PLAN(plan) => write!(f, "Plan({})", plan),
            NodeId::GADGET(expr) => write!(f, "Gadget({})", expr),
        }
    }
}

impl NodeId {
    pub fn to_plan(&self) -> Option<&PlanNodeId> {
        match self {
            NodeId::PLAN(plan) => Some(plan),
            _ => None,
        }
    }

    pub fn to_gadget(&self) -> Option<&GadgetNodeId> {
        match self {
            NodeId::GADGET(expr) => Some(expr),
            _ => None,
        }
    }
}



#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct GadgetNodeId {
    plan: PlanNodeId,
    gadget_ancestors: Vec<String>,
}

impl fmt::Display for GadgetNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "plan: ({}), gadget_ancestors: {:?}",
            self.plan, self.gadget_ancestors
        )
    }
}




#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum PlanNodeId {
    LP(LogicalPlan),
    EXPR(Expr),
}

impl fmt::Display for PlanNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanNodeId::LP(plan) => write!(f, "LogicalPlan({})", plan),
            PlanNodeId::EXPR(expr) => write!(f, "Expr({})", expr),
        }
    }
}

impl PlanNodeId {
    pub fn to_lp(&self) -> Option<&LogicalPlan> {
        match self {
            PlanNodeId::LP(plan) => Some(plan),
            _ => None,
        }
    }

    pub fn to_expr(&self) -> Option<&Expr> {
        match self {
            PlanNodeId::EXPR(expr) => Some(expr),
            _ => None,
        }
    }
}
