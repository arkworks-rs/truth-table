use std::{any::Any, collections::HashMap, sync::Arc};

use datafusion::{
    logical_expr::LogicalPlan,
    prelude::{Expr, SessionContext},
};

mod graphs;
mod nodes;
mod plans;
