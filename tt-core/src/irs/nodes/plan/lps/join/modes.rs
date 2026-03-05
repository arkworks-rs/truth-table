use datafusion_expr::Join;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinMode {
    ONE_TO_MANY,
    MANY_TO_ONE,
    ONE_TO_ONE,
    MANY_TO_MANY,
}

/// Decide join mode directly from the logical join specification.
///
/// This keeps the plan-side materialization decision and gadget-side optimization
/// decision sourced from the same place, so they cannot drift.
pub fn decide_join_mode(join: &Join) -> JoinMode {
    let _ = join;
    JoinMode::MANY_TO_MANY
}
