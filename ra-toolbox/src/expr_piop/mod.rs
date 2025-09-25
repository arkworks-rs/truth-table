use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::prelude::Expr;
use planner::{arithmetized_plan::ArithmetizedPlan, ra_proof_plan::ProofPlanNodeType};

pub fn dispatch_expr_piop<F, MvPCS, UvPCS>(
    prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    arithmetized_plan_node: &ArithmetizedPlan<F, MvPCS, UvPCS>,
) where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    let inner_expr_plan = match arithmetized_plan_node.node.node_type() {
        ProofPlanNodeType::Expr(plan) => plan,
        _ => panic!("Expected Expr node"),
    };
    match inner_expr_plan {
        Expr::Alias(_) => todo!("alias expr"),
        Expr::Column(_) => todo!("column expr"),
        Expr::ScalarVariable(..) => todo!("scalar variable expr"),
        Expr::Literal(_) => todo!("literal expr"),
        Expr::BinaryExpr(_) => todo!("binary expr"),
        Expr::Like(_) => todo!("like expr"),
        Expr::SimilarTo(_) => todo!("similar to expr"),
        Expr::Not(_) => todo!("not expr"),
        Expr::IsNotNull(_) => todo!("is not null expr"),
        Expr::IsNull(_) => todo!("is null expr"),
        Expr::IsTrue(_) => todo!("is true expr"),
        Expr::IsFalse(_) => todo!("is false expr"),
        Expr::IsUnknown(_) => todo!("is unknown expr"),
        Expr::IsNotTrue(_) => todo!("is not true expr"),
        Expr::IsNotFalse(_) => todo!("is not false expr"),
        Expr::IsNotUnknown(_) => todo!("is not unknown expr"),
        Expr::Negative(_) => todo!("negative expr"),
        Expr::Between(_) => todo!("between expr"),
        Expr::Case(_) => todo!("case expr"),
        Expr::Cast(_) => todo!("cast expr"),
        Expr::TryCast(_) => todo!("try cast expr"),
        Expr::ScalarFunction(_) => todo!("scalar function expr"),
        Expr::AggregateFunction(_) => todo!("aggregate function expr"),
        Expr::WindowFunction(_) => todo!("window function expr"),
        Expr::InList(_) => todo!("in list expr"),
        Expr::Exists(_) => todo!("exists expr"),
        Expr::InSubquery(_) => todo!("in subquery expr"),
        Expr::ScalarSubquery(_) => todo!("scalar subquery expr"),
        Expr::Wildcard { .. } => todo!("wildcard expr"),
        Expr::GroupingSet(_) => todo!("grouping set expr"),
        Expr::Placeholder(_) => todo!("placeholder expr"),
        Expr::OuterReferenceColumn(..) => todo!("outer reference column expr"),
        Expr::Unnest(_) => todo!("unnest expr"),
    }
}
