pub mod aggregate_function;
pub mod alias;
pub mod between;
pub mod binary_expr;
pub mod case;
pub mod cast;
pub mod column;
pub mod exists;
pub mod grouping_set;
pub mod in_list;
pub mod in_subquery;
pub mod is_false;
pub mod is_not_false;
pub mod is_not_null;
pub mod is_not_true;
pub mod is_not_unknown;
pub mod is_null;
pub mod is_true;
pub mod is_unknown;
pub mod like;
pub mod literal;
pub mod negative;
pub mod not;
pub mod outer_reference_column;
pub mod placeholder;
pub mod scalar_function;
pub mod scalar_subquery;
pub mod scalar_variable;
pub mod similar_to;
pub mod try_cast;
pub mod unnest;
pub mod wildcard;
pub mod window_function;

use std::sync::Arc;

use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
};
use datafusion::prelude::Expr;
use planner::{
    arithmetized_plan::ArithmetizedGraph,
    ra_proof_plan::{ProofPlan, ProofPlanNodeId},
};

pub type ExprPIOPResult = SnarkResult<()>;

macro_rules! impl_expr_piop_deep_clone {
    ($ty:ty) => {
        impl<F, MvPCS, UvPCS> ark_piop::piop::DeepClone<F, MvPCS, UvPCS> for $ty
        where
            F: ark_ff::PrimeField,
            MvPCS: PCS<F, Poly = MLE<F>>,
            UvPCS: PCS<F, Poly = LDE<F>>,
        {
            fn deep_clone(&self, _new_prover: ark_piop::prover::Prover<F, MvPCS, UvPCS>) -> Self {
                self.clone()
            }
        }
    };
}

pub(crate) use impl_expr_piop_deep_clone;

use crate::expr_piop::column::{ColumnExprPIOP, ColumnPIOPProverInput};

pub fn dispatch_expr_piop<F, MvPCS, UvPCS>(
    prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    _proof_node: &Arc<dyn ProofPlan>,
    _arith_plan: &ArithmetizedGraph<F, MvPCS, UvPCS>,
) -> ExprPIOPResult
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    let inner_expr_plan = match _proof_node.node_id() {
        ProofPlanNodeId::Expr(plan) => plan,
        _ => panic!("Expected Expr node"),
    };

    match inner_expr_plan {
        Expr::Alias(_) => todo!("Alias PIOP not implemented"),
        Expr::Column(c) => {
            let column_piop_prover_input = ColumnPIOPProverInput { column: c.clone() };
            ColumnExprPIOP::prove(prover, column_piop_prover_input)
        },
        Expr::ScalarVariable(..) => todo!("ScalarVariable PIOP not implemented"),
        Expr::Literal(_) => todo!("Literal PIOP not implemented"),
        Expr::BinaryExpr(_) => todo!("BinaryExpr PIOP not implemented"),
        Expr::Like(_) => todo!("Like PIOP not implemented"),
        Expr::SimilarTo(_) => todo!("SimilarTo PIOP not implemented"),
        Expr::Not(_) => todo!("Not PIOP not implemented"),
        Expr::IsNotNull(_) => todo!("IsNotNull PIOP not implemented"),
        Expr::IsNull(_) => todo!("IsNull PIOP not implemented"),
        Expr::IsTrue(_) => todo!("IsTrue PIOP not implemented"),
        Expr::IsFalse(_) => todo!("IsFalse PIOP not implemented"),
        Expr::IsUnknown(_) => todo!("IsUnknown PIOP not implemented"),
        Expr::IsNotTrue(_) => todo!("IsNotTrue PIOP not implemented"),
        Expr::IsNotFalse(_) => todo!("IsNotFalse PIOP not implemented"),
        Expr::IsNotUnknown(_) => todo!("IsNotUnknown PIOP not implemented"),
        Expr::Negative(_) => todo!("Negative PIOP not implemented"),
        Expr::Between(_) => todo!("Between PIOP not implemented"),
        Expr::Case(_) => todo!("Case PIOP not implemented"),
        Expr::Cast(_) => todo!("Cast PIOP not implemented"),
        Expr::TryCast(_) => todo!("TryCast PIOP not implemented"),
        Expr::ScalarFunction(_) => todo!("ScalarFunction PIOP not implemented"),
        Expr::AggregateFunction(_) => todo!("AggregateFunction PIOP not implemented"),
        Expr::WindowFunction(_) => todo!("WindowFunction PIOP not implemented"),
        Expr::InList(_) => todo!("InList PIOP not implemented"),
        Expr::Exists(_) => todo!("Exists PIOP not implemented"),
        Expr::InSubquery(_) => todo!("InSubquery PIOP not implemented"),
        Expr::ScalarSubquery(_) => todo!("ScalarSubquery PIOP not implemented"),
        Expr::Wildcard { .. } => todo!("Wildcard PIOP not implemented"),
        Expr::GroupingSet(_) => todo!("GroupingSet PIOP not implemented"),
        Expr::Placeholder(_) => todo!("Placeholder PIOP not implemented"),
        Expr::OuterReferenceColumn(..) => todo!("OuterReferenceColumn PIOP not implemented"),
        Expr::Unnest(_) => todo!("Unnest PIOP not implemented"),
    }
}
