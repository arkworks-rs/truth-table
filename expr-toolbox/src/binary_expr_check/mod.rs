mod operators;
#[cfg(test)]
mod test;
use crate::prelude::*;
use datafusion::logical_expr::{Operator, expr::BinaryExpr};

pub struct BinaryExprCheckPiop;

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for BinaryExprCheckPiop
{
    type ProverInput = ExprPIOPProverInput<F, MvPCS, UvPCS, BinaryExpr>;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = ExprPIOPVerifierInput<F, MvPCS, UvPCS, BinaryExpr>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(_input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        todo!()
    }

    fn prove_inner(
        _prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let left_operand = input.expr.left.as_ref();
        let right_operand = input.expr.right.as_ref();
        let operator = &input.expr.op;
        match input.expr.op {
            Operator::Eq => todo!(),
            Operator::NotEq => todo!(),
            Operator::Lt => todo!(),
            Operator::LtEq => todo!(),
            Operator::Gt => todo!(),
            Operator::GtEq => todo!(),
            Operator::Plus => Ok(()),
            Operator::Minus => Ok(()),
            Operator::Multiply => Ok(()),
            Operator::Divide => todo!(),
            Operator::Modulo => todo!(),
            Operator::And => todo!(),
            Operator::Or => todo!(),
            Operator::IsDistinctFrom => todo!(),
            Operator::IsNotDistinctFrom => todo!(),
            Operator::RegexMatch => todo!(),
            Operator::RegexIMatch => todo!(),
            Operator::RegexNotMatch => todo!(),
            Operator::RegexNotIMatch => todo!(),
            Operator::LikeMatch => todo!(),
            Operator::ILikeMatch => todo!(),
            Operator::NotLikeMatch => todo!(),
            Operator::NotILikeMatch => todo!(),
            Operator::BitwiseAnd => todo!(),
            Operator::BitwiseOr => todo!(),
            Operator::BitwiseXor => todo!(),
            Operator::BitwiseShiftRight => todo!(),
            Operator::BitwiseShiftLeft => todo!(),
            Operator::StringConcat => todo!(),
            Operator::AtArrow => todo!(),
            Operator::ArrowAt => todo!(),
            _ => todo!(),
        }
    }

    fn verify_inner(
        _verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        match input.expr.op {
            Operator::Eq => todo!(),
            Operator::NotEq => todo!(),
            Operator::Lt => todo!(),
            Operator::LtEq => todo!(),
            Operator::Gt => todo!(),
            Operator::GtEq => todo!(),
            Operator::Plus => Ok(()),
            Operator::Minus => Ok(()),
            Operator::Multiply => Ok(()),
            Operator::Divide => todo!(),
            Operator::Modulo => todo!(),
            Operator::And => todo!(),
            Operator::Or => todo!(),
            Operator::IsDistinctFrom => todo!(),
            Operator::IsNotDistinctFrom => todo!(),
            Operator::RegexMatch => todo!(),
            Operator::RegexIMatch => todo!(),
            Operator::RegexNotMatch => todo!(),
            Operator::RegexNotIMatch => todo!(),
            Operator::LikeMatch => todo!(),
            Operator::ILikeMatch => todo!(),
            Operator::NotLikeMatch => todo!(),
            Operator::NotILikeMatch => todo!(),
            Operator::BitwiseAnd => todo!(),
            Operator::BitwiseOr => todo!(),
            Operator::BitwiseXor => todo!(),
            Operator::BitwiseShiftRight => todo!(),
            Operator::BitwiseShiftLeft => todo!(),
            Operator::StringConcat => todo!(),
            Operator::AtArrow => todo!(),
            Operator::ArrowAt => todo!(),
            _ => todo!(),
        }
    }
}
