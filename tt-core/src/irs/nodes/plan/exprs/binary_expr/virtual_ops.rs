use ark_piop::{
    SnarkBackend, prover::structs::polynomial::TrackedPoly,
    verifier::structs::oracle::TrackedOracle,
};
use datafusion_expr::{BinaryExpr, Operator};

pub(super) fn output_virtual_table<B: SnarkBackend>(
    bin_expr: &BinaryExpr,
    left: &TrackedPoly<B>,
    right: &TrackedPoly<B>,
) -> TrackedPoly<B> {
    match bin_expr.op {
        Operator::And => left * right,
        Operator::Plus => left + right,
        Operator::Minus => left - right,
        Operator::Multiply => left * right,
        _ => panic!("unsupported operator for virtual witness"),
    }
}

pub(super) fn output_virtual_table_oracle<B: SnarkBackend>(
    bin_expr: &BinaryExpr,
    left: &TrackedOracle<B>,
    right: &TrackedOracle<B>,
) -> TrackedOracle<B> {
    match bin_expr.op {
        Operator::And => left * right,
        Operator::Plus => left + right,
        Operator::Minus => left - right,
        Operator::Multiply => left * right,
        _ => panic!("unsupported operator for virtual witness"),
    }
}
