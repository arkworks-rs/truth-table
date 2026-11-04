//! Which `+`, `-`, `*` and scaling casts range-check their output
//! ([`check`](super::check)).
//!
//! A value only has to stay within `2^S` ([`safe_bits`](super::safe_bits)):
//! past its type it is still the right integer. So an operation is left
//! unchecked when its consumer reads the integer, not the type (another
//! `+`, `-`, `*`, a comparison, a scaling cast or a SUM argument), and that
//! consumer's own bound stays within `2^S` without the check. Its bound is
//! then its operands' bounds through the operation ([`Plan::unchecked`]),
//! not its type. A consumer whose bound would pass `2^S` has its operations
//! as operands checked, which brings them back to their types.
//!
//! Every other consumer reads a value by its type (a column, a key, the
//! result, a division), so an operation it consumes is checked, unless its
//! bound already lies in the range the check admits ([`check::admits`]).
//! That keeps every column within its type, and a column's bound is its
//! type's. A SUM's output is checked on the same terms
//! ([`sum_output_is_checked`]).
//!
//! Prover and verifier run this on the same expressions and decide alike.

use std::marker::PhantomData;
use std::sync::Weak;

use ark_ff::PrimeField;
use ark_piop::{
    SnarkBackend,
    arithmetic::errors::DataTypeError,
    errors::{SnarkError, SnarkResult},
};
use datafusion::arrow::datatypes::DataType;
use datafusion_common::DFSchema;
use datafusion_expr::{BinaryExpr, Expr, ExprSchemable, Operator, expr::Cast};

use super::{Bound, Numeric, check, numeric};
use crate::irs::nodes::plan::exprs::cast::{Rescale, rescale};
use crate::irs::nodes::{Node, PlanNode};

/// How an expression's value is consumed.
pub(crate) enum Consumer<'a> {
    /// Read by its type.
    Root,
    Operand(&'a Expr),
    /// Summed over a domain of `2^log_rows` rows.
    Sum {
        log_rows: usize,
    },
}

impl<'a> Consumer<'a> {
    /// The consumer of a value whose parent node computes `parent`, and
    /// whose own domain has `2^log_rows` rows.
    pub(crate) fn of_parent(parent: Option<&'a Expr>, log_rows: usize) -> Self {
        match parent {
            Some(Expr::AggregateFunction(aggregate))
                if aggregate.func.name().eq_ignore_ascii_case("sum") =>
            {
                Consumer::Sum { log_rows }
            }
            Some(parent @ (Expr::BinaryExpr(_) | Expr::Cast(_))) => Consumer::Operand(parent),
            _ => Consumer::Root,
        }
    }
}

pub(crate) struct Plan<'a, F> {
    schema: &'a DFSchema,
    phantom: PhantomData<F>,
}

fn strip_alias(expr: &Expr) -> &Expr {
    match expr {
        Expr::Alias(alias) => strip_alias(&alias.expr),
        other => other,
    }
}

impl<'a, F: PrimeField> Plan<'a, F> {
    pub(crate) fn new(schema: &'a DFSchema) -> Self {
        Self {
            schema,
            phantom: PhantomData,
        }
    }

    fn data_type(&self, expr: &Expr) -> SnarkResult<DataType> {
        expr.get_type(self.schema).map_err(|e| {
            SnarkError::DataTypeError(DataTypeError::NotSupported(format!(
                "the type of {expr}: {e}"
            )))
        })
    }

    /// `Some(k)` for a cast that multiplies by `10^k` into another type.
    fn scaling_cast(&self, cast: &Cast) -> SnarkResult<Option<u32>> {
        let from = self.data_type(&cast.expr)?;
        Ok(match rescale(&from, &cast.data_type) {
            Some(Rescale::Up(k)) if from != cast.data_type => Some(k),
            _ => None,
        })
    }

    /// Whether `expr` is an operation whose output this plan may leave
    /// unchecked.
    fn is_checkable(&self, expr: &Expr) -> SnarkResult<bool> {
        Ok(match expr {
            Expr::BinaryExpr(BinaryExpr { op, .. }) => {
                matches!(op, Operator::Plus | Operator::Minus | Operator::Multiply)
            }
            Expr::Cast(cast) => self.scaling_cast(cast)?.is_some(),
            _ => false,
        })
    }

    /// The bound of what `expr` computes from its operands bounded by
    /// `operand`: the result of `+`, `-`, `*` or a scaling cast, the
    /// difference a comparison checks the sign of. `None` for any other
    /// expression, and for operands without a numeric bound (strings).
    fn operation(
        &self,
        expr: &Expr,
        operand: impl Fn(&Expr) -> SnarkResult<Option<Bound>>,
    ) -> SnarkResult<Option<Bound>> {
        let Some(bound) = (match expr {
            Expr::BinaryExpr(BinaryExpr { left, op, right }) => {
                let (Some(l), Some(r)) = (operand(left)?, operand(right)?) else {
                    return Ok(None);
                };
                match op {
                    Operator::Multiply => Some(l.mul(&r)),
                    Operator::Plus | Operator::Minus | Operator::Eq | Operator::NotEq => {
                        Some(l.add(&r))
                    }
                    // `bin_cmp` rescales decimal operands to the larger scale.
                    Operator::Lt | Operator::LtEq | Operator::Gt | Operator::GtEq => {
                        let (lt, rt) = (self.data_type(left)?, self.data_type(right)?);
                        let (ls, rs) = match (numeric(&lt), numeric(&rt)) {
                            (
                                Some(Numeric::Decimal { scale: ls, .. }),
                                Some(Numeric::Decimal { scale: rs, .. }),
                            ) => (i32::from(ls), i32::from(rs)),
                            _ => (0, 0),
                        };
                        let target = ls.max(rs);
                        Some(
                            l.scale_pow10((target - ls) as u32)
                                .add(&r.scale_pow10((target - rs) as u32)),
                        )
                    }
                    _ => None,
                }
            }
            Expr::Cast(cast) => match self.scaling_cast(cast)? {
                Some(k) => operand(&cast.expr)?.map(|b| b.scale_pow10(k)),
                None => None,
            },
            _ => None,
        }) else {
            return Ok(None);
        };
        Ok(Some(bound))
    }

    /// The bound of `expr` when its own output is not range-checked. `None`
    /// for a value without a numeric bound.
    pub(crate) fn unchecked(&self, expr: &Expr) -> SnarkResult<Option<Bound>> {
        let expr = strip_alias(expr);
        if let Some(bound) = Bound::of_literal(expr) {
            return Ok(Some(bound));
        }
        if self.is_checkable(expr)? {
            return self.operation(expr, |operand| {
                self.consumed(operand, &Consumer::Operand(expr))
            });
        }
        let data_type = self.data_type(expr)?;
        Ok(match (&data_type, numeric(&data_type)) {
            (DataType::Boolean, _) | (_, Some(_)) => Some(Bound::of_type(&data_type)?),
            _ => None,
        })
    }

    /// Whether a consumer computing `parent` needs its operations as
    /// operands checked: its bound with them unchecked passes `2^S`.
    fn checks_operands(&self, parent: &Expr) -> SnarkResult<bool> {
        let bound = self.operation(parent, |operand| self.unchecked(operand))?;
        Ok(bound.is_some_and(|b| !b.fits_field::<F>()))
    }

    pub(crate) fn is_checked(&self, expr: &Expr, consumer: &Consumer) -> SnarkResult<bool> {
        let expr = strip_alias(expr);
        if !self.is_checkable(expr)? {
            return Ok(false);
        }
        let needs_type = match consumer {
            Consumer::Root => true,
            Consumer::Operand(parent) => {
                let parent = strip_alias(parent);
                !self.is_checkable(parent)? && !self.is_comparison(parent)
                    || self.checks_operands(parent)?
            }
            Consumer::Sum { log_rows } => self
                .unchecked(expr)?
                .is_none_or(|b| !b.sum(*log_rows).fits_field::<F>()),
        };
        if !needs_type {
            return Ok(false);
        }
        // A bound the check already admits makes the check redundant.
        let data_type = self.data_type(expr)?;
        Ok(!self
            .unchecked(expr)?
            .is_some_and(|bound| check::admits(&bound, &data_type)))
    }

    fn is_comparison(&self, expr: &Expr) -> bool {
        matches!(
            expr,
            Expr::BinaryExpr(BinaryExpr {
                op: Operator::Eq
                    | Operator::NotEq
                    | Operator::Lt
                    | Operator::LtEq
                    | Operator::Gt
                    | Operator::GtEq,
                ..
            })
        )
    }

    /// The bound of `expr` as `consumer` reads it.
    fn consumed(&self, expr: &Expr, consumer: &Consumer) -> SnarkResult<Option<Bound>> {
        if self.is_checked(expr, consumer)? {
            return Ok(Some(Bound::of_type(&self.data_type(expr)?)?));
        }
        self.unchecked(expr)
    }

    /// Refuses an operation, or a comparison, whose bound passes `2^S` even
    /// with its operands checked.
    pub(crate) fn ensure_fits_field(&self, expr: &Expr) -> SnarkResult<()> {
        let expr = strip_alias(expr);
        let bound = self.operation(expr, |operand| {
            self.consumed(operand, &Consumer::Operand(expr))
        })?;
        match bound {
            Some(bound) => bound.ensure_fits_field::<F>(&expr.to_string()),
            None if self.is_checkable(expr)? => Err(SnarkError::DataTypeError(
                DataTypeError::NotSupported(format!("a numeric bound for {expr}")),
            )),
            None => Ok(()),
        }
    }
}

/// The expression the node `parent` computes, if it is an expression node.
pub(crate) fn parent_expr<B: SnarkBackend>(parent: Option<&Weak<Node<B>>>) -> Option<Expr> {
    match parent?.upgrade()?.as_ref() {
        Node::Plan(PlanNode::ExprBased(node)) => Some(node.expr()),
        _ => None,
    }
}

/// The schema an expression node's operands are typed in: its scope's
/// logical plan's, the same for prover and verifier.
pub(crate) fn scope_schema<B: SnarkBackend>(scope: &[Weak<Node<B>>]) -> DFSchema {
    let scope = scope[0].upgrade().expect("an expression's scope is alive");
    match scope.as_ref() {
        Node::Plan(PlanNode::LpBased(node)) => node.lp().schema().as_ref().clone(),
        _ => panic!("an expression's scope is a relational plan node"),
    }
}

/// Whether the output of `expr`, computed by a node under `parent` on a
/// domain of `2^log_rows` rows, is range-checked; refuses it first if it
/// could leave the field.
pub(crate) fn output_is_checked<B: SnarkBackend>(
    expr: &Expr,
    parent: Option<&Weak<Node<B>>>,
    log_rows: usize,
    schema: &DFSchema,
) -> SnarkResult<bool> {
    let plan = Plan::<B::F>::new(schema);
    plan.ensure_fits_field(expr)?;
    let parent = parent_expr(parent);
    plan.is_checked(expr, &Consumer::of_parent(parent.as_ref(), log_rows))
}

/// Whether a SUM of `arg` over a domain of `2^log_rows` rows range-checks
/// its output against `output_type`: not when the argument's bound, as
/// summed, already lies in the range the check admits.
pub(crate) fn sum_output_is_checked<B: SnarkBackend>(
    arg: &Expr,
    log_rows: usize,
    output_type: &DataType,
    schema: &DFSchema,
) -> SnarkResult<bool> {
    let plan = Plan::<B::F>::new(schema);
    Ok(!plan
        .consumed(arg, &Consumer::Sum { log_rows })?
        .is_some_and(|bound| check::admits(&bound.sum(log_rows), output_type)))
}

#[cfg(test)]
mod tests;
