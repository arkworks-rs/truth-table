use std::{collections::HashMap, fmt, ops::Deref};

use arithmetic::col::{ArithCol, ArithColOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::Prover,
    verifier::Verifier,
};
use datafusion::logical_expr::Expr;

pub mod aggregate_function_check;
pub mod alias_check;
pub mod between_check;
pub mod binary_expr_check;
pub mod case_check;
pub mod cast_check;
pub mod column_check;
pub mod exists_check;
pub mod grouping_set_check;
pub mod in_list_check;
pub mod in_subquery_check;
pub mod is_false_check;
pub mod is_not_false_check;
pub mod is_not_null_check;
pub mod is_not_true_check;
pub mod is_not_unknown_check;
pub mod is_null_check;
pub mod is_true_check;
pub mod is_unknown_check;
pub mod like_check;
pub mod literal_check;
pub mod negative_check;
pub mod not_check;
pub mod outer_reference_column_check;
pub mod placeholder_check;
pub mod scalar_function_check;
pub mod scalar_subquery_check;
pub mod scalar_variable_check;
pub mod similar_to_check;
pub mod try_cast_check;
pub mod unnest_check;
pub mod wildcard_check;
pub mod window_function_check;

#[derive(Clone)]
pub struct ExprPIOPProverInput<F, MvPCS, UvPCS, T>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    T: Clone + std::fmt::Debug,
{
    pub expr: T,
    pub expr_cols: HashMap<Expr, ArithCol<F, MvPCS, UvPCS>>,
}

impl<F, MvPCS, UvPCS, T> fmt::Debug for ExprPIOPProverInput<F, MvPCS, UvPCS, T>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    T: Clone + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExprPIOPProverInput")
            .field("expr", &self.expr)
            .field("expr_cols_len", &self.expr_cols.len())
            .finish()
    }
}

impl<F, MvPCS, UvPCS, T> ExprPIOPProverInput<F, MvPCS, UvPCS, T>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    T: Clone + std::fmt::Debug,
{
    pub fn new(expr: T, expr_cols: HashMap<Expr, ArithCol<F, MvPCS, UvPCS>>) -> Self {
        Self { expr, expr_cols }
    }

    pub fn into_inner(self) -> T {
        self.expr
    }

    pub fn into_parts(self) -> (T, HashMap<Expr, ArithCol<F, MvPCS, UvPCS>>) {
        (self.expr, self.expr_cols)
    }

    pub fn map_expr<U>(self, expr: U) -> ExprPIOPProverInput<F, MvPCS, UvPCS, U>
    where
        U: Clone + std::fmt::Debug,
    {
        ExprPIOPProverInput {
            expr,
            expr_cols: self.expr_cols,
        }
    }
}

impl<F, MvPCS, UvPCS, T> Deref for ExprPIOPProverInput<F, MvPCS, UvPCS, T>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    T: Clone + std::fmt::Debug,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.expr
    }
}

impl<F, MvPCS, UvPCS, T> DeepClone<F, MvPCS, UvPCS> for ExprPIOPProverInput<F, MvPCS, UvPCS, T>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + Clone,
    UvPCS: PCS<F, Poly = LDE<F>> + Clone,
    T: Clone + std::fmt::Debug,
{
    fn deep_clone(&self, new_prover: Prover<F, MvPCS, UvPCS>) -> Self {
        let expr_cols = self
            .expr_cols
            .iter()
            .map(|(expr, col)| (expr.clone(), col.deep_clone(new_prover.clone())))
            .collect();
        Self {
            expr: self.expr.clone(),
            expr_cols,
        }
    }
}

#[derive(Clone)]
pub struct ExprPIOPVerifierInput<F, MvPCS, UvPCS, T>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    T: Clone + std::fmt::Debug,
{
    pub expr: T,
    pub expr_cols: HashMap<Expr, ArithColOracle<F, MvPCS, UvPCS>>,
}

impl<F, MvPCS, UvPCS, T> fmt::Debug for ExprPIOPVerifierInput<F, MvPCS, UvPCS, T>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    T: Clone + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExprPIOPVerifierInput")
            .field("expr", &self.expr)
            .field("expr_cols_len", &self.expr_cols.len())
            .finish()
    }
}

impl<F, MvPCS, UvPCS, T> ExprPIOPVerifierInput<F, MvPCS, UvPCS, T>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    T: Clone + std::fmt::Debug,
{
    pub fn new(expr: T, expr_cols: HashMap<Expr, ArithColOracle<F, MvPCS, UvPCS>>) -> Self {
        Self { expr, expr_cols }
    }

    pub fn into_inner(self) -> T {
        self.expr
    }

    pub fn into_parts(self) -> (T, HashMap<Expr, ArithColOracle<F, MvPCS, UvPCS>>) {
        (self.expr, self.expr_cols)
    }

    pub fn map_expr<U>(self, expr: U) -> ExprPIOPVerifierInput<F, MvPCS, UvPCS, U>
    where
        U: Clone + std::fmt::Debug,
    {
        ExprPIOPVerifierInput {
            expr,
            expr_cols: self.expr_cols,
        }
    }
}

impl<F, MvPCS, UvPCS, T> Deref for ExprPIOPVerifierInput<F, MvPCS, UvPCS, T>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    T: Clone + std::fmt::Debug,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.expr
    }
}

pub(crate) mod prelude {
    pub use crate::{ExprPIOPProverInput, ExprPIOPVerifierInput};
    pub use ark_ff::PrimeField;
    pub use ark_piop::{
        arithmetic::mat_poly::{lde::LDE, mle::MLE},
        errors::SnarkResult,
        pcs::PCS,
        piop::PIOP,
        prover::Prover,
        verifier::Verifier,
    };
}

pub struct ExprCheckPiop;

impl ExprCheckPiop {
    fn dispatch_prove<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: ExprPIOPProverInput<F, MvPCS, UvPCS, Expr>,
    ) -> SnarkResult<()> {
        let (expr, expr_cols) = input.into_parts();
        match expr {
            Expr::Alias(alias) => crate::alias_check::AliasCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(alias, expr_cols),
            ),
            Expr::Column(column) => crate::column_check::ColumnCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(column, expr_cols),
            ),
            Expr::ScalarVariable(data_type, identifiers) => {
                crate::scalar_variable_check::ScalarVariableCheckPiop::prove(
                    prover,
                    ExprPIOPProverInput::new((data_type, identifiers), expr_cols),
                )
            },
            Expr::Literal(literal) => crate::literal_check::LiteralCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(literal, expr_cols),
            ),
            Expr::BinaryExpr(binary) => crate::binary_expr_check::BinaryExprCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(binary, expr_cols),
            ),
            Expr::Like(like) => crate::like_check::LikeCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(like, expr_cols),
            ),
            Expr::SimilarTo(like) => crate::similar_to_check::SimilarToCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(like, expr_cols),
            ),
            Expr::Not(expr) => crate::not_check::NotCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(expr, expr_cols),
            ),
            Expr::IsNotNull(expr) => crate::is_not_null_check::IsNotNullCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(expr, expr_cols),
            ),
            Expr::IsNull(expr) => crate::is_null_check::IsNullCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(expr, expr_cols),
            ),
            Expr::IsTrue(expr) => crate::is_true_check::IsTrueCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(expr, expr_cols),
            ),
            Expr::IsFalse(expr) => crate::is_false_check::IsFalseCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(expr, expr_cols),
            ),
            Expr::IsUnknown(expr) => crate::is_unknown_check::IsUnknownCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(expr, expr_cols),
            ),
            Expr::IsNotTrue(expr) => crate::is_not_true_check::IsNotTrueCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(expr, expr_cols),
            ),
            Expr::IsNotFalse(expr) => crate::is_not_false_check::IsNotFalseCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(expr, expr_cols),
            ),
            Expr::IsNotUnknown(expr) => crate::is_not_unknown_check::IsNotUnknownCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(expr, expr_cols),
            ),
            Expr::Negative(expr) => crate::negative_check::NegativeCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(expr, expr_cols),
            ),
            Expr::Between(between) => crate::between_check::BetweenCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(between, expr_cols),
            ),
            Expr::Case(case_expr) => crate::case_check::CaseCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(case_expr, expr_cols),
            ),
            Expr::Cast(cast) => crate::cast_check::CastCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(cast, expr_cols),
            ),
            Expr::TryCast(try_cast) => crate::try_cast_check::TryCastCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(try_cast, expr_cols),
            ),
            Expr::ScalarFunction(scalar_fn) => {
                crate::scalar_function_check::ScalarFunctionCheckPiop::prove(
                    prover,
                    ExprPIOPProverInput::new(scalar_fn, expr_cols),
                )
            },
            Expr::AggregateFunction(agg_fn) => {
                crate::aggregate_function_check::AggregateFunctionCheckPiop::prove(
                    prover,
                    ExprPIOPProverInput::new(agg_fn, expr_cols),
                )
            },
            Expr::WindowFunction(window_fn) => {
                crate::window_function_check::WindowFunctionCheckPiop::prove(
                    prover,
                    ExprPIOPProverInput::new(window_fn, expr_cols),
                )
            },
            Expr::InList(in_list) => crate::in_list_check::InListCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(in_list, expr_cols),
            ),
            Expr::Exists(exists) => crate::exists_check::ExistsCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(exists, expr_cols),
            ),
            Expr::InSubquery(in_subquery) => crate::in_subquery_check::InSubqueryCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(in_subquery, expr_cols),
            ),
            Expr::ScalarSubquery(subquery) => {
                crate::scalar_subquery_check::ScalarSubqueryCheckPiop::prove(
                    prover,
                    ExprPIOPProverInput::new(subquery, expr_cols),
                )
            },
            Expr::Wildcard { qualifier, options } => {
                crate::wildcard_check::WildcardCheckPiop::prove(
                    prover,
                    ExprPIOPProverInput::new((qualifier, options), expr_cols),
                )
            },
            Expr::GroupingSet(grouping_set) => {
                crate::grouping_set_check::GroupingSetCheckPiop::prove(
                    prover,
                    ExprPIOPProverInput::new(grouping_set, expr_cols),
                )
            },
            Expr::Placeholder(placeholder) => {
                crate::placeholder_check::PlaceholderCheckPiop::prove(
                    prover,
                    ExprPIOPProverInput::new(placeholder, expr_cols),
                )
            },
            Expr::OuterReferenceColumn(data_type, column) => {
                crate::outer_reference_column_check::OuterReferenceColumnCheckPiop::prove(
                    prover,
                    ExprPIOPProverInput::new((data_type, column), expr_cols),
                )
            },
            Expr::Unnest(unnest) => crate::unnest_check::UnnestCheckPiop::prove(
                prover,
                ExprPIOPProverInput::new(unnest, expr_cols),
            ),
        }
    }

    fn dispatch_verify<
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>>,
        UvPCS: PCS<F, Poly = LDE<F>>,
    >(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: ExprPIOPVerifierInput<F, MvPCS, UvPCS, Expr>,
    ) -> SnarkResult<()> {
        let (expr, expr_cols) = input.into_parts();
        match expr {
            Expr::Alias(alias) => crate::alias_check::AliasCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(alias, expr_cols),
            ),
            Expr::Column(column) => crate::column_check::ColumnCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(column, expr_cols),
            ),
            Expr::ScalarVariable(data_type, identifiers) => {
                crate::scalar_variable_check::ScalarVariableCheckPiop::verify(
                    verifier,
                    ExprPIOPVerifierInput::new((data_type, identifiers), expr_cols),
                )
            },
            Expr::Literal(literal) => crate::literal_check::LiteralCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(literal, expr_cols),
            ),
            Expr::BinaryExpr(binary) => crate::binary_expr_check::BinaryExprCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(binary, expr_cols),
            ),
            Expr::Like(like) => crate::like_check::LikeCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(like, expr_cols),
            ),
            Expr::SimilarTo(like) => crate::similar_to_check::SimilarToCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(like, expr_cols),
            ),
            Expr::Not(expr) => crate::not_check::NotCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(expr, expr_cols),
            ),
            Expr::IsNotNull(expr) => crate::is_not_null_check::IsNotNullCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(expr, expr_cols),
            ),
            Expr::IsNull(expr) => crate::is_null_check::IsNullCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(expr, expr_cols),
            ),
            Expr::IsTrue(expr) => crate::is_true_check::IsTrueCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(expr, expr_cols),
            ),
            Expr::IsFalse(expr) => crate::is_false_check::IsFalseCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(expr, expr_cols),
            ),
            Expr::IsUnknown(expr) => crate::is_unknown_check::IsUnknownCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(expr, expr_cols),
            ),
            Expr::IsNotTrue(expr) => crate::is_not_true_check::IsNotTrueCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(expr, expr_cols),
            ),
            Expr::IsNotFalse(expr) => crate::is_not_false_check::IsNotFalseCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(expr, expr_cols),
            ),
            Expr::IsNotUnknown(expr) => crate::is_not_unknown_check::IsNotUnknownCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(expr, expr_cols),
            ),
            Expr::Negative(expr) => crate::negative_check::NegativeCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(expr, expr_cols),
            ),
            Expr::Between(between) => crate::between_check::BetweenCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(between, expr_cols),
            ),
            Expr::Case(case_expr) => crate::case_check::CaseCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(case_expr, expr_cols),
            ),
            Expr::Cast(cast) => crate::cast_check::CastCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(cast, expr_cols),
            ),
            Expr::TryCast(try_cast) => crate::try_cast_check::TryCastCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(try_cast, expr_cols),
            ),
            Expr::ScalarFunction(scalar_fn) => {
                crate::scalar_function_check::ScalarFunctionCheckPiop::verify(
                    verifier,
                    ExprPIOPVerifierInput::new(scalar_fn, expr_cols),
                )
            },
            Expr::AggregateFunction(agg_fn) => {
                crate::aggregate_function_check::AggregateFunctionCheckPiop::verify(
                    verifier,
                    ExprPIOPVerifierInput::new(agg_fn, expr_cols),
                )
            },
            Expr::WindowFunction(window_fn) => {
                crate::window_function_check::WindowFunctionCheckPiop::verify(
                    verifier,
                    ExprPIOPVerifierInput::new(window_fn, expr_cols),
                )
            },
            Expr::InList(in_list) => crate::in_list_check::InListCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(in_list, expr_cols),
            ),
            Expr::Exists(exists) => crate::exists_check::ExistsCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(exists, expr_cols),
            ),
            Expr::InSubquery(in_subquery) => crate::in_subquery_check::InSubqueryCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(in_subquery, expr_cols),
            ),
            Expr::ScalarSubquery(subquery) => {
                crate::scalar_subquery_check::ScalarSubqueryCheckPiop::verify(
                    verifier,
                    ExprPIOPVerifierInput::new(subquery, expr_cols),
                )
            },
            Expr::Wildcard { qualifier, options } => {
                crate::wildcard_check::WildcardCheckPiop::verify(
                    verifier,
                    ExprPIOPVerifierInput::new((qualifier, options), expr_cols),
                )
            },
            Expr::GroupingSet(grouping_set) => {
                crate::grouping_set_check::GroupingSetCheckPiop::verify(
                    verifier,
                    ExprPIOPVerifierInput::new(grouping_set, expr_cols),
                )
            },
            Expr::Placeholder(placeholder) => {
                crate::placeholder_check::PlaceholderCheckPiop::verify(
                    verifier,
                    ExprPIOPVerifierInput::new(placeholder, expr_cols),
                )
            },
            Expr::OuterReferenceColumn(data_type, column) => {
                crate::outer_reference_column_check::OuterReferenceColumnCheckPiop::verify(
                    verifier,
                    ExprPIOPVerifierInput::new((data_type, column), expr_cols),
                )
            },
            Expr::Unnest(unnest) => crate::unnest_check::UnnestCheckPiop::verify(
                verifier,
                ExprPIOPVerifierInput::new(unnest, expr_cols),
            ),
        }
    }

    #[cfg(feature = "honest-prover")]
    fn dispatch_honest<
        F: PrimeField,
        MvPCS: PCS<F, Poly = MLE<F>>,
        UvPCS: PCS<F, Poly = LDE<F>>,
    >(
        input: ExprPIOPProverInput<F, MvPCS, UvPCS, Expr>,
    ) -> SnarkResult<()> {
        let (expr, expr_cols) = input.into_parts();
        match expr {
            Expr::Alias(alias) => crate::alias_check::AliasCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(alias, expr_cols),
            ),
            Expr::Column(column) => crate::column_check::ColumnCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(column, expr_cols),
            ),
            Expr::ScalarVariable(data_type, identifiers) =>
                crate::scalar_variable_check::ScalarVariableCheckPiop::honest_prover_check(
                    ExprPIOPProverInput::new((data_type, identifiers), expr_cols),
                ),
            Expr::Literal(literal) => crate::literal_check::LiteralCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(literal, expr_cols),
            ),
            Expr::BinaryExpr(binary) =>
                crate::binary_expr_check::BinaryExprCheckPiop::honest_prover_check(
                    ExprPIOPProverInput::new(binary, expr_cols),
                ),
            Expr::Like(like) => crate::like_check::LikeCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(like, expr_cols),
            ),
            Expr::SimilarTo(like) => crate::similar_to_check::SimilarToCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(like, expr_cols),
            ),
            Expr::Not(expr) => crate::not_check::NotCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(expr, expr_cols),
            ),
            Expr::IsNotNull(expr) => crate::is_not_null_check::IsNotNullCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(expr, expr_cols),
            ),
            Expr::IsNull(expr) => crate::is_null_check::IsNullCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(expr, expr_cols),
            ),
            Expr::IsTrue(expr) => crate::is_true_check::IsTrueCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(expr, expr_cols),
            ),
            Expr::IsFalse(expr) => crate::is_false_check::IsFalseCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(expr, expr_cols),
            ),
            Expr::IsUnknown(expr) => crate::is_unknown_check::IsUnknownCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(expr, expr_cols),
            ),
            Expr::IsNotTrue(expr) => crate::is_not_true_check::IsNotTrueCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(expr, expr_cols),
            ),
            Expr::IsNotFalse(expr) => crate::is_not_false_check::IsNotFalseCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(expr, expr_cols),
            ),
            Expr::IsNotUnknown(expr) =>
                crate::is_not_unknown_check::IsNotUnknownCheckPiop::honest_prover_check(
                    ExprPIOPProverInput::new(expr, expr_cols),
                ),
            Expr::Negative(expr) => crate::negative_check::NegativeCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(expr, expr_cols),
            ),
            Expr::Between(between) => crate::between_check::BetweenCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(between, expr_cols),
            ),
            Expr::Case(case_expr) => crate::case_check::CaseCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(case_expr, expr_cols),
            ),
            Expr::Cast(cast) => crate::cast_check::CastCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(cast, expr_cols),
            ),
            Expr::TryCast(try_cast) => crate::try_cast_check::TryCastCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(try_cast, expr_cols),
            ),
            Expr::ScalarFunction(scalar_fn) =>
                crate::scalar_function_check::ScalarFunctionCheckPiop::honest_prover_check(
                    ExprPIOPProverInput::new(scalar_fn, expr_cols),
                ),
            Expr::AggregateFunction(agg_fn) =>
                crate::aggregate_function_check::AggregateFunctionCheckPiop::honest_prover_check(
                    ExprPIOPProverInput::new(agg_fn, expr_cols),
                ),
            Expr::WindowFunction(window_fn) =>
                crate::window_function_check::WindowFunctionCheckPiop::honest_prover_check(
                    ExprPIOPProverInput::new(window_fn, expr_cols),
                ),
            Expr::InList(in_list) => crate::in_list_check::InListCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(in_list, expr_cols),
            ),
            Expr::Exists(exists) => crate::exists_check::ExistsCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(exists, expr_cols),
            ),
            Expr::InSubquery(in_subquery) =>
                crate::in_subquery_check::InSubqueryCheckPiop::honest_prover_check(
                    ExprPIOPProverInput::new(in_subquery, expr_cols),
                ),
            Expr::ScalarSubquery(subquery) =>
                crate::scalar_subquery_check::ScalarSubqueryCheckPiop::honest_prover_check(
                    ExprPIOPProverInput::new(subquery, expr_cols),
                ),
            Expr::Wildcard { qualifier, options } =>
                crate::wildcard_check::WildcardCheckPiop::honest_prover_check(
                    ExprPIOPProverInput::new((qualifier, options), expr_cols),
                ),
            Expr::GroupingSet(grouping_set) =>
                crate::grouping_set_check::GroupingSetCheckPiop::honest_prover_check(
                    ExprPIOPProverInput::new(grouping_set, expr_cols),
                ),
            Expr::Placeholder(placeholder) =>
                crate::placeholder_check::PlaceholderCheckPiop::honest_prover_check(
                    ExprPIOPProverInput::new(placeholder, expr_cols),
                ),
            Expr::OuterReferenceColumn(data_type, column) =>
                crate::outer_reference_column_check::OuterReferenceColumnCheckPiop::honest_prover_check(
                    ExprPIOPProverInput::new((data_type, column), expr_cols),
                ),
            Expr::Unnest(unnest) => crate::unnest_check::UnnestCheckPiop::honest_prover_check(
                ExprPIOPProverInput::new(unnest, expr_cols),
            ),
        }
    }
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for ExprCheckPiop
{
    type ProverInput = ExprPIOPProverInput<F, MvPCS, UvPCS, Expr>;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = ExprPIOPVerifierInput<F, MvPCS, UvPCS, Expr>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        Self::dispatch_honest::<F, MvPCS, UvPCS>(input)
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        Self::dispatch_prove::<F, MvPCS, UvPCS>(prover, input)
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        Self::dispatch_verify::<F, MvPCS, UvPCS>(verifier, input)
    }
}
