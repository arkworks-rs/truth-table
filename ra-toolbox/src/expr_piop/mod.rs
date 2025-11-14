pub mod aggregate_function;
pub mod alias;
pub mod between;
pub mod binary_expr;
pub mod case;
pub mod cast;
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

use ark_piop::errors::SnarkResult;

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
