pub(crate) mod hints;
#[cfg(test)]
mod tests;
use crate::proof_nodes::{
    HintDF, OUTPUT_PLAN_KEY,
    cost::ProvingCost,
    lps::sort::hints::{
        LEX_SORTED_SORT_EXPRESSIONS_PLAN_KEY, SHIFTED_LEX_SORTED_SORT_EXPRESSIONS_PLAN_KEY,
        TIE_INDICATOR_PLAN_KEY, build_sort_hint_dfs,
    },
    prover::{ArgProverGadget, ProverLpNode, ProverPlanNode},
    verifier::{VerifierLpNode, VerifierNode},
};
use arithmetic::{ACTIVATOR_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::PIOP,
    prover::structs::polynomial::TrackedPoly,
    verifier::{Verifier, structs::oracle::TrackedOracle},
};
use datafusion::prelude::DataFrame;
use datafusion::{
    arrow::datatypes::{DataType, Field, FieldRef},
    prelude::SessionContext,
};

use datafusion_expr::LogicalPlan;
use indexmap::IndexMap;
use ra_toolbox::lp_piop::sort_check::{SortPIOP, SortPIOPProverInput, SortPIOPVerifierInput};
use std::sync::Arc;

pub struct ProverSortExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub expr: Arc<dyn ProverPlanNode<F, MvPCS, UvPCS>>,
    /// The direction of the sort
    pub asc: bool,
    /// Whether to put Nulls before all other data values
    pub nulls_first: bool,
}

pub struct VerifierSortExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub expr: Arc<dyn VerifierNode<F, MvPCS, UvPCS>>,
    /// The direction of the sort
    pub asc: bool,
    /// Whether to put Nulls before all other data values
    pub nulls_first: bool,
}
