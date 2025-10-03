use arithmetic::table::{TrackedTable, TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    piop::DeepClone,
    prover::Prover,
};
use derivative::Derivative;

#[derive(Clone, Debug, PartialEq)]
pub struct SelectConfig<F: PrimeField> {
    pub where_clause: WhereClause<F>,
}

// TODO: All of these structs and enums are also defined in datafusion sql
// parse. We should ultimately merge the interfaces.

#[derive(Clone, Debug, PartialEq)]
pub enum WhereClause<F: PrimeField> {
    Eq(usize, F),
    Neq(usize, F),
    Geq(usize, F),
    Leq(usize, F),
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct SelectProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub input_table: TrackedTable<F, MvPCS, UvPCS>,
    pub output_table: TrackedTable<F, MvPCS, UvPCS>,
    pub select_conf: SelectConfig<F>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for SelectProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        let input_table = self.input_table.deep_clone(prover.clone());
        let output_table = self.output_table.deep_clone(prover);
        Self {
            input_table,
            output_table,
            select_conf: self.select_conf.clone(),
        }
    }
}

#[derive(Clone)]
pub struct SelectVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub input_tracked_Table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub output_tracked_Table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub select_conf: SelectConfig<F>,
}
