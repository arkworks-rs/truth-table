#[cfg(test)]
mod test;

use arithmetic::{
    col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{Prover, structs::polynomial::TrackedPoly},
    verifier::{Verifier, structs::oracle::TrackedOracle},
};
use col_toolbox::perm_check::{PermPIOP, PermPIOPProverInput, PermPIOPVerifierInput};
use datafusion::logical_expr::Sort;
use derivative::Derivative;

#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct SortTrackedCol<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// The expression to sort on
    pub expr: TrackedCol<F, MvPCS, UvPCS>,
    /// The direction of the sort
    pub asc: bool,
    /// Whether to put Nulls before all other data values
    pub nulls_first: bool,
}

impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for SortTrackedCol<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, new_prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            expr: self.expr.deep_clone(new_prover),
            asc: self.asc,
            nulls_first: self.nulls_first,
        }
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct SortTrackedColOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    /// The expression to sort on
    pub expr: TrackedColOracle<F, MvPCS, UvPCS>,
    /// The direction of the sort
    pub asc: bool,
    /// Whether to put Nulls before all other data values
    pub nulls_first: bool,
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct SortPIOPProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub sort: Sort,
    pub input_sort_exprs: Vec<SortTrackedCol<F, MvPCS, UvPCS>>,
    pub output_sort_exprs: Vec<SortTrackedCol<F, MvPCS, UvPCS>>,
    pub input_table: TrackedTable<F, MvPCS, UvPCS>,
    pub output_table: TrackedTable<F, MvPCS, UvPCS>,
}
#[derive(Derivative)]
#[derivative(
    Clone(bound = "MvPCS: PCS<F>"),
    PartialEq(bound = "MvPCS: PCS<F>"),
    Debug(bound = "")
)]
pub struct SortPIOPVerifierInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub sort: Sort,
    pub input_sort_exprs: Vec<SortTrackedColOracle<F, MvPCS, UvPCS>>,
    pub output_sort_exprs: Vec<SortTrackedColOracle<F, MvPCS, UvPCS>>,
    pub input_table: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub output_table: TrackedTableOracle<F, MvPCS, UvPCS>,
}
impl<F, MvPCS, UvPCS> DeepClone<F, MvPCS, UvPCS> for SortPIOPProverInput<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    fn deep_clone(&self, new_prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            sort: self.sort.clone(),
            input_sort_exprs: self
                .input_sort_exprs
                .iter()
                .map(|expr| expr.deep_clone(new_prover.clone()))
                .collect(),
            output_sort_exprs: self
                .output_sort_exprs
                .iter()
                .map(|expr| expr.deep_clone(new_prover.clone()))
                .collect(),
            input_table: self.input_table.deep_clone(new_prover.clone()),
            output_table: self.output_table.deep_clone(new_prover),
        }
    }
}

pub struct SortPIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    _field: std::marker::PhantomData<F>,
    _mvpcs: std::marker::PhantomData<MvPCS>,
    _uvpcs: std::marker::PhantomData<UvPCS>,
}

impl<F, MvPCS, UvPCS> PIOP<F, MvPCS, UvPCS> for SortPIOP<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ProverInput = SortPIOPProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = SortPIOPVerifierInput<F, MvPCS, UvPCS>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        // TODO
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let row_fold_challenges: Vec<F> = (0..input.input_table.num_data_tracked_cols())
            .map(|_| {
                prover
                    .get_and_append_challenge(b"sort-row-fold")
                    .expect("failed to draw folding challenge")
            })
            .collect();

        // Hash every row (across all data columns) into a single fingerprint so we can
        // reason about row movement without tracking each column separately.
        // Mirror the prover’s row hashing so the verifier checks against the same
        // fingerprints.
        let input_row_fingerprint = input
            .input_table
            .fold_all_data_columns(&row_fold_challenges);
        let output_row_fingerprint = input
            .output_table
            .fold_all_data_columns(&row_fold_challenges);

        let key_components_len = 1 + input.input_sort_exprs.len();
        let key_fold_challenges: Vec<F> = (0..key_components_len)
            .map(|_| {
                prover
                    .get_and_append_challenge(b"sort-key-fold")
                    .expect("failed to draw key folding challenge")
            })
            .collect();

        // Mix the row fingerprint with each sort expression using the same random
        // challenges so the permutation gadget can work with a single column
        // per table.
        let mut input_key_components = Vec::with_capacity(key_components_len);
        input_key_components.push(input_row_fingerprint);
        input_key_components.extend(
            input
                .input_sort_exprs
                .into_iter()
                .map(|tracked| tracked.expr),
        );
        let mut input_key_col =
            linear_combine_tracked_cols(input_key_components, &key_fold_challenges);
        input_key_col = apply_activator_to_tracked_col(
            input_key_col,
            input.input_table.activator_tracked_poly(),
        );

        let mut output_key_components = Vec::with_capacity(key_components_len);
        output_key_components.push(output_row_fingerprint);
        output_key_components.extend(
            input
                .output_sort_exprs
                .into_iter()
                .map(|tracked| tracked.expr),
        );
        let mut output_key_col =
            linear_combine_tracked_cols(output_key_components, &key_fold_challenges);
        output_key_col = apply_activator_to_tracked_col(
            output_key_col,
            input.output_table.activator_tracked_poly(),
        );

        let perm_input = PermPIOPProverInput {
            left_col: input_key_col,
            right_col: output_key_col,
        };

        // If the hashed key columns match as a multiset, the output is a permutation
        // of the input that respects the requested ordering.

        PermPIOP::<F, MvPCS, UvPCS>::prove(prover, perm_input)?;

        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let SortPIOPVerifierInput {
            sort: _,
            input_sort_exprs,
            output_sort_exprs,
            input_table,
            output_table,
        } = input;

        assert_eq!(
            input_sort_exprs.len(),
            output_sort_exprs.len(),
            "sort expressions mismatch between input and output"
        );
        let num_table_cols = input_table.num_data_tracked_col_oracles();
        assert!(
            num_table_cols > 0,
            "input table must expose at least one data column oracle"
        );
        assert_eq!(
            num_table_cols,
            output_table.num_data_tracked_col_oracles(),
            "input and output tables must expose the same number of data column oracles"
        );

        let row_fold_challenges: Vec<F> = (0..num_table_cols)
            .map(|_| {
                verifier
                    .get_and_append_challenge(b"sort-row-fold")
                    .expect("failed to draw folding challenge")
            })
            .collect();

        let input_row_fingerprint = input_table.fold_all_data_columns(&row_fold_challenges);
        let output_row_fingerprint = output_table.fold_all_data_columns(&row_fold_challenges);

        let key_components_len = 1 + input_sort_exprs.len();
        let key_fold_challenges: Vec<F> = (0..key_components_len)
            .map(|_| {
                verifier
                    .get_and_append_challenge(b"sort-key-fold")
                    .expect("failed to draw key folding challenge")
            })
            .collect();

        let mut input_key_components = Vec::with_capacity(key_components_len);
        input_key_components.push(input_row_fingerprint);
        input_key_components.extend(input_sort_exprs.into_iter().map(|tracked| tracked.expr));
        let mut input_key_col =
            linear_combine_tracked_col_oracles(input_key_components, &key_fold_challenges);
        input_key_col = apply_activator_to_tracked_col_oracle(
            input_key_col,
            input_table.activator_tracked_poly(),
        );

        let mut output_key_components = Vec::with_capacity(key_components_len);
        output_key_components.push(output_row_fingerprint);
        output_key_components.extend(output_sort_exprs.into_iter().map(|tracked| tracked.expr));
        let mut output_key_col =
            linear_combine_tracked_col_oracles(output_key_components, &key_fold_challenges);
        output_key_col = apply_activator_to_tracked_col_oracle(
            output_key_col,
            output_table.activator_tracked_poly(),
        );

        let perm_input = PermPIOPVerifierInput {
            left_tracked_col_oracle: input_key_col,
            right_tracked_col_oracle: output_key_col,
        };

        // Enforce that the prover supplied a permutation between the compressed key
        // columns.

        PermPIOP::<F, MvPCS, UvPCS>::verify(verifier, perm_input)?;

        Ok(())
    }
}

// Random linear combination of tracked columns that produces a single
// fingerprint.
fn linear_combine_tracked_cols<F, MvPCS, UvPCS>(
    cols: Vec<TrackedCol<F, MvPCS, UvPCS>>,
    challenges: &[F],
) -> TrackedCol<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    assert!(!cols.is_empty(), "expected at least one column to combine");
    assert_eq!(
        cols.len(),
        challenges.len(),
        "challenge count must match column count"
    );

    let mut cols_iter = cols.into_iter();
    let mut activator = None;

    let first = cols_iter.next().expect("non-empty iterator");
    let mut combined_poly: TrackedPoly<F, MvPCS, UvPCS> = first.data_tracked_poly();
    combined_poly *= challenges[0];
    activator = first.activator_tracked_poly();

    for (col, chall) in cols_iter.zip(challenges.iter().skip(1)) {
        if let Some(ref existing) = activator {
            if let Some(col_act) = col.activator_tracked_poly() {
                existing.assert_same_tracker(&col_act);
            }
        } else {
            activator = col.activator_tracked_poly();
        }
        let mut term = col.data_tracked_poly();
        term *= *chall;
        combined_poly += &term;
    }

    TrackedCol::new(combined_poly, activator, None)
}

// Verifier-side counterpart: combine tracked column oracles under the same
// challenges.
fn linear_combine_tracked_col_oracles<F, MvPCS, UvPCS>(
    cols: Vec<TrackedColOracle<F, MvPCS, UvPCS>>,
    challenges: &[F],
) -> TrackedColOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    assert!(
        !cols.is_empty(),
        "expected at least one column oracle to combine"
    );
    assert_eq!(
        cols.len(),
        challenges.len(),
        "challenge count must match column oracle count"
    );

    let mut cols_iter = cols.into_iter();
    let mut activator = None;

    let first = cols_iter.next().expect("non-empty iterator");
    let mut combined_oracle: TrackedOracle<F, MvPCS, UvPCS> = first.data_tracked_oracle();
    combined_oracle *= challenges[0];
    activator = first.activator_tracked_oracle();

    for (col, chall) in cols_iter.zip(challenges.iter().skip(1)) {
        if let Some(ref existing) = activator {
            if let Some(col_act) = col.activator_tracked_oracle() {
                existing.assert_same_tracker(&col_act);
            }
        } else {
            activator = col.activator_tracked_oracle();
        }
        let mut term = col.data_tracked_oracle();
        term *= *chall;
        combined_oracle += &term;
    }

    TrackedColOracle::new(combined_oracle, activator, None)
}

fn apply_activator_to_tracked_col<F, MvPCS, UvPCS>(
    col: TrackedCol<F, MvPCS, UvPCS>,
    override_activator: Option<TrackedPoly<F, MvPCS, UvPCS>>,
) -> TrackedCol<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    let field_ref = col.field_ref();
    let data_poly = col.data_tracked_poly();
    let existing_activator = col.activator_tracked_poly();

    if let (Some(new_act), Some(existing)) = (&override_activator, &existing_activator) {
        existing.assert_same_tracker(new_act);
    }

    let final_activator = match override_activator {
        Some(act) => Some(act),
        None => existing_activator,
    };

    TrackedCol::new(data_poly, final_activator, field_ref)
}

fn apply_activator_to_tracked_col_oracle<F, MvPCS, UvPCS>(
    col: TrackedColOracle<F, MvPCS, UvPCS>,
    override_activator: Option<TrackedOracle<F, MvPCS, UvPCS>>,
) -> TrackedColOracle<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    let field_ref = col.field_ref();
    let data_oracle = col.data_tracked_oracle();
    let existing_activator = col.activator_tracked_oracle();

    if let (Some(new_act), Some(existing)) = (&override_activator, &existing_activator) {
        existing.assert_same_tracker(new_act);
    }

    let final_activator = match override_activator {
        Some(act) => Some(act),
        None => existing_activator,
    };

    TrackedColOracle::new(data_oracle, final_activator, field_ref)
}
