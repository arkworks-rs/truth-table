use crypto::pcs::PolynomialCommitmentScheme;
use arithmetic::ark_ff::PrimeField;
use super::{ColInd, TrackedComm, TrackedPoly};



#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AggregationType {
    Count,
    Sum,
    Avg,
    Min,
    Max,
    // MEDIAN()
    // MODE()
    // STDDEV()
    // COUNT(DISTINCT)
    // PERCENTILE_CONT()
    // ...
}

#[derive(Clone, Debug, PartialEq)]
pub struct GroupByInstruction {
    pub gpd_col_indices: Vec<ColInd>,
    pub agg_instr: Vec<(ColInd, AggregationType)>, // (col_idx, agg_type)
}

/// Represents the proving advice for a `GROUP BY` operation, including
/// polynomials and precomputed advice needed to prove the correctness of
/// grouping and aggregation.
///
/// Example: Consider an IMDb movies table with columns:
/// [0: Movie ID, 1: Title, 2: Genre, 3: Year, 4: Rating, 5: Votes]
///
/// Query: "SELECT Genre, Year, COUNT(*), AVG(Rating), SUM(Votes)
///         FROM Movies
///         GROUP BY Genre, Year;"
///
/// - `grouping_cols = vec![2, 3]` (Grouping by `Genre` and `Year`)
/// - `support_cols` encodes the distinct combinations of `Genre` and `Year`.
/// - `support_sel` maps rows to their respective `Genre` and `Year`
///   combinations.
/// - `support_multiplicity` counts how many movies belong to each group.
/// - `agg_instr` includes:
///     - `(4, AggregationType::Avg, rating_avg_poly)` for the average rating.
///     - `(5, AggregationType::Sum, votes_sum_poly)` for the total votes.
///     - `(0, AggregationType::Count, count_poly)` for the count of movies.
///
/// This structure encapsulates the above details, facilitating the proving
/// process.
#[derive(Clone, PartialEq)]
pub struct GroupByInstructionWithProvingAdvice<F: PrimeField, PCS: PolynomialCommitmentScheme<F>> {
    /// Indices of the columns used for grouping.
    /// In this example, grouping by `Genre` and `Year`, so:
    /// `grouping_cols = vec![2, 3]`
    pub grouping_cols: Vec<usize>,

    /// Polynomials encoding the distinct values for each grouping column.
    /// For `Genre` and `Year`, `support_cols` might encode values like:
    /// - `Genre`: {Sci-Fi, Action, Crime}
    /// - `Year`: {2010, 2008, 1972, 1994, 2014}
    pub support_cols: Vec<TrackedPoly<F, PCS>>,

    /// A Polynomial encoding the selector column for the supports columns
    /// This is a polynomial consisting of 1s and 0s, in the case of supports
    /// column, probabely mostly 0s
    pub support_sel: TrackedPoly<F, PCS>,

    /// The multiplicity vectors used to prove that the supporta of each of the
    /// grouping cols are
    pub support_multiplicity: Vec<TrackedPoly<F, PCS>>,
    pub agg_instr: Vec<(usize, AggregationType, TrackedPoly<F, PCS>)>, /* (col_idx, agg_type,
                                                                        * agg_poly) */
}

#[derive(Clone, PartialEq)]
pub struct GroupByInstructionWithVerifyingAdvice<F: PrimeField, PCS: PolynomialCommitmentScheme<F>>
{
    /// Indices of the columns used for grouping.
    /// In this example, grouping by `Genre` and `Year`, so:
    /// `grouping_cols = vec![2, 3]` (assuming `Genre` is column 2 and `Year` is
    /// column 3).
    pub grouping_cols: Vec<usize>,

    /// Commitments to the distinct values for each grouping column.
    /// For `Genre` and `Year`, `support_cols` might include commitments to:
    /// - `Genre`: {Sci-Fi, Action, Crime}
    /// - `Year`: {2010, 2008, 1972, 1994, 2014}
    pub support_cols: Vec<TrackedComm<F, PCS>>,

    /// A commitment to the selector column for the supports columns
    /// This is a polynomial consisting of 1s and 0s, in the case of supports
    /// column, probabely mostly 0s
    pub support_sel: TrackedComm<F, PCS>,

    /// The multiplicity vectors used to prove that the supporta of each of the
    /// grouping cols are
    pub support_multiplicity: TrackedComm<F, PCS>,
    pub agg_instr: Vec<(usize, AggregationType, TrackedComm<F, PCS>)>, /* (col_idx, agg_type,
                                                                        * agg_poly) */
}