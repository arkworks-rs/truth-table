//! The prover's rank of a string sort key, for planning the sort check's
//! witnesses: each row's string mapped to its base column's rank
//! (TruthTable++ §3.2), the value of the key's `__rank` segment.

use std::sync::Arc;

use arithmetic::encoding::BaseRanks;
use datafusion::arrow::array::{ArrayRef, UInt32Array};
use datafusion::arrow::datatypes::DataType;
use datafusion::prelude::DataFrame;
use datafusion_common::{Column, DataFusionError, Result as DataFusionResult};
use datafusion_expr::{
    ColumnarValue, Expr, ScalarFunctionArgs, ScalarUDF, ScalarUDFImpl, Signature, Volatility,
    expr::ScalarFunction,
};

/// The rank of each distinct value of `column` in the scan's rows,
/// computed with the encoder's own function.
pub(crate) fn base_ranks(scan: &DataFrame, column: &str) -> DataFusionResult<BaseRanks> {
    let (qualifier, _) = scan
        .schema()
        .iter()
        .find(|(_, field)| field.name() == column)
        .ok_or_else(|| DataFusionError::Plan(format!("the scan has no column {column}")))?;
    let distinct = scan
        .clone()
        .select(vec![Expr::Column(Column::new(qualifier.cloned(), column))])?
        .distinct()?;
    let batches = crate::session::block_on(distinct.collect())?;
    let mut values = Vec::new();
    for batch in &batches {
        values.extend(
            string_values(batch.column(0))?
                .into_iter()
                .map(|value| value.map(<[u8]>::to_vec)),
        );
    }
    let ranks = arithmetic::encoding::base_ranks(values.iter().map(Option::as_deref));
    #[cfg(feature = "test-utils")]
    let ranks = crate::test_utils::dishonest_prover::forge_base_ranks(ranks);
    Ok(ranks)
}

/// `key`'s rank under `ranks`, as a UInt32 column. A value missing from
/// `ranks` is not a base string: an error.
pub(crate) fn rank_expr(key: Expr, ranks: BaseRanks) -> Expr {
    let udf = RankUdf {
        ranks: Arc::new(ranks),
        signature: Signature::any(1, Volatility::Immutable),
    };
    Expr::ScalarFunction(ScalarFunction::new_udf(
        Arc::new(ScalarUDF::new_from_impl(udf)),
        vec![key],
    ))
}

struct RankUdf {
    ranks: Arc<BaseRanks>,
    signature: Signature,
}

impl std::fmt::Debug for RankUdf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tt_rank({} values)", self.ranks.len())
    }
}

impl ScalarUDFImpl for RankUdf {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn name(&self) -> &str {
        "tt_rank"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _arg_types: &[DataType]) -> DataFusionResult<DataType> {
        Ok(DataType::UInt32)
    }

    fn invoke_with_args(&self, args: ScalarFunctionArgs) -> DataFusionResult<ColumnarValue> {
        let input = args.args[0].clone().into_array(args.number_rows)?;
        let ranks = string_values(&input)?
            .into_iter()
            .map(|value| match value {
                // NULL ranks 0, as in the encoder.
                None => Ok(0),
                Some(bytes) => self.ranks.get(bytes).copied().ok_or_else(|| {
                    DataFusionError::Execution(format!(
                        "tt_rank: {:?} is not a value of the base column",
                        String::from_utf8_lossy(bytes)
                    ))
                }),
            })
            .collect::<DataFusionResult<Vec<u32>>>()?;
        let out: ArrayRef = Arc::new(UInt32Array::from(ranks));
        Ok(ColumnarValue::Array(out))
    }
}

fn string_values(array: &ArrayRef) -> DataFusionResult<Vec<Option<&[u8]>>> {
    arithmetic::encoding::string_values(array.as_ref()).ok_or_else(|| {
        DataFusionError::Execution(format!(
            "tt_rank: expected a string column, got {}",
            array.data_type()
        ))
    })
}
