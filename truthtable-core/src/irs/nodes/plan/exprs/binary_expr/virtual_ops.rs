use arithmetic::{
    col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use datafusion::arrow::datatypes::{Field, FieldRef};
use datafusion_expr::{BinaryExpr, Operator};
use indexmap::IndexMap;

use crate::proof_nodes::exprs::{prover::ProverBinaryExprNode, verifier::VerifierBinaryExprNode};

impl<F, MvPCS, UvPCS> ProverBinaryExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    pub(super) fn output_virtual_table(
        bin_expr: &BinaryExpr,
        left_col: &TrackedCol<F, MvPCS, UvPCS>,
        right_col: &TrackedCol<F, MvPCS, UvPCS>,
        log_size: usize,
    ) -> TrackedTable<F, MvPCS, UvPCS> {
        let output_data_tracked_poly = match bin_expr.op {
            Operator::And => {
                let data_out = &left_col.data_tracked_poly() * &right_col.data_tracked_poly();

                match (
                    left_col.activator_tracked_poly(),
                    right_col.activator_tracked_poly(),
                ) {
                    (Some(l), Some(r)) => &(&l * &r) * &data_out,
                    (Some(l), None) => &l * &data_out,
                    (None, Some(r)) => &r * &data_out,
                    (None, None) => data_out,
                }
            }
            Operator::Plus => {
                let data_out = &left_col.data_tracked_poly() + &right_col.data_tracked_poly();

                match (
                    left_col.activator_tracked_poly(),
                    right_col.activator_tracked_poly(),
                ) {
                    (Some(l), Some(r)) => &(&l * &r) * &data_out,
                    (Some(l), None) => &l * &data_out,
                    (None, Some(r)) => &r * &data_out,
                    (None, None) => data_out,
                }
            }
            Operator::Minus => {
                let data_out = &left_col.data_tracked_poly() - &right_col.data_tracked_poly();

                match (
                    left_col.activator_tracked_poly(),
                    right_col.activator_tracked_poly(),
                ) {
                    (Some(l), Some(r)) => &(&l * &r) * &data_out,
                    (Some(l), None) => &l * &data_out,
                    (None, Some(r)) => &r * &data_out,
                    (None, None) => data_out,
                }
            }
            Operator::Multiply => {
                let data_out = &left_col.data_tracked_poly() * &right_col.data_tracked_poly();

                match (
                    left_col.activator_tracked_poly(),
                    right_col.activator_tracked_poly(),
                ) {
                    (Some(l), Some(r)) => &(&l * &r) * &data_out,
                    (Some(l), None) => &l * &data_out,
                    (None, Some(r)) => &r * &data_out,
                    (None, None) => data_out,
                }
            }
            _ => panic!("unsupported operator for virtual witness"),
        };
        let field_ref = if let Some(f) = left_col.field_ref() {
            let base_field = f.as_ref();
            let mut new_field = Field::new(
                bin_expr.to_string(),
                base_field.data_type().clone(),
                base_field.is_nullable(),
            );
            if !base_field.metadata().is_empty() {
                new_field = new_field.with_metadata(base_field.metadata().clone());
            }
            FieldRef::new(new_field)
        } else {
            FieldRef::new(Field::new(
                bin_expr.to_string(),
                datafusion::arrow::datatypes::DataType::Null,
                false,
            ))
        };
        let output_activator = match (
            left_col.activator_tracked_poly(),
            right_col.activator_tracked_poly(),
        ) {
            (Some(l), Some(r)) => Some(&l * &r),
            (Some(l), None) => Some(l.clone()),
            (None, Some(r)) => Some(r.clone()),
            (None, None) => None,
        };
        let mut columns = IndexMap::from([(field_ref, output_data_tracked_poly)]);
        if let Some(activator_poly) = output_activator {
            let activator_field = FieldRef::new(Field::new(
                arithmetic::ACTIVATOR_COL_NAME,
                datafusion::arrow::datatypes::DataType::Boolean,
                true,
            ));
            columns.insert(activator_field, activator_poly);
        }

        TrackedTable::new(None, columns, log_size)
    }
}

impl<F, MvPCS, UvPCS> VerifierBinaryExprNode<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static + Send + Sync,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static + Send + Sync,
{
    pub(super) fn output_virtual_table(
        bin_expr: &BinaryExpr,
        left_col_oracle: &TrackedColOracle<F, MvPCS, UvPCS>,
        right_col_oracle: &TrackedColOracle<F, MvPCS, UvPCS>,
        log_size: usize,
    ) -> TrackedTableOracle<F, MvPCS, UvPCS> {
        let output_data_tracked_poly = match bin_expr.op {
            Operator::And => {
                let data_out = &left_col_oracle.data_tracked_oracle()
                    * &right_col_oracle.data_tracked_oracle();

                match (
                    left_col_oracle.activator_tracked_oracle(),
                    right_col_oracle.activator_tracked_oracle(),
                ) {
                    (Some(l), Some(r)) => &(&l * &r) * &data_out,
                    (Some(l), None) => &l * &data_out,
                    (None, Some(r)) => &r * &data_out,
                    (None, None) => data_out,
                }
            }
            Operator::Plus => {
                let data_out = &left_col_oracle.data_tracked_oracle()
                    + &right_col_oracle.data_tracked_oracle();

                match (
                    left_col_oracle.activator_tracked_oracle(),
                    right_col_oracle.activator_tracked_oracle(),
                ) {
                    (Some(l), Some(r)) => &(&l * &r) * &data_out,
                    (Some(l), None) => &l * &data_out,
                    (None, Some(r)) => &r * &data_out,
                    (None, None) => data_out,
                }
            }
            Operator::Minus => {
                let data_out = &left_col_oracle.data_tracked_oracle()
                    - &right_col_oracle.data_tracked_oracle();

                match (
                    left_col_oracle.activator_tracked_oracle(),
                    right_col_oracle.activator_tracked_oracle(),
                ) {
                    (Some(l), Some(r)) => &(&l * &r) * &data_out,
                    (Some(l), None) => &l * &data_out,
                    (None, Some(r)) => &r * &data_out,
                    (None, None) => data_out,
                }
            }
            Operator::Multiply => {
                let data_out = &left_col_oracle.data_tracked_oracle()
                    * &right_col_oracle.data_tracked_oracle();

                match (
                    left_col_oracle.activator_tracked_oracle(),
                    right_col_oracle.activator_tracked_oracle(),
                ) {
                    (Some(l), Some(r)) => &(&l * &r) * &data_out,
                    (Some(l), None) => &l * &data_out,
                    (None, Some(r)) => &r * &data_out,
                    (None, None) => data_out,
                }
            }
            _ => panic!("unsupported operator for virtual witness"),
        };

        let output_activator = match (
            left_col_oracle.activator_tracked_oracle(),
            right_col_oracle.activator_tracked_oracle(),
        ) {
            (Some(l), Some(r)) => Some(&l * &r),
            (Some(l), None) => Some(l.clone()),
            (None, Some(r)) => Some(r.clone()),
            (None, None) => None,
        };
        let field_ref = if let Some(f) = left_col_oracle.field_ref() {
            let base_field = f.as_ref();
            let mut new_field = Field::new(
                bin_expr.to_string(),
                base_field.data_type().clone(),
                base_field.is_nullable(),
            );
            if !base_field.metadata().is_empty() {
                new_field = new_field.with_metadata(base_field.metadata().clone());
            }
            FieldRef::new(new_field)
        } else {
            FieldRef::new(Field::new(
                bin_expr.to_string(),
                datafusion::arrow::datatypes::DataType::Null,
                false,
            ))
        };
        let mut tracked_oracles = IndexMap::from_iter(vec![(field_ref, output_data_tracked_poly)]);
        if let Some(activator_oracle) = output_activator {
            let activator_field = FieldRef::new(Field::new(
                arithmetic::ACTIVATOR_COL_NAME,
                datafusion::arrow::datatypes::DataType::Boolean,
                true,
            ));
            tracked_oracles.insert(activator_field, activator_oracle);
        }
        TrackedTableOracle::new(None, tracked_oracles, log_size)
    }
}
