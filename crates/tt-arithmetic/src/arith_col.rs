use std::sync::Arc;

use ark_ff::PrimeField;
use ark_piop::arithmetic::mat_poly::mle::MLE;
use datafusion::arrow::datatypes::FieldRef;
use indexmap::IndexMap;

use crate::table::ArithSideCol;

/// Untracked mirror of `TrackedCol`: the polynomials of one Arrow source
/// column of an `ArithTable`, namely its primary row-domain MLE, its
/// auxiliary row-domain MLEs (`__length`) and its side-domain segments
/// (`__chars`, `__orig_ind`, `__int_ind`, `__bnd`).
///
/// It carries no activators: row-domain MLEs share the table's
/// `__activator__`, and a side segment's activator follows from the
/// `active_len` of its `ArithSideCol`.
#[derive(Debug, Clone, PartialEq)]
pub enum ArithCol<F: PrimeField> {
    SingleSegment {
        data: Arc<MLE<F>>,
        field_ref: Option<FieldRef>,
    },
    MultiSegment {
        /// Has the source column's name.
        primary_data: Arc<MLE<F>>,
        /// Keyed by segment suffix, in encoder order.
        aux_data: IndexMap<String, Arc<MLE<F>>>,
        /// Keyed by segment suffix.
        side_data: IndexMap<String, ArithSideCol>,
        field_ref: Option<FieldRef>,
    },
}

impl<F: PrimeField> ArithCol<F> {
    pub fn new(data: Arc<MLE<F>>, field_ref: Option<FieldRef>) -> Self {
        Self::SingleSegment { data, field_ref }
    }

    pub fn new_multi(
        primary_data: Arc<MLE<F>>,
        aux_data: IndexMap<String, Arc<MLE<F>>>,
        side_data: IndexMap<String, ArithSideCol>,
        field_ref: Option<FieldRef>,
    ) -> Self {
        Self::MultiSegment {
            primary_data,
            aux_data,
            side_data,
            field_ref,
        }
    }

    /// The primary row-domain MLE.
    pub fn data(&self) -> &Arc<MLE<F>> {
        match self {
            Self::SingleSegment { data, .. } => data,
            Self::MultiSegment { primary_data, .. } => primary_data,
        }
    }

    pub fn field_ref(&self) -> Option<&FieldRef> {
        match self {
            Self::SingleSegment { field_ref, .. } | Self::MultiSegment { field_ref, .. } => {
                field_ref.as_ref()
            }
        }
    }

    /// The auxiliary row-domain segment `suffix`.
    pub fn aux_segment(&self, suffix: &str) -> Option<&Arc<MLE<F>>> {
        match self {
            Self::SingleSegment { .. } => None,
            Self::MultiSegment { aux_data, .. } => aux_data.get(suffix),
        }
    }

    pub fn side_segment(&self, suffix: &str) -> Option<&ArithSideCol> {
        match self {
            Self::SingleSegment { .. } => None,
            Self::MultiSegment { side_data, .. } => side_data.get(suffix),
        }
    }

    /// The row-domain segments: the primary with `suffix = None`, then each
    /// aux with `suffix = Some(..)`, in insertion order.
    #[allow(clippy::type_complexity)]
    pub fn row_segments_iter(&self) -> Box<dyn Iterator<Item = (Option<&str>, &Arc<MLE<F>>)> + '_> {
        match self {
            Self::SingleSegment { data, .. } => Box::new(std::iter::once((None, data))),
            Self::MultiSegment {
                primary_data,
                aux_data,
                ..
            } => {
                let primary = std::iter::once((None, primary_data));
                let aux = aux_data.iter().map(|(sid, mle)| (Some(sid.as_str()), mle));
                Box::new(primary.chain(aux))
            }
        }
    }

    /// The side-domain segments, in insertion order.
    pub fn side_segments_iter(&self) -> Box<dyn Iterator<Item = (&str, &ArithSideCol)> + '_> {
        match self {
            Self::SingleSegment { .. } => Box::new(std::iter::empty()),
            Self::MultiSegment { side_data, .. } => {
                Box::new(side_data.iter().map(|(sid, side)| (sid.as_str(), side)))
            }
        }
    }
}
