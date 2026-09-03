use std::sync::Arc;

use ark_ff::PrimeField;
use ark_piop::arithmetic::mat_poly::mle::MLE;
use datafusion::arrow::datatypes::FieldRef;
use indexmap::IndexMap;

use crate::table::ArithSideCol;

/// Untracked mirror of `TrackedCol`: the source-column-keyed view of an
/// `ArithTable`. Groups one Arrow source column's polynomials — its
/// primary row-domain MLE plus zero or more auxiliary row-domain MLEs
/// (e.g. `__length` for strings) plus zero or more side-domain segments
/// (e.g. `__chars`, `__orig_ind`, `__int_ind`, `__bnd`).
///
/// Simpler than `TrackedCol`: activators are table-level (one
/// `__activator__` MLE shared across all row-domain polys), so this enum
/// does not carry per-segment activator information. Side-domain segments
/// bring their own activator inside `ArithSideCol` (via `active_len`).
#[derive(Debug, Clone, PartialEq)]
pub enum ArithCol<F: PrimeField> {
    SingleSegment {
        data: Arc<MLE<F>>,
        field_ref: Option<FieldRef>,
    },
    MultiSegment {
        /// The primary (canonical) row-domain MLE — inherits the source
        /// column's name.
        primary_data: Arc<MLE<F>>,
        /// Auxiliary row-domain MLEs, keyed by segment suffix (e.g.
        /// `__length`). Iteration order matches encoder emission order.
        aux_data: IndexMap<String, Arc<MLE<F>>>,
        /// Side-domain segments, keyed by segment suffix (e.g. `__chars`).
        /// Each carries its own multilinear domain and activator.
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

    /// Returns the primary (canonical) row-domain MLE.
    pub fn data(&self) -> &Arc<MLE<F>> {
        match self {
            Self::SingleSegment { data, .. } => data,
            Self::MultiSegment { primary_data, .. } => primary_data,
        }
    }

    /// Returns the field reference of the source column, if any.
    pub fn field_ref(&self) -> Option<&FieldRef> {
        match self {
            Self::SingleSegment { field_ref, .. } | Self::MultiSegment { field_ref, .. } => {
                field_ref.as_ref()
            }
        }
    }

    /// Look up an auxiliary row-domain segment by suffix.
    pub fn aux_segment(&self, suffix: &str) -> Option<&Arc<MLE<F>>> {
        match self {
            Self::SingleSegment { .. } => None,
            Self::MultiSegment { aux_data, .. } => aux_data.get(suffix),
        }
    }

    /// Look up a side-domain segment by suffix.
    pub fn side_segment(&self, suffix: &str) -> Option<&ArithSideCol> {
        match self {
            Self::SingleSegment { .. } => None,
            Self::MultiSegment { side_data, .. } => side_data.get(suffix),
        }
    }

    /// Iterate row-domain segments: primary yields `suffix = None`, aux
    /// yields `suffix = Some(sid)` in insertion order.
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

    /// Iterate side-domain segments in insertion order.
    pub fn side_segments_iter(&self) -> Box<dyn Iterator<Item = (&str, &ArithSideCol)> + '_> {
        match self {
            Self::SingleSegment { .. } => Box::new(std::iter::empty()),
            Self::MultiSegment { side_data, .. } => {
                Box::new(side_data.iter().map(|(sid, side)| (sid.as_str(), side)))
            }
        }
    }
}
