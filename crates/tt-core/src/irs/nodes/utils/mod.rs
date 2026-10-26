pub mod activator_consistency_check;
pub mod bitwise_and;
pub mod bool;
pub mod broadcast_check;
pub mod compaction;
pub mod contig_sort;
pub mod data_preserving_update_check;
pub mod domain_preserving_update_check;
pub mod eq;
pub mod factor_placement;
pub mod geq;
pub mod keyed_sumcheck;
pub mod length_filtering_check;
pub mod leq;
pub mod lex_sort;
pub mod lookup;
pub mod match_pair_check;
pub mod multi_character_pattern_matching;
pub mod neq;
pub mod nodup;
pub mod perm;
pub mod pre_filtering_check;
pub mod prescr_perm;
pub mod result_check;
pub mod rotation_check;
pub mod sign;
pub mod supp;
pub mod sweep_factors;

use std::sync::Arc;

use std::{cell::RefCell, rc::Rc};

use ark_ff::{BigInteger, PrimeField};
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    prover::{structs::polynomial::TrackedPoly, tracker::ProverTracker},
    verifier::{errors::VerifierError, structs::oracle::TrackedOracle, tracker::VerifierTracker},
};
use datafusion::arrow::datatypes::{DataType, Field, FieldRef};
use either::Either;

/// Commits `evals` through the tracker, for `add_virtual_witness`, which has
/// no `ArgProver`. The verifier reads it back with [`track_next_committed`]
/// at the same point of its own pass.
pub(crate) fn commit_with_tracker<B: SnarkBackend>(
    tracker_rc: &Rc<RefCell<ProverTracker<B>>>,
    log_size: usize,
    evals: Vec<B::F>,
) -> SnarkResult<TrackedPoly<B>> {
    let mle = MLE::from_evaluations_vec(log_size, evals);
    let num_vars = mle.num_vars();
    let result = tracker_rc
        .borrow_mut()
        .track_and_commit_mat_mv_p(&mle, false)?;
    Ok(match result {
        Either::Left(id) => TrackedPoly::new(Either::Left(id), num_vars, tracker_rc.clone()),
        Either::Right((id, cnst)) => {
            TrackedPoly::new_committed_constant(cnst, id, num_vars, tracker_rc.clone())
        }
    })
}

pub(crate) fn track_next_committed<B: SnarkBackend>(
    tracker_rc: &Rc<RefCell<VerifierTracker<B>>>,
) -> SnarkResult<TrackedOracle<B>> {
    let id = tracker_rc.borrow_mut().peek_next_id();
    let maybe_cnst = tracker_rc.borrow().proof_mv_constant(id);
    let (nv, tid) = tracker_rc.borrow_mut().track_mv_com_by_id(id)?;
    Ok(match maybe_cnst {
        Some(cnst) => TrackedOracle::new_committed_constant(cnst, tid, tracker_rc.clone(), nv),
        None => TrackedOracle::new(Either::Left(tid), tracker_rc.clone(), nv),
    })
}

/// `p` as a polynomial of `log_size` variables.
pub(crate) fn resize_poly<B: SnarkBackend>(p: &TrackedPoly<B>, log_size: usize) -> TrackedPoly<B> {
    TrackedPoly::new(p.id_or_const(), log_size, p.tracker())
}

/// `o` as an oracle of `log_size` variables.
pub(crate) fn resize_oracle<B: SnarkBackend>(
    o: &TrackedOracle<B>,
    log_size: usize,
) -> TrackedOracle<B> {
    TrackedOracle::new(o.id_or_const(), o.tracker(), log_size)
}

pub(crate) fn u64_field(name: &str) -> FieldRef {
    Arc::new(Field::new(name, DataType::UInt64, false))
}

/// The field of a single-column boolean table.
pub(crate) fn bool_field() -> FieldRef {
    Arc::new(Field::new("data", DataType::Boolean, false))
}

/// A count the verifier read from the proof, as a `usize`. `what` names it
/// in the error.
pub(crate) fn field_to_usize<F: PrimeField>(value: F, what: &str) -> SnarkResult<usize> {
    let bytes = value.into_bigint().to_bytes_le();
    let max = std::mem::size_of::<usize>();
    let mut out: usize = 0;
    for (i, byte) in bytes.iter().enumerate() {
        if i >= max {
            if *byte != 0 {
                return Err(SnarkError::VerifierError(
                    VerifierError::VerifierCheckFailed(format!("{what} does not fit into usize")),
                ));
            }
            continue;
        }
        out |= (*byte as usize) << (8 * i);
    }
    Ok(out)
}
