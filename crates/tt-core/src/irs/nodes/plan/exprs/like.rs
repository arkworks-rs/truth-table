//! `Expr::Like` — SQL `LIKE` lowering into the Multi-Character Pattern
//! Matching (MCPM) gadget (paper §6.1 PIOP 6).
//!
//! Pipeline:
//! 1. Parse the LIKE pattern via `sweep_factors::parse_like_pattern`
//!    into an ordered `Vec<(literal, Mode)>` factor list.
//! 2. Pull the string column's char-level side segments (`__chars`,
//!    `__orig_ind`, `__int_ind`, `__bnd`) from the scope's tracked
//!    table. These are emitted at the TableScan encoding site.
//! 3. Read plaintext evaluations back on the prover, compute every
//!    MCPM/SweepFactors witness column via
//!    `sweep_factors::witness::compute_mcpm_witness`, commit each as a
//!    fresh MLE, and wire them into the MCPM gadget's payload.
//! 4. Expose `a_new` (the per-string boolean match column) as this
//!    node's PlanPayload output.
//!
//! Wildcard-only patterns (`""`, `"%"`, `"%%"`) short-circuit to a
//! constant-1 output — no MCPM child is spawned.
//!
//! Design note: witness commits happen inside `add_virtual_witness`
//! (via the tracker `Rc<RefCell<...>>` reachable from any scope poly)
//! rather than `initialize_gadgets`. This is required because the
//! virtualization pass runs post-order — a parent operator (e.g.
//! `Filter`) reads this node's `PlanPayload` during ITS own
//! `add_virtual_witness`, which happens before this node's
//! `initialize_gadgets` would run. So `a_new` must be committed before
//! virtualization completes.
//!
//! Limitations: `NOT LIKE`, ESCAPE clauses, `_` single-char wildcards,
//! and case-insensitive matching are not supported yet.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use arithmetic::{
    self, ACTIVATOR_COL_NAME, ACTIVATOR_FIELD, ROW_ID_COL_NAME,
    encoding::{
        self, EncodedSegment, STRING_BND_SUFFIX, STRING_CHARS_SUFFIX, STRING_INT_IND_SUFFIX,
        STRING_LENGTH_SUFFIX, STRING_ORIG_IND_SUFFIX, SideColData,
    },
    is_system_column,
    table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::{BigInteger, PrimeField};
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    errors::{SnarkError, SnarkResult},
    prover::{structs::polynomial::TrackedPoly, tracker::ProverTracker},
    verifier::{structs::oracle::TrackedOracle, tracker::VerifierTracker},
};
use datafusion::arrow::{
    array::{Array, ArrayRef, Int64Array},
    datatypes::{DataType, Field, FieldRef, Schema},
    record_batch::RecordBatch,
};
use datafusion::datasource::MemTable;
use datafusion::prelude::SessionContext;
use datafusion_common::{Result as DataFusionResult, ScalarValue, Statistics};
use datafusion_expr::{Expr, Like};
use either::Either;
use indexmap::IndexMap;

use crate::irs::{
    nodes::{
        IsExprNode, IsNode, IsPlanNode, Node, NodeId, ProverNodeOps, VerifierNodeOps,
        hints::HintDF,
        utils::{
            multi_character_pattern_matching as mcpm,
            sweep_factors::{
                Mode, factor_label, parse_like_pattern,
                witness::{McpmWitness, ScannedTables, compute_mcpm_witness},
            },
        },
    },
    payloads::PayloadStructure,
    tree::Tree,
};
use crate::prover::irs::VirtualizedIr as ProverVirtualizedIr;
use crate::verifier::irs::VirtualizedIr as VerifierVirtualizedIr;

pub struct ExprNode<B: SnarkBackend> {
    pub scope: Vec<std::sync::Weak<Node<B>>>,
    pub parent: Option<std::sync::Weak<Node<B>>>,
    pub like: Like,
    pub factors: Vec<(Vec<B::F>, Mode)>,
    pub expr: Arc<Node<B>>,
    /// The MCPM gadget child. `None` when the pattern is wildcard-only.
    pub mcpm: Option<Arc<Node<B>>>,
    output_data_field_cache: Mutex<Option<FieldRef>>,
}

impl<B: SnarkBackend> ExprNode<B> {
    fn output_field(&self) -> FieldRef {
        if let Some(field) = self
            .output_data_field_cache
            .lock()
            .expect("output_data_field_cache poisoned")
            .as_ref()
            .cloned()
        {
            return field;
        }
        let field: FieldRef = Arc::new(Field::new(
            self.output_field_name(),
            DataType::Boolean,
            true,
        ));
        *self
            .output_data_field_cache
            .lock()
            .expect("output_data_field_cache poisoned") = Some(field.clone());
        field
    }

    fn output_expr(&self) -> Expr {
        Expr::Like(self.like.clone())
    }

    fn output_field_name(&self) -> String {
        format!(
            "{}_LIKE_{}",
            match self.like.expr.as_ref() {
                Expr::Column(c) => c.name.clone(),
                _ => "expr".to_string(),
            },
            self.short_pattern_label(),
        )
    }

    fn find_string_column_base_name_side_prover(table: &TrackedTable<B>) -> Option<String> {
        for (side_field, _) in table.side_cols().iter() {
            if let Some(base) = side_field.name().strip_suffix(STRING_CHARS_SUFFIX) {
                return Some(base.to_string());
            }
        }
        None
    }

    fn find_string_column_base_name_side_verifier(table: &TrackedTableOracle<B>) -> Option<String> {
        for (side_field, _) in table.side_cols().iter() {
            if let Some(base) = side_field.name().strip_suffix(STRING_CHARS_SUFFIX) {
                return Some(base.to_string());
            }
        }
        None
    }

    fn short_pattern_label(&self) -> String {
        match self.like.pattern.as_ref() {
            Expr::Literal(ScalarValue::Utf8(Some(s))) => s.clone(),
            _ => "?".to_string(),
        }
    }
}

impl<B: SnarkBackend> IsNode<B> for ExprNode<B> {
    fn name(&self) -> String {
        "Like".to_string()
    }

    fn display(&self) -> String {
        format!(
            "Like\nInput: {}, pattern: '{}' (t={})",
            self.expr.name(),
            self.short_pattern_label(),
            self.factors.len(),
        )
    }

    fn cost(
        &self,
        _statistics: Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    // NOTE: `like.pattern` is intentionally NOT a child. `from_expr`
    // asserts it must be a Utf8 literal and consumes it into `factors`
    // at construction; it produces no witness, oracle, or payload. If we
    // ever support non-literal patterns (e.g. `col1 LIKE col2`), wrap it
    // as a Node<B> here so it gets its own witness/oracle slot.
    fn children(&self) -> Vec<Arc<Node<B>>> {
        let mut kids = vec![self.expr.clone()];
        if let Some(mcpm) = &self.mcpm {
            kids.push(mcpm.clone());
        }
        kids
    }

    fn required_side_columns(&self) -> Vec<String> {
        // Wildcard-only patterns short-circuit in add_virtual_witness
        // without ever touching side segments.
        if self.factors.is_empty() {
            return Vec::new();
        }
        self.like
            .expr
            .column_refs()
            .into_iter()
            .map(|column| column.name.clone())
            .collect()
    }
}

// -----------------------------------------------------------------------------
// Commit helpers going through the tracker `Rc<RefCell<...>>` directly
// so we can commit inside `add_virtual_witness` (which has no
// `ArgProver` / `ArgVerifier` reference).
// -----------------------------------------------------------------------------

/// Commits an evaluation vector. Storage compression is applied inside
/// ark-piop's `track_and_commit_mat_mv_p` (auto-classifies into the tightest
/// `MLEStorage` variant), so callers here don't need to know the semantic
/// type of `evals`.
fn commit_prover<B: SnarkBackend>(
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

fn track_next_verifier<B: SnarkBackend>(
    tracker_rc: &Rc<RefCell<VerifierTracker<B>>>,
) -> SnarkResult<TrackedOracle<B>> {
    let id = tracker_rc.borrow_mut().peek_next_id();
    let maybe_cnst = tracker_rc.borrow().proof_mv_constant(id);
    if let Some(cnst) = maybe_cnst {
        let (nv, tid) = tracker_rc.borrow_mut().track_mv_com_by_id(id)?;
        return Ok(TrackedOracle::new_committed_constant(
            cnst,
            tid,
            tracker_rc.clone(),
            nv,
        ));
    }
    let (nv, tid) = tracker_rc.borrow_mut().track_mv_com_by_id(id)?;
    Ok(TrackedOracle::new(
        Either::Left(tid),
        tracker_rc.clone(),
        nv,
    ))
}

// -----------------------------------------------------------------------------
// Prover path — witnesses committed inside `add_virtual_witness`.
// -----------------------------------------------------------------------------

impl<B: SnarkBackend> ExprNode<B> {
    /// Compute the full MCPM witness set upfront so we can commit
    /// `a_new` here (needed by parent Filter's `add_virtual_witness`)
    /// and cache the remaining evals on the node for `initialize_gadgets`
    /// to commit + wire onto the MCPM payload.
    fn commit_a_new_prover(
        &self,
        id: NodeId,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let scope_table = match virtualized_ir.payload_for_node(&self.expr.id()) {
            Some(PayloadStructure::PlanPayload(t)) => t.clone(),
            _ => panic!("Like: expected PlanPayload on input column child"),
        };
        let str_domain = scope_table.log_size();

        let base_name = Self::find_string_column_base_name_side_prover(&scope_table).expect(
            "Like: no Utf8 side segments found in scope. \
             Requires the string column to bind directly to a TableScan.",
        );
        let chars_side = scope_table
            .side_segment(&base_name, STRING_CHARS_SUFFIX)
            .cloned()
            .expect("Like: missing __chars side col");
        let tracker_rc = chars_side.data.tracker();

        // Compute the full witness (used again in ig; we recompute
        // there rather than cache to avoid holding a large evals blob
        // on the node across passes).
        let witness = self.scan_and_compute_witness_prover(&scope_table, &chars_side);
        let a_new = commit_prover(&tracker_rc, str_domain, witness.a_new.clone())?;

        // Own PlanPayload = a_new + activator + row_id (so Filter sees it).
        let mut merged: IndexMap<FieldRef, TrackedPoly<B>> = IndexMap::new();
        merged.insert(self.output_field(), a_new);
        if let Some(activator) = scope_table.activator_tracked_poly() {
            merged.insert(ACTIVATOR_FIELD.clone(), activator);
        }
        if let Some((row_id_field, row_id_poly)) = scope_table
            .tracked_polys_iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
        {
            merged.insert(row_id_field.clone(), row_id_poly.clone());
        }
        let fields: Vec<Field> = merged.keys().map(|f| f.as_ref().clone()).collect();
        let schema = Some(Schema::new(fields));
        virtualized_ir.set_payload_for_node(
            id,
            Some(PayloadStructure::PlanPayload(TrackedTable::new(
                schema, merged, str_domain,
            ))),
        );
        Ok(())
    }

    fn scan_and_compute_witness_prover(
        &self,
        scope_table: &TrackedTable<B>,
        chars_side: &arithmetic::col::PolyBundle<B>,
    ) -> McpmWitness<B::F> {
        let str_domain = scope_table.log_size();
        let base_name = Self::find_string_column_base_name_side_prover(scope_table).unwrap();
        let orig_ind_side = scope_table
            .side_segment(&base_name, STRING_ORIG_IND_SUFFIX)
            .cloned()
            .expect("Like: missing __orig_ind side col");
        let int_ind_side = scope_table
            .side_segment(&base_name, STRING_INT_IND_SUFFIX)
            .cloned()
            .expect("Like: missing __int_ind side col");
        let bnd_side = scope_table
            .side_segment(&base_name, STRING_BND_SUFFIX)
            .cloned()
            .expect("Like: missing __bnd side col");
        let char_domain = chars_side.log_size();

        let (_length_field, length_poly) = scope_table
            .tracked_polys_iter()
            .find(|(f, _)| {
                f.name().as_str() == format!("{base_name}{STRING_LENGTH_SUFFIX}").as_str()
            })
            .map(|(f, p)| (f.clone(), p.clone()))
            .expect("Like: missing __length row-domain segment");

        let char_evals = chars_side.data.evaluations().to_vec();
        let orig_ind_evals = orig_ind_side.data.evaluations().to_vec();
        let int_ind_evals = int_ind_side.data.evaluations().to_vec();
        let bnd_evals = bnd_side.data.evaluations().to_vec();
        let char_act_evals = chars_side
            .activator
            .as_ref()
            .expect("side segment must carry activator")
            .evaluations()
            .to_vec();
        let l_evals = length_poly.evaluations().to_vec();
        let a_evals = scope_table
            .activator_tracked_poly()
            .expect("Like: scope must carry a string-level activator")
            .evaluations()
            .to_vec();
        let n_strs = 1usize << str_domain;
        let ind_evals: Vec<B::F> = scope_table
            .tracked_polys_iter()
            .find(|(f, _)| f.name() == ROW_ID_COL_NAME)
            .map(|(_, p)| p.evaluations().to_vec())
            .unwrap_or_else(|| (0..n_strs).map(|i| B::F::from(i as u64)).collect());
        let tables = ScannedTables::<B::F> {
            char: char_evals,
            orig_ind: orig_ind_evals,
            int_ind: int_ind_evals,
            bnd: bnd_evals,
            char_act: char_act_evals,
            char_domain,
            ind: ind_evals,
            a: a_evals,
            l: l_evals,
            str_domain,
        };
        compute_mcpm_witness(&tables, &self.factors)
    }

    fn commit_and_wire_prover(
        &self,
        id: NodeId,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let mcpm_node = self
            .mcpm
            .as_ref()
            .expect("Like: non-empty pattern must have an MCPM child");

        let scope_table = match virtualized_ir.payload_for_node(&self.expr.id()) {
            Some(PayloadStructure::PlanPayload(t)) => t.clone(),
            _ => panic!("Like: expected PlanPayload on input column child"),
        };
        let str_domain = scope_table.log_size();

        let base_name = Self::find_string_column_base_name_side_prover(&scope_table).expect(
            "Like: no Utf8 side segments found in scope. \
             Requires the string column to bind directly to a TableScan \
             (side polys are not propagated through intermediate ops).",
        );
        let chars_side = scope_table
            .side_segment(&base_name, STRING_CHARS_SUFFIX)
            .cloned()
            .expect("Like: missing __chars side col");
        let orig_ind_side = scope_table
            .side_segment(&base_name, STRING_ORIG_IND_SUFFIX)
            .cloned()
            .expect("Like: missing __orig_ind side col");
        let int_ind_side = scope_table
            .side_segment(&base_name, STRING_INT_IND_SUFFIX)
            .cloned()
            .expect("Like: missing __int_ind side col");
        let bnd_side = scope_table
            .side_segment(&base_name, STRING_BND_SUFFIX)
            .cloned()
            .expect("Like: missing __bnd side col");
        let char_domain = chars_side.log_size();

        let (length_field, length_poly) = scope_table
            .tracked_polys_iter()
            .find(|(f, _)| {
                f.name().as_str() == format!("{base_name}{STRING_LENGTH_SUFFIX}").as_str()
            })
            .map(|(f, p)| (f.clone(), p.clone()))
            .expect("Like: missing __length row-domain segment");

        // Grab the tracker Rc from a scope poly — same tracker as ArgProver's.
        let tracker_rc = chars_side.data.tracker();

        // Read plaintext evaluations back for the witness computer.
        let char_evals = chars_side.data.evaluations().to_vec();
        let orig_ind_evals = orig_ind_side.data.evaluations().to_vec();
        let int_ind_evals = int_ind_side.data.evaluations().to_vec();
        let bnd_evals = bnd_side.data.evaluations().to_vec();
        let char_act_evals = chars_side
            .activator
            .as_ref()
            .expect("side segment must carry activator")
            .evaluations()
            .to_vec();
        let l_evals = length_poly.evaluations().to_vec();
        let a_evals = scope_table
            .activator_tracked_poly()
            .expect("Like: scope must carry a string-level activator")
            .evaluations()
            .to_vec();
        let n_strs = 1usize << str_domain;
        let ind_evals: Vec<B::F> = scope_table
            .tracked_polys_iter()
            .find(|(f, _)| f.name() == ROW_ID_COL_NAME)
            .map(|(_, p)| p.evaluations().to_vec())
            .unwrap_or_else(|| (0..n_strs).map(|i| B::F::from(i as u64)).collect());

        let tables = ScannedTables::<B::F> {
            char: char_evals,
            orig_ind: orig_ind_evals,
            int_ind: int_ind_evals,
            bnd: bnd_evals,
            char_act: char_act_evals,
            char_domain,
            ind: ind_evals,
            a: a_evals,
            l: l_evals,
            str_domain,
        };

        let witness: McpmWitness<B::F> = compute_mcpm_witness(&tables, &self.factors);

        // `a_new` was committed FIRST in add_virtual_witness (so parent
        // Filter's `add_virtual_witness`, which runs later in the
        // post-order pass, can see it in this node's PlanPayload).
        // Recover it from our own PlanPayload here.
        let own_payload = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(t)) => t.clone(),
            _ => panic!("Like: expected PlanPayload set by add_virtual_witness"),
        };
        let a_new = own_payload
            .tracked_polys_iter()
            .find(|(f, _)| f.name() == self.output_field().name())
            .map(|(_, p)| p.clone())
            .expect("Like: a_new must be committed by add_virtual_witness");

        // Commit order for the REST = CONTRACT with the verifier.
        let char_act_old_prime =
            commit_prover(&tracker_rc, char_domain, witness.char_act_old_prime.clone())?;
        let a_old_prime = commit_prover(&tracker_rc, str_domain, witness.a_old_prime.clone())?;
        let char_act_new = commit_prover(&tracker_rc, char_domain, witness.char_act_new.clone())?;

        struct FactorPolys<B: SnarkBackend> {
            rotated_chars: Vec<TrackedPoly<B>>,
            occurs: TrackedPoly<B>,
            match_str: TrackedPoly<B>,
            mark: TrackedPoly<B>,
            start: TrackedPoly<B>,
            match_broadcast: TrackedPoly<B>,
            start_broadcast: TrackedPoly<B>,
            leftmost_mask: TrackedPoly<B>,
            att_mask: Option<TrackedPoly<B>>,
            rotated_bnd: Option<Vec<TrackedPoly<B>>>,
            past: Option<TrackedPoly<B>>,
        }

        let mut per_factor_polys: Vec<FactorPolys<B>> = Vec::with_capacity(self.factors.len());
        for fw in witness.per_factor.iter() {
            let mut rotated_chars = Vec::with_capacity(fw.rotated_chars.len());
            for col in fw.rotated_chars.iter() {
                rotated_chars.push(commit_prover(&tracker_rc, char_domain, col.clone())?);
            }
            let occurs = commit_prover(&tracker_rc, char_domain, fw.occurs.clone())?;
            let match_str = commit_prover(&tracker_rc, str_domain, fw.match_str.clone())?;
            let mark = commit_prover(&tracker_rc, char_domain, fw.mark.clone())?;
            let start = commit_prover(&tracker_rc, str_domain, fw.start.clone())?;
            let match_broadcast =
                commit_prover(&tracker_rc, char_domain, fw.match_broadcast.clone())?;
            let start_broadcast =
                commit_prover(&tracker_rc, char_domain, fw.start_broadcast.clone())?;
            let leftmost_mask = commit_prover(&tracker_rc, char_domain, fw.leftmost_mask.clone())?;
            let att_mask = if let Some(am) = &fw.att_mask {
                Some(commit_prover(&tracker_rc, char_domain, am.clone())?)
            } else {
                None
            };
            let rotated_bnd = if let Some(rb) = &fw.rotated_bnd {
                let mut cols = Vec::with_capacity(rb.len());
                for col in rb.iter() {
                    cols.push(commit_prover(&tracker_rc, char_domain, col.clone())?);
                }
                Some(cols)
            } else {
                None
            };
            let past = if let Some(p) = &fw.past {
                Some(commit_prover(&tracker_rc, char_domain, p.clone())?)
            } else {
                None
            };
            per_factor_polys.push(FactorPolys {
                rotated_chars,
                occurs,
                match_str,
                mark,
                start,
                match_broadcast,
                start_broadcast,
                leftmost_mask,
                att_mask,
                rotated_bnd,
                past,
            });
        }

        // MCPM payload map.
        let mut mcpm_payload: IndexMap<String, TrackedTable<B>> = IndexMap::new();

        {
            let char_f = Arc::new(Field::new("char", DataType::UInt64, false));
            let orig_ind_f = Arc::new(Field::new("orig_ind", DataType::UInt64, false));
            let int_ind_f = Arc::new(Field::new("int_ind", DataType::UInt64, false));
            let bnd_f = Arc::new(Field::new("bnd", DataType::UInt64, false));
            let mut polys = IndexMap::new();
            polys.insert(char_f.clone(), chars_side.data.clone());
            polys.insert(orig_ind_f.clone(), orig_ind_side.data.clone());
            polys.insert(int_ind_f.clone(), int_ind_side.data.clone());
            polys.insert(bnd_f.clone(), bnd_side.data.clone());
            polys.insert(
                ACTIVATOR_FIELD.clone(),
                chars_side
                    .activator
                    .clone()
                    .expect("side segment must carry activator"),
            );
            let schema = Schema::new(vec![
                char_f.as_ref().clone(),
                orig_ind_f.as_ref().clone(),
                int_ind_f.as_ref().clone(),
                bnd_f.as_ref().clone(),
            ]);
            mcpm_payload.insert(
                mcpm::CHAR_INPUT_LABEL.to_string(),
                TrackedTable::new(Some(schema), polys, char_domain),
            );
        }
        {
            let ind_f = Arc::new(Field::new("ind", DataType::UInt64, false));
            let l_f = length_field.clone();
            let mut polys = IndexMap::new();
            let ind_poly = scope_table
                .tracked_polys_iter()
                .find(|(f, _)| f.name() == ROW_ID_COL_NAME)
                .map(|(_, p)| p.clone())
                .unwrap_or_else(|| {
                    let evals: Vec<B::F> = (0..(1usize << str_domain))
                        .map(|i| B::F::from(i as u64))
                        .collect();
                    commit_prover(&tracker_rc, str_domain, evals).expect("commit ind fallback")
                });
            polys.insert(ind_f.clone(), ind_poly);
            polys.insert(l_f.clone(), length_poly.clone());
            polys.insert(
                ACTIVATOR_FIELD.clone(),
                scope_table
                    .activator_tracked_poly()
                    .expect("Like: scope must carry a string-level activator"),
            );
            let schema = Schema::new(vec![
                Field::new("ind", DataType::UInt64, false),
                length_field.as_ref().clone(),
            ]);
            mcpm_payload.insert(
                mcpm::STR_INPUT_LABEL.to_string(),
                TrackedTable::new(Some(schema), polys, str_domain),
            );
        }

        let bool_table = |data: TrackedPoly<B>, log_size: usize| -> TrackedTable<B> {
            let mut polys = IndexMap::new();
            polys.insert(Arc::new(Field::new("data", DataType::Boolean, false)), data);
            let schema = Schema::new(vec![
                Arc::new(Field::new("data", DataType::Boolean, false))
                    .as_ref()
                    .clone(),
            ]);
            TrackedTable::new(Some(schema), polys, log_size)
        };
        mcpm_payload.insert(
            mcpm::LENGTH_FILTERED_CHAR_LABEL.to_string(),
            bool_table(char_act_old_prime, char_domain),
        );
        mcpm_payload.insert(
            mcpm::LENGTH_FILTERED_STR_LABEL.to_string(),
            bool_table(a_old_prime, str_domain),
        );
        mcpm_payload.insert(
            mcpm::NEW_CHAR_LABEL.to_string(),
            bool_table(char_act_new, char_domain),
        );
        mcpm_payload.insert(
            mcpm::NEW_STR_LABEL.to_string(),
            bool_table(a_new.clone(), str_domain),
        );

        for (j, fp) in per_factor_polys.into_iter().enumerate() {
            {
                let k = fp.rotated_chars.len();
                let mut polys = IndexMap::new();
                let mut fields = Vec::with_capacity(k);
                for (delta, p) in fp.rotated_chars.into_iter().enumerate() {
                    let f = Arc::new(Field::new(format!("char_{delta}"), DataType::UInt64, false));
                    polys.insert(f.clone(), p);
                    fields.push(f.as_ref().clone());
                }
                mcpm_payload.insert(
                    factor_label(j, "rotated_char"),
                    TrackedTable::new(Some(Schema::new(fields)), polys, char_domain),
                );
            }
            mcpm_payload.insert(
                factor_label(j, "occurs"),
                bool_table(fp.occurs, char_domain),
            );
            mcpm_payload.insert(
                factor_label(j, "match"),
                bool_table(fp.match_str, str_domain),
            );
            mcpm_payload.insert(factor_label(j, "mark"), bool_table(fp.mark, char_domain));
            {
                let start_f = Arc::new(Field::new("start", DataType::UInt64, false));
                let mut polys = IndexMap::new();
                polys.insert(start_f.clone(), fp.start);
                mcpm_payload.insert(
                    factor_label(j, "start"),
                    TrackedTable::new(
                        Some(Schema::new(vec![start_f.as_ref().clone()])),
                        polys,
                        str_domain,
                    ),
                );
            }
            {
                let mb_f = Arc::new(Field::new("match_prime", DataType::UInt64, false));
                let mut polys = IndexMap::new();
                polys.insert(mb_f.clone(), fp.match_broadcast);
                mcpm_payload.insert(
                    factor_label(j, "match_broadcast"),
                    TrackedTable::new(
                        Some(Schema::new(vec![mb_f.as_ref().clone()])),
                        polys,
                        char_domain,
                    ),
                );
            }
            {
                let sb_f = Arc::new(Field::new("start_broadcast", DataType::UInt64, false));
                let mut polys = IndexMap::new();
                polys.insert(sb_f.clone(), fp.start_broadcast);
                mcpm_payload.insert(
                    factor_label(j, "start_broadcast"),
                    TrackedTable::new(
                        Some(Schema::new(vec![sb_f.as_ref().clone()])),
                        polys,
                        char_domain,
                    ),
                );
            }
            {
                let mask_f = Arc::new(Field::new("leftmost_mask", DataType::UInt64, false));
                let mut polys = IndexMap::new();
                polys.insert(mask_f.clone(), fp.leftmost_mask);
                mcpm_payload.insert(
                    factor_label(j, "leftmost_mask"),
                    TrackedTable::new(
                        Some(Schema::new(vec![mask_f.as_ref().clone()])),
                        polys,
                        char_domain,
                    ),
                );
            }
            if let Some(am) = fp.att_mask {
                let am_f = Arc::new(Field::new("att_mask", DataType::UInt64, false));
                let mut polys = IndexMap::new();
                polys.insert(am_f.clone(), am);
                mcpm_payload.insert(
                    factor_label(j, "att_mask"),
                    TrackedTable::new(
                        Some(Schema::new(vec![am_f.as_ref().clone()])),
                        polys,
                        char_domain,
                    ),
                );
            }
            if let Some(rb) = fp.rotated_bnd {
                let mut polys = IndexMap::new();
                let mut fields = Vec::with_capacity(rb.len());
                for (delta1, p) in rb.into_iter().enumerate() {
                    let name = format!("bnd_{}", delta1 + 1);
                    let f = Arc::new(Field::new(name, DataType::UInt64, false));
                    polys.insert(f.clone(), p);
                    fields.push(f.as_ref().clone());
                }
                mcpm_payload.insert(
                    factor_label(j, "rotated_bnd"),
                    TrackedTable::new(Some(Schema::new(fields)), polys, char_domain),
                );
            }
            if let Some(past) = fp.past {
                let past_f = Arc::new(Field::new("past", DataType::UInt64, false));
                let mut polys = IndexMap::new();
                polys.insert(past_f.clone(), past);
                mcpm_payload.insert(
                    factor_label(j, "past"),
                    TrackedTable::new(
                        Some(Schema::new(vec![past_f.as_ref().clone()])),
                        polys,
                        char_domain,
                    ),
                );
            }
        }

        virtualized_ir.set_payload_for_node(
            mcpm_node.id(),
            Some(PayloadStructure::GadgetPayload(mcpm_payload)),
        );

        // Own PlanPayload = a_new (boolean output) + activator/row_id.
        let mut merged: IndexMap<FieldRef, TrackedPoly<B>> = IndexMap::new();
        merged.insert(self.output_field(), a_new);
        if let Some(activator) = scope_table.activator_tracked_poly() {
            merged.insert(ACTIVATOR_FIELD.clone(), activator);
        }
        if let Some((row_id_field, row_id_poly)) = scope_table
            .tracked_polys_iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
        {
            merged.insert(row_id_field.clone(), row_id_poly.clone());
        }
        let fields: Vec<Field> = merged.keys().map(|f| f.as_ref().clone()).collect();
        let schema = Some(Schema::new(fields));
        virtualized_ir.set_payload_for_node(
            id,
            Some(PayloadStructure::PlanPayload(TrackedTable::new(
                schema, merged, str_domain,
            ))),
        );
        Ok(())
    }

    fn track_a_new_verifier(
        &self,
        id: NodeId,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let scope_table = match virtualized_ir.payload_for_node(&self.expr.id()) {
            Some(PayloadStructure::PlanPayload(t)) => t.clone(),
            _ => panic!("Like: expected PlanPayload on input column child"),
        };
        let str_domain = scope_table.log_size();
        let chars_side = scope_table
            .side_cols()
            .iter()
            .find_map(|(f, s)| {
                if f.name().ends_with(STRING_CHARS_SUFFIX) {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .expect("Like verifier: no __chars side oracle in scope");
        let tracker_rc = chars_side.data.tracker();

        let a_new = track_next_verifier(&tracker_rc)?;

        let mut merged: IndexMap<FieldRef, TrackedOracle<B>> = IndexMap::new();
        merged.insert(self.output_field(), a_new);
        if let Some(activator) = scope_table.activator_tracked_poly() {
            merged.insert(ACTIVATOR_FIELD.clone(), activator);
        }
        if let Some((row_id_field, row_id_oracle)) = scope_table
            .tracked_oracles_iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
        {
            merged.insert(row_id_field.clone(), row_id_oracle.clone());
        }
        let fields: Vec<Field> = merged.keys().map(|f| f.as_ref().clone()).collect();
        let schema = Some(Schema::new(fields));
        virtualized_ir.set_payload_for_node(
            id,
            Some(PayloadStructure::PlanPayload(TrackedTableOracle::new(
                schema, merged, str_domain,
            ))),
        );
        Ok(())
    }

    fn track_and_wire_verifier(
        &self,
        id: NodeId,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        let mcpm_node = self
            .mcpm
            .as_ref()
            .expect("Like: non-empty pattern must have an MCPM child");

        let scope_table = match virtualized_ir.payload_for_node(&self.expr.id()) {
            Some(PayloadStructure::PlanPayload(t)) => t.clone(),
            _ => panic!("Like: expected PlanPayload on input column child"),
        };
        let str_domain = scope_table.log_size();

        let base_name = Self::find_string_column_base_name_side_verifier(&scope_table).expect(
            "Like: no Utf8 side oracles found in scope. \
             Requires direct binding to a TableScan.",
        );
        let chars_side = scope_table
            .side_segment(&base_name, STRING_CHARS_SUFFIX)
            .cloned()
            .expect("Like: missing __chars side oracle");
        let orig_ind_side = scope_table
            .side_segment(&base_name, STRING_ORIG_IND_SUFFIX)
            .cloned()
            .expect("Like: missing __orig_ind side oracle");
        let int_ind_side = scope_table
            .side_segment(&base_name, STRING_INT_IND_SUFFIX)
            .cloned()
            .expect("Like: missing __int_ind side oracle");
        let bnd_side = scope_table
            .side_segment(&base_name, STRING_BND_SUFFIX)
            .cloned()
            .expect("Like: missing __bnd side oracle");
        let char_domain = chars_side.log_size();

        let (length_field, length_oracle) = scope_table
            .tracked_oracles_iter()
            .find(|(f, _)| {
                f.name().as_str() == format!("{base_name}{STRING_LENGTH_SUFFIX}").as_str()
            })
            .map(|(f, p)| (f.clone(), p.clone()))
            .expect("Like: missing __length row-domain oracle");

        let tracker_rc = chars_side.data.tracker();

        // `a_new` was tracked FIRST in add_virtual_witness (mirrors the
        // prover's a_new-first commit order). Recover it from own
        // PlanPayload set there.
        let own_payload = match virtualized_ir.payload_for_node(&id) {
            Some(PayloadStructure::PlanPayload(t)) => t.clone(),
            _ => panic!("Like verifier: expected PlanPayload set by add_virtual_witness"),
        };
        let a_new = own_payload
            .tracked_oracles_iter()
            .find(|(f, _)| f.name() == self.output_field().name())
            .map(|(_, p)| p.clone())
            .expect("Like verifier: a_new must be tracked by add_virtual_witness");

        // Track the REST in the same order the prover committed them.
        let char_act_old_prime = track_next_verifier(&tracker_rc)?;
        let a_old_prime = track_next_verifier(&tracker_rc)?;
        let char_act_new = track_next_verifier(&tracker_rc)?;

        struct FactorOracles<B: SnarkBackend> {
            rotated_chars: Vec<TrackedOracle<B>>,
            occurs: TrackedOracle<B>,
            match_str: TrackedOracle<B>,
            mark: TrackedOracle<B>,
            start: TrackedOracle<B>,
            match_broadcast: TrackedOracle<B>,
            start_broadcast: TrackedOracle<B>,
            leftmost_mask: TrackedOracle<B>,
            att_mask: Option<TrackedOracle<B>>,
            rotated_bnd: Option<Vec<TrackedOracle<B>>>,
            past: Option<TrackedOracle<B>>,
        }

        let mut per_factor_oracles: Vec<FactorOracles<B>> = Vec::with_capacity(self.factors.len());
        for (j, (pat, mode)) in self.factors.iter().enumerate() {
            let k = pat.len();
            let mut rotated_chars = Vec::with_capacity(k);
            for _ in 0..k {
                rotated_chars.push(track_next_verifier(&tracker_rc)?);
            }
            let occurs = track_next_verifier(&tracker_rc)?;
            let match_str = track_next_verifier(&tracker_rc)?;
            let mark = track_next_verifier(&tracker_rc)?;
            let start = track_next_verifier(&tracker_rc)?;
            let match_broadcast = track_next_verifier(&tracker_rc)?;
            let start_broadcast = track_next_verifier(&tracker_rc)?;
            let leftmost_mask = track_next_verifier(&tracker_rc)?;
            let att_mask = if matches!(mode, Mode::Suffix) {
                Some(track_next_verifier(&tracker_rc)?)
            } else {
                None
            };
            let rotated_bnd = if matches!(mode, Mode::Infix) && k >= 2 {
                let mut cols = Vec::with_capacity(k - 1);
                for _ in 1..k {
                    cols.push(track_next_verifier(&tracker_rc)?);
                }
                Some(cols)
            } else {
                None
            };
            let past = if j + 1 < self.factors.len() {
                Some(track_next_verifier(&tracker_rc)?)
            } else {
                None
            };
            per_factor_oracles.push(FactorOracles {
                rotated_chars,
                occurs,
                match_str,
                mark,
                start,
                match_broadcast,
                start_broadcast,
                leftmost_mask,
                att_mask,
                rotated_bnd,
                past,
            });
        }

        let mut mcpm_payload: IndexMap<String, TrackedTableOracle<B>> = IndexMap::new();

        {
            let char_f = Arc::new(Field::new("char", DataType::UInt64, false));
            let orig_ind_f = Arc::new(Field::new("orig_ind", DataType::UInt64, false));
            let int_ind_f = Arc::new(Field::new("int_ind", DataType::UInt64, false));
            let bnd_f = Arc::new(Field::new("bnd", DataType::UInt64, false));
            let mut oracles = IndexMap::new();
            oracles.insert(char_f.clone(), chars_side.data.clone());
            oracles.insert(orig_ind_f.clone(), orig_ind_side.data.clone());
            oracles.insert(int_ind_f.clone(), int_ind_side.data.clone());
            oracles.insert(bnd_f.clone(), bnd_side.data.clone());
            oracles.insert(
                ACTIVATOR_FIELD.clone(),
                chars_side
                    .activator
                    .clone()
                    .expect("side segment must carry activator"),
            );
            let schema = Schema::new(vec![
                char_f.as_ref().clone(),
                orig_ind_f.as_ref().clone(),
                int_ind_f.as_ref().clone(),
                bnd_f.as_ref().clone(),
            ]);
            mcpm_payload.insert(
                mcpm::CHAR_INPUT_LABEL.to_string(),
                TrackedTableOracle::new(Some(schema), oracles, char_domain),
            );
        }
        {
            let ind_f = Arc::new(Field::new("ind", DataType::UInt64, false));
            let mut oracles = IndexMap::new();
            // Mirror prover: if no __row_id__ oracle exists on the scope,
            // the prover committed a fresh ind poly at (0..n_strs). Track
            // the corresponding commitment here in the same order.
            let ind_oracle = scope_table
                .tracked_oracles_iter()
                .find(|(f, _)| f.name() == ROW_ID_COL_NAME)
                .map(|(_, p)| p.clone())
                .unwrap_or_else(|| track_next_verifier(&tracker_rc).expect("track ind fallback"));
            oracles.insert(ind_f.clone(), ind_oracle);
            oracles.insert(length_field.clone(), length_oracle.clone());
            oracles.insert(
                ACTIVATOR_FIELD.clone(),
                scope_table
                    .activator_tracked_poly()
                    .expect("Like verifier: scope must expose string activator oracle"),
            );
            let schema = Schema::new(vec![
                Field::new("ind", DataType::UInt64, false),
                length_field.as_ref().clone(),
            ]);
            mcpm_payload.insert(
                mcpm::STR_INPUT_LABEL.to_string(),
                TrackedTableOracle::new(Some(schema), oracles, str_domain),
            );
        }

        let bool_table_oracle =
            |data: TrackedOracle<B>, log_size: usize| -> TrackedTableOracle<B> {
                let mut oracles = IndexMap::new();
                oracles.insert(Arc::new(Field::new("data", DataType::Boolean, false)), data);
                let schema = Schema::new(vec![
                    Arc::new(Field::new("data", DataType::Boolean, false))
                        .as_ref()
                        .clone(),
                ]);
                TrackedTableOracle::new(Some(schema), oracles, log_size)
            };
        mcpm_payload.insert(
            mcpm::LENGTH_FILTERED_CHAR_LABEL.to_string(),
            bool_table_oracle(char_act_old_prime, char_domain),
        );
        mcpm_payload.insert(
            mcpm::LENGTH_FILTERED_STR_LABEL.to_string(),
            bool_table_oracle(a_old_prime, str_domain),
        );
        mcpm_payload.insert(
            mcpm::NEW_CHAR_LABEL.to_string(),
            bool_table_oracle(char_act_new, char_domain),
        );
        mcpm_payload.insert(
            mcpm::NEW_STR_LABEL.to_string(),
            bool_table_oracle(a_new.clone(), str_domain),
        );

        for (j, fo) in per_factor_oracles.into_iter().enumerate() {
            {
                let k = fo.rotated_chars.len();
                let mut oracles = IndexMap::new();
                let mut fields = Vec::with_capacity(k);
                for (delta, p) in fo.rotated_chars.into_iter().enumerate() {
                    let f = Arc::new(Field::new(format!("char_{delta}"), DataType::UInt64, false));
                    oracles.insert(f.clone(), p);
                    fields.push(f.as_ref().clone());
                }
                mcpm_payload.insert(
                    factor_label(j, "rotated_char"),
                    TrackedTableOracle::new(Some(Schema::new(fields)), oracles, char_domain),
                );
            }
            mcpm_payload.insert(
                factor_label(j, "occurs"),
                bool_table_oracle(fo.occurs, char_domain),
            );
            mcpm_payload.insert(
                factor_label(j, "match"),
                bool_table_oracle(fo.match_str, str_domain),
            );
            mcpm_payload.insert(
                factor_label(j, "mark"),
                bool_table_oracle(fo.mark, char_domain),
            );
            {
                let start_f = Arc::new(Field::new("start", DataType::UInt64, false));
                let mut oracles = IndexMap::new();
                oracles.insert(start_f.clone(), fo.start);
                mcpm_payload.insert(
                    factor_label(j, "start"),
                    TrackedTableOracle::new(
                        Some(Schema::new(vec![start_f.as_ref().clone()])),
                        oracles,
                        str_domain,
                    ),
                );
            }
            {
                let mb_f = Arc::new(Field::new("match_prime", DataType::UInt64, false));
                let mut oracles = IndexMap::new();
                oracles.insert(mb_f.clone(), fo.match_broadcast);
                mcpm_payload.insert(
                    factor_label(j, "match_broadcast"),
                    TrackedTableOracle::new(
                        Some(Schema::new(vec![mb_f.as_ref().clone()])),
                        oracles,
                        char_domain,
                    ),
                );
            }
            {
                let sb_f = Arc::new(Field::new("start_broadcast", DataType::UInt64, false));
                let mut oracles = IndexMap::new();
                oracles.insert(sb_f.clone(), fo.start_broadcast);
                mcpm_payload.insert(
                    factor_label(j, "start_broadcast"),
                    TrackedTableOracle::new(
                        Some(Schema::new(vec![sb_f.as_ref().clone()])),
                        oracles,
                        char_domain,
                    ),
                );
            }
            {
                let mask_f = Arc::new(Field::new("leftmost_mask", DataType::UInt64, false));
                let mut oracles = IndexMap::new();
                oracles.insert(mask_f.clone(), fo.leftmost_mask);
                mcpm_payload.insert(
                    factor_label(j, "leftmost_mask"),
                    TrackedTableOracle::new(
                        Some(Schema::new(vec![mask_f.as_ref().clone()])),
                        oracles,
                        char_domain,
                    ),
                );
            }
            if let Some(am) = fo.att_mask {
                let am_f = Arc::new(Field::new("att_mask", DataType::UInt64, false));
                let mut oracles = IndexMap::new();
                oracles.insert(am_f.clone(), am);
                mcpm_payload.insert(
                    factor_label(j, "att_mask"),
                    TrackedTableOracle::new(
                        Some(Schema::new(vec![am_f.as_ref().clone()])),
                        oracles,
                        char_domain,
                    ),
                );
            }
            if let Some(rb) = fo.rotated_bnd {
                let mut oracles = IndexMap::new();
                let mut fields = Vec::with_capacity(rb.len());
                for (delta1, p) in rb.into_iter().enumerate() {
                    let name = format!("bnd_{}", delta1 + 1);
                    let f = Arc::new(Field::new(name, DataType::UInt64, false));
                    oracles.insert(f.clone(), p);
                    fields.push(f.as_ref().clone());
                }
                mcpm_payload.insert(
                    factor_label(j, "rotated_bnd"),
                    TrackedTableOracle::new(Some(Schema::new(fields)), oracles, char_domain),
                );
            }
            if let Some(past) = fo.past {
                let past_f = Arc::new(Field::new("past", DataType::UInt64, false));
                let mut oracles = IndexMap::new();
                oracles.insert(past_f.clone(), past);
                mcpm_payload.insert(
                    factor_label(j, "past"),
                    TrackedTableOracle::new(
                        Some(Schema::new(vec![past_f.as_ref().clone()])),
                        oracles,
                        char_domain,
                    ),
                );
            }
        }

        virtualized_ir.set_payload_for_node(
            mcpm_node.id(),
            Some(PayloadStructure::GadgetPayload(mcpm_payload)),
        );

        let mut merged: IndexMap<FieldRef, TrackedOracle<B>> = IndexMap::new();
        merged.insert(self.output_field(), a_new);
        if let Some(activator) = scope_table.activator_tracked_poly() {
            merged.insert(ACTIVATOR_FIELD.clone(), activator);
        }
        if let Some((row_id_field, row_id_oracle)) = scope_table
            .tracked_oracles_iter()
            .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
        {
            merged.insert(row_id_field.clone(), row_id_oracle.clone());
        }
        let fields: Vec<Field> = merged.keys().map(|f| f.as_ref().clone()).collect();
        let schema = Some(Schema::new(fields));
        virtualized_ir.set_payload_for_node(
            id,
            Some(PayloadStructure::PlanPayload(TrackedTableOracle::new(
                schema, merged, str_domain,
            ))),
        );
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Plan-time helpers: build virtual HintDFs for SortNoDup's INPUT_LABEL
// derivation, plus a scanner that re-encodes the LIKE input string
// column to a `ScannedTables` view for the witness computer.
// -----------------------------------------------------------------------------

/// Blocking DataFrame collect that works in both current-thread and
/// multi-thread tokio runtimes. Mirrors the helper in `nodup/mod.rs`.
fn collect_blocking_like(df: datafusion::prelude::DataFrame) -> DataFusionResult<Vec<RecordBatch>> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => match handle.runtime_flavor() {
            tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(df.collect()))
            }
            tokio::runtime::RuntimeFlavor::CurrentThread => {
                let df_clone = df.clone();
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| {
                            datafusion_common::DataFusionError::Execution(e.to_string())
                        })?;
                    rt.block_on(df_clone.collect())
                })
                .join()
                .map_err(|_| {
                    datafusion_common::DataFusionError::Execution(
                        "like plan hint collection thread panicked".to_string(),
                    )
                })?
            }
            _ => tokio::task::block_in_place(|| handle.block_on(df.collect())),
        },
        Err(_) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| datafusion_common::DataFusionError::Execution(e.to_string()))?;
            rt.block_on(df.collect())
        }
    }
}

/// Convert a small non-negative field element to `i64` via the low bytes
/// of its big-int representation. Panics on overflow beyond 8 bytes with
/// the high bit set — SortNoDup's inputs (mark/orig_ind bytes and indices)
/// always fit comfortably.
fn field_to_i64_like<F: PrimeField>(value: F) -> i64 {
    let big = value.into_bigint();
    let bytes = big.to_bytes_le();
    let mut out: u64 = 0;
    for (i, byte) in bytes.iter().take(8).enumerate() {
        out |= (*byte as u64) << (8 * i);
    }
    out as i64
}

/// Build a virtual char-domain HintDF for a single column of field
/// values. The DataFrame carries `{ name: Int64, __row_id__: Int64 }`;
/// both fields are marked `should_materialize = false` so the tracking
/// pass does not attempt to commit them.
fn build_virtual_char_domain_hint<F: PrimeField>(
    name: &str,
    values: Vec<F>,
) -> DataFusionResult<HintDF> {
    let row_count = values.len();
    let target = if row_count <= 1 {
        2
    } else {
        row_count.next_power_of_two()
    };
    let mut vals: Vec<i64> = values.into_iter().map(field_to_i64_like::<F>).collect();
    vals.resize(target, 0);

    let data_field = Field::new(name, DataType::Int64, false);
    let row_id_field = Field::new(ROW_ID_COL_NAME, DataType::Int64, false);
    let schema = Arc::new(Schema::new(vec![data_field.clone(), row_id_field.clone()]));

    let data_arr: ArrayRef = Arc::new(Int64Array::from(vals));
    let row_arr: ArrayRef = Arc::new(Int64Array::from_iter_values((0..target).map(|i| i as i64)));
    let batch = RecordBatch::try_new(schema.clone(), vec![data_arr, row_arr])?;
    let mem_table = MemTable::try_new(schema, vec![vec![batch]])?;
    let ctx = SessionContext::new();
    let df = ctx.read_table(Arc::new(mem_table))?;

    let data_fref: FieldRef = Arc::new(data_field);
    let row_id_fref: FieldRef = Arc::new(row_id_field);
    let mut should_materialize: IndexMap<FieldRef, bool> = IndexMap::new();
    should_materialize.insert(data_fref, false);
    should_materialize.insert(row_id_fref, false);
    Ok(HintDF::new(df, should_materialize))
}

/// Build a schema-only virtual char-domain HintDF for the verifier. Data
/// values are placeholders (empty rows are OK because verifier planning
/// skips materialization); only the schema + should_materialize flags
/// are consumed by the tracking pass.
fn build_virtual_char_domain_hint_schema_only(name: &str) -> DataFusionResult<HintDF> {
    let data_field = Field::new(name, DataType::Int64, false);
    let row_id_field = Field::new(ROW_ID_COL_NAME, DataType::Int64, false);
    let schema = Arc::new(Schema::new(vec![data_field.clone(), row_id_field.clone()]));
    // Empty batch works fine — verifier planning must not consume data.
    let data_arr: ArrayRef = Arc::new(Int64Array::from(Vec::<i64>::new()));
    let row_arr: ArrayRef = Arc::new(Int64Array::from(Vec::<i64>::new()));
    let batch = RecordBatch::try_new(schema.clone(), vec![data_arr, row_arr])?;
    let mem_table = MemTable::try_new(schema, vec![vec![batch]])?;
    let ctx = SessionContext::new();
    let df = ctx.read_table(Arc::new(mem_table))?;

    let data_fref: FieldRef = Arc::new(data_field);
    let row_id_fref: FieldRef = Arc::new(row_id_field);
    let mut should_materialize: IndexMap<FieldRef, bool> = IndexMap::new();
    should_materialize.insert(data_fref, false);
    should_materialize.insert(row_id_fref, false);
    Ok(HintDF::new(df, should_materialize))
}

impl<B: SnarkBackend> ExprNode<B> {
    /// Re-scan the LIKE input string column at plan time to produce a
    /// `ScannedTables` view suitable for `compute_mcpm_witness`. Returns
    /// `None` when the child expr's PlanPayload hasn't been populated
    /// yet (e.g. wildcard-only patterns or upstream shapes that skip the
    /// hint pipeline).
    fn scan_string_side_data_plan_time_prover(
        &self,
        planned_ir: &crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> Option<ScannedTables<B::F>> {
        let child_hint = match planned_ir.payload_for_node(&self.expr.id()) {
            Some(PayloadStructure::PlanPayload(h)) => h.clone(),
            _ => return None,
        };
        let df = child_hint.data_frame().clone();

        let batches = collect_blocking_like(df).ok()?;
        if batches.is_empty() {
            return None;
        }
        let schema = batches[0].schema();
        let combined = datafusion::arrow::compute::concat_batches(&schema, &batches).ok()?;

        // Locate the Utf8/Utf8View column (the string column). Skip
        // system columns. If none present, we cannot scan.
        let string_col_idx = combined.schema().fields().iter().position(|f| {
            !is_system_column(f.name())
                && matches!(
                    f.data_type(),
                    DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View
                )
        })?;
        let string_column: ArrayRef = combined.column(string_col_idx).clone();

        // Compute the pre-padding active byte count the same way
        // `encode_utf8_like` does — sum of byte lengths of non-null rows.
        let n_rows = string_column.len();
        let active_len: usize = (0..n_rows)
            .map(|i| {
                if string_column.is_null(i) {
                    0
                } else {
                    match string_column.data_type() {
                        DataType::Utf8 => string_column
                            .as_any()
                            .downcast_ref::<datafusion::arrow::array::StringArray>()
                            .map(|a| a.value(i).len())
                            .unwrap_or(0),
                        DataType::LargeUtf8 => string_column
                            .as_any()
                            .downcast_ref::<datafusion::arrow::array::LargeStringArray>()
                            .map(|a| a.value(i).len())
                            .unwrap_or(0),
                        DataType::Utf8View => string_column
                            .as_any()
                            .downcast_ref::<datafusion::arrow::array::StringViewArray>()
                            .map(|a| a.value(i).len())
                            .unwrap_or(0),
                        _ => 0,
                    }
                }
            })
            .sum();

        let segments: Vec<EncodedSegment<B::F>> =
            encoding::encode_arrow_array_to_field::<B::F>(&string_column).ok()?;

        // Row-domain segment: length column. The length MLE keeps a
        // native small-int storage but this LIKE-gadget site needs a
        // `Vec<F>` for the field-arithmetic that follows, so we materialize
        // once here — the tracker never sees this expanded form.
        let l_evals: Vec<B::F> = segments
            .iter()
            .find(|seg| seg.suffix == STRING_LENGTH_SUFFIX)
            .and_then(|seg| seg.mle.as_ref())
            .map(|mle| mle.evaluations())?;

        // Side segments: chars, orig_ind, int_ind, bnd.
        let chars_bytes: Vec<u8> = segments
            .iter()
            .find(|seg| seg.suffix == STRING_CHARS_SUFFIX)
            .and_then(|seg| seg.side.as_ref())
            .and_then(|s| match &s.data {
                SideColData::Bytes(v) => Some(v.clone()),
                _ => None,
            })?;
        let orig_ind_u32: Vec<u32> = segments
            .iter()
            .find(|seg| seg.suffix == STRING_ORIG_IND_SUFFIX)
            .and_then(|seg| seg.side.as_ref())
            .and_then(|s| match &s.data {
                SideColData::U32(v) => Some(v.clone()),
                _ => None,
            })?;
        let int_ind_u32: Vec<u32> = segments
            .iter()
            .find(|seg| seg.suffix == STRING_INT_IND_SUFFIX)
            .and_then(|seg| seg.side.as_ref())
            .and_then(|s| match &s.data {
                SideColData::U32(v) => Some(v.clone()),
                _ => None,
            })?;
        let bnd_bytes: Vec<u8> = segments
            .iter()
            .find(|seg| seg.suffix == STRING_BND_SUFFIX)
            .and_then(|seg| seg.side.as_ref())
            .and_then(|s| match &s.data {
                SideColData::Bytes(v) => Some(v.clone()),
                _ => None,
            })?;

        let char: Vec<B::F> = chars_bytes.iter().map(|b| B::F::from(*b as u64)).collect();
        let orig_ind: Vec<B::F> = orig_ind_u32.iter().map(|v| B::F::from(*v as u64)).collect();
        let int_ind: Vec<B::F> = int_ind_u32.iter().map(|v| B::F::from(*v as u64)).collect();
        let bnd: Vec<B::F> = bnd_bytes.iter().map(|b| B::F::from(*b as u64)).collect();

        let padded_char_len = chars_bytes.len().max(1);
        let char_domain = padded_char_len.trailing_zeros() as usize;
        let mut char_act: Vec<B::F> = Vec::with_capacity(padded_char_len);
        for i in 0..padded_char_len {
            if i < active_len {
                char_act.push(B::F::from(1u64));
            } else {
                char_act.push(B::F::from(0u64));
            }
        }

        // Row-domain: `ind` from __row_id__, `a` from activator, both
        // padded to the string-domain size (already equal to n_rows since
        // Arrow batches are row-aligned).
        let str_domain = n_rows.max(1).trailing_zeros() as usize;
        let row_id_idx = combined
            .schema()
            .fields()
            .iter()
            .position(|f| f.name() == ROW_ID_COL_NAME);
        let ind: Vec<B::F> = if let Some(idx) = row_id_idx {
            let arr = combined.column(idx);
            let segs = encoding::encode_arrow_array_to_field::<B::F>(&arr.clone()).ok()?;
            segs.into_iter()
                .find(|seg| seg.suffix.is_empty())
                .and_then(|seg| seg.mle)
                .map(|mle| mle.evaluations())?
        } else {
            (0..n_rows).map(|i| B::F::from(i as u64)).collect()
        };

        let activator_idx = combined
            .schema()
            .fields()
            .iter()
            .position(|f| f.name() == ACTIVATOR_COL_NAME);
        let a: Vec<B::F> = if let Some(idx) = activator_idx {
            let arr = combined.column(idx);
            let segs = encoding::encode_arrow_array_to_field::<B::F>(&arr.clone()).ok()?;
            segs.into_iter()
                .find(|seg| seg.suffix.is_empty())
                .and_then(|seg| seg.mle)
                .map(|mle| mle.evaluations())?
        } else {
            vec![B::F::from(1u64); n_rows]
        };

        Some(ScannedTables::<B::F> {
            char,
            orig_ind,
            int_ind,
            bnd,
            char_act,
            char_domain,
            ind,
            a,
            l: l_evals,
            str_domain,
        })
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for ExprNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        if self.factors.is_empty() {
            // Empty-pattern short-circuit — no MCPM child, boolean
            // output IS the scope's activator.
            let scope_table = match virtualized_ir.payload_for_node(&self.expr.id()) {
                Some(PayloadStructure::PlanPayload(t)) => t.clone(),
                _ => panic!("Like: expected PlanPayload on input column child"),
            };
            let mut polys: IndexMap<FieldRef, TrackedPoly<B>> = IndexMap::new();
            let activator = scope_table
                .activator_tracked_poly()
                .expect("Like: empty-pattern short-circuit requires a scope activator");
            polys.insert(self.output_field(), activator.clone());
            polys.insert(ACTIVATOR_FIELD.clone(), activator);
            if let Some((row_id_field, row_id_poly)) = scope_table
                .tracked_polys_iter()
                .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
            {
                polys.insert(row_id_field.clone(), row_id_poly.clone());
            }
            let fields: Vec<Field> = polys.keys().map(|f| f.as_ref().clone()).collect();
            let schema = Some(Schema::new(fields));
            let log_size = scope_table.log_size();
            virtualized_ir.set_payload_for_node(
                id,
                Some(PayloadStructure::PlanPayload(TrackedTable::new(
                    schema, polys, log_size,
                ))),
            );
            return Ok(());
        }
        // Commit `a_new` upfront so parent nodes visited later in this
        // post-order pass (e.g. Filter) see a data column on our
        // PlanPayload.
        self.commit_a_new_prover(id, virtualized_ir)
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut ProverVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        if self.factors.is_empty() {
            return Ok(());
        }
        // Commit remaining witnesses + wire MCPM payload. Runs before
        // MCPM's own `initialize_gadgets` in this pre-order pass, so
        // MCPM will find its payload populated.
        self.commit_and_wire_prover(id, virtualized_ir)
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        if self.factors.is_empty() {
            return Ok(());
        }
        let mcpm_node = match self.mcpm.as_ref() {
            Some(m) => m.clone(),
            None => return Ok(()),
        };
        let scanned = match self.scan_string_side_data_plan_time_prover(planned_ir) {
            Some(s) => s,
            None => return Ok(()), // upstream hint not ready or wrong shape — skip.
        };
        let witness: McpmWitness<B::F> = compute_mcpm_witness(&scanned, &self.factors);

        let orig_ind_hint =
            build_virtual_char_domain_hint::<B::F>("orig_ind", scanned.orig_ind.clone())
                .map_err(|e| SnarkError::Artifact(format!("like plan hint: orig_ind: {e}")))?;

        let mut mcpm_payload = match planned_ir.payload_for_node(&mcpm_node.id()) {
            Some(PayloadStructure::GadgetPayload(m)) => m.clone(),
            _ => IndexMap::new(),
        };
        mcpm_payload.insert("__like_orig_ind_plan_hint__".to_string(), orig_ind_hint);
        for (j, fw) in witness.per_factor.iter().enumerate() {
            let mark_hint = build_virtual_char_domain_hint::<B::F>("mark", fw.mark.clone())
                .map_err(|e| SnarkError::Artifact(format!("like plan hint: mark[{j}]: {e}")))?;
            mcpm_payload.insert(format!("__like_f{j}_mark_plan_hint__"), mark_hint);
        }
        planned_ir.set_payload_for_node(
            mcpm_node.id(),
            Some(PayloadStructure::GadgetPayload(mcpm_payload)),
        );
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Verifier path — mirrors the prover's commit order via track_next_mv_com.
// -----------------------------------------------------------------------------

impl<B: SnarkBackend> VerifierNodeOps<B> for ExprNode<B> {
    fn add_virtual_witness(
        &self,
        id: NodeId,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        if self.factors.is_empty() {
            let scope_table = match virtualized_ir.payload_for_node(&self.expr.id()) {
                Some(PayloadStructure::PlanPayload(t)) => t.clone(),
                _ => panic!("Like: expected PlanPayload on input column child"),
            };
            let mut oracles: IndexMap<FieldRef, TrackedOracle<B>> = IndexMap::new();
            let activator = scope_table
                .activator_tracked_poly()
                .expect("Like: empty-pattern short-circuit requires a scope activator");
            oracles.insert(self.output_field(), activator.clone());
            oracles.insert(ACTIVATOR_FIELD.clone(), activator);
            if let Some((row_id_field, row_id_oracle)) = scope_table
                .tracked_oracles_iter()
                .find(|(field, _)| field.name() == ROW_ID_COL_NAME)
            {
                oracles.insert(row_id_field.clone(), row_id_oracle.clone());
            }
            let fields: Vec<Field> = oracles.keys().map(|f| f.as_ref().clone()).collect();
            let schema = Some(Schema::new(fields));
            let log_size = scope_table.log_size();
            virtualized_ir.set_payload_for_node(
                id,
                Some(PayloadStructure::PlanPayload(TrackedTableOracle::new(
                    schema, oracles, log_size,
                ))),
            );
            return Ok(());
        }
        self.track_a_new_verifier(id, virtualized_ir)
    }

    fn initialize_gadgets(
        &self,
        id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut VerifierVirtualizedIr<B>,
    ) -> SnarkResult<()> {
        if self.factors.is_empty() {
            return Ok(());
        }
        self.track_and_wire_verifier(id, virtualized_ir)
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        if self.factors.is_empty() {
            return Ok(());
        }
        let mcpm_node = match self.mcpm.as_ref() {
            Some(m) => m.clone(),
            None => return Ok(()),
        };
        let orig_ind_hint = build_virtual_char_domain_hint_schema_only("orig_ind")
            .map_err(|e| SnarkError::Artifact(format!("like plan hint: orig_ind: {e}")))?;

        let mut mcpm_payload = match planned_ir.payload_for_node(&mcpm_node.id()) {
            Some(PayloadStructure::GadgetPayload(m)) => m.clone(),
            _ => IndexMap::new(),
        };
        mcpm_payload.insert("__like_orig_ind_plan_hint__".to_string(), orig_ind_hint);
        for j in 0..self.factors.len() {
            let mark_hint = build_virtual_char_domain_hint_schema_only("mark")
                .map_err(|e| SnarkError::Artifact(format!("like plan hint: mark[{j}]: {e}")))?;
            mcpm_payload.insert(format!("__like_f{j}_mark_plan_hint__"), mark_hint);
        }
        planned_ir.set_payload_for_node(
            mcpm_node.id(),
            Some(PayloadStructure::GadgetPayload(mcpm_payload)),
        );
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Plan / IsPlanNode / IsExprNode / output()
// -----------------------------------------------------------------------------

impl<B: SnarkBackend> IsPlanNode<B> for ExprNode<B> {
    fn gadget(&self) -> Option<Node<B>> {
        self.mcpm.as_ref().map(|g| g.as_ref().clone())
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsProverPlanNode<B> for ExprNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let scope = self.scope[0]
            .upgrade()
            .expect("Like scope should be available during output");
        let scope_hint_df = match scope.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsProverPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Like scope cannot be a gadget node"),
        };
        let input_df =
            crate::irs::nodes::hints::sort_by_row_id_if_present(scope_hint_df.data_frame().clone())
                .expect("like row-id sort should succeed");
        let mut exprs = vec![self.output_expr()];
        crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut exprs);
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);
        let projected = input_df
            .select(exprs)
            .expect("like projection should succeed");
        let projected = crate::irs::nodes::hints::sort_by_row_id_if_present(projected)
            .expect("like output sort should succeed");
        let should_materialize: IndexMap<FieldRef, bool> = projected
            .schema()
            .fields()
            .iter()
            .map(|field| {
                let is_data = field.name() != ACTIVATOR_COL_NAME && field.name() != ROW_ID_COL_NAME;
                (field.clone(), is_data)
            })
            .collect();
        crate::irs::nodes::hints::HintDF::new(projected, should_materialize)
    }
}

impl<B: SnarkBackend> crate::irs::nodes::IsVerifierPlanNode<B> for ExprNode<B> {
    fn output(&self) -> crate::irs::nodes::hints::HintDF {
        let scope = self.scope[0]
            .upgrade()
            .expect("Like scope should be available during output");
        let scope_hint_df = match scope.as_ref() {
            Node::Plan(plan_node) => {
                <crate::irs::nodes::PlanNode<B> as crate::irs::nodes::IsVerifierPlanNode<B>>::output(
                    plan_node,
                )
            }
            Node::Gadget(_) => panic!("Like scope cannot be a gadget node"),
        };
        let input_df = scope_hint_df.data_frame().clone();
        let mut exprs = vec![self.output_expr()];
        crate::irs::nodes::hints::append_activator_exprs_if_present(&input_df, &mut exprs);
        crate::irs::nodes::hints::append_row_id_expr_if_present(&input_df, &mut exprs);
        let projected = input_df
            .select(exprs)
            .expect("like verifier projection should succeed");
        let should_materialize: IndexMap<FieldRef, bool> = projected
            .schema()
            .fields()
            .iter()
            .map(|field| {
                let is_data = field.name() != ACTIVATOR_COL_NAME && field.name() != ROW_ID_COL_NAME;
                (field.clone(), is_data)
            })
            .collect();
        crate::irs::nodes::hints::HintDF::new(projected, should_materialize)
    }
}

impl<B: SnarkBackend> IsExprNode<B> for ExprNode<B> {
    fn from_expr(
        expr: Expr,
        self_ref: std::sync::Weak<Node<B>>,
        parent: Option<std::sync::Weak<Node<B>>>,
        scope: Vec<std::sync::Weak<Node<B>>>,
    ) -> Self
    where
        Self: Sized,
    {
        let like = match expr {
            Expr::Like(l) => l,
            _ => panic!("Like::from_expr called with non-Like expression"),
        };
        assert!(!like.negated, "Like: NOT LIKE is not supported yet");
        assert!(
            !like.case_insensitive,
            "Like: case-insensitive matching is not supported yet"
        );
        assert!(
            like.escape_char.is_none(),
            "Like: ESCAPE clause is not supported yet"
        );
        let pattern_str = match like.pattern.as_ref() {
            Expr::Literal(ScalarValue::Utf8(Some(s)))
            | Expr::Literal(ScalarValue::LargeUtf8(Some(s)))
            | Expr::Literal(ScalarValue::Utf8View(Some(s))) => s.clone(),
            other => panic!(
                "Like: pattern must be a Utf8 literal, got {other:?}. \
                 Non-literal patterns are not supported yet."
            ),
        };
        let factors = parse_like_pattern::<B::F>(&pattern_str)
            .unwrap_or_else(|e| panic!("Like: pattern parse error: {e}"));

        let expr_node = Tree::<B>::from_expr(&like.expr, Some(self_ref.clone()), scope.clone())
            .root()
            .clone();
        let mcpm = if factors.is_empty() {
            None
        } else {
            Some(Arc::new(Node::<B>::Gadget(Arc::new(
                mcpm::GadgetNode::new(factors.clone()),
            ))))
        };

        Self {
            scope,
            parent,
            like,
            factors,
            expr: expr_node,
            mcpm,
            output_data_field_cache: Mutex::new(None),
        }
    }

    fn expr(&self) -> Expr {
        Expr::Like(self.like.clone())
    }

    fn parent(&self) -> crate::irs::nodes::PlanNode<B>
    where
        Self: Sized,
    {
        self.parent
            .as_ref()
            .and_then(|weak_ref| weak_ref.upgrade())
            .map(|arc_node| match arc_node.as_ref() {
                Node::Plan(plan_node) => plan_node.clone(),
                Node::Gadget(_) => panic!("Like parent cannot be a gadget node"),
            })
            .expect("Like node must have a parent")
    }

    fn scope(&self) -> Vec<Arc<Node<B>>>
    where
        Self: Sized,
    {
        self.scope
            .iter()
            .map(|s| s.upgrade().expect("Like scope should be available"))
            .collect()
    }
}
