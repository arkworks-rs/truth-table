//! A gadget node for paper §4.3 Broadcast Check.
//!
//! Given a string-level column `x` and a character-level column `x'`,
//! together with `src` (character → owning-string index) and `ind`
//! (string identity), the gadget proves for every active character `c`:
//!
//! ```text
//! x'[c] = x[src[c]]
//! ```
//!
//! Payload structure:
//! - `STR_LABEL` (`"__str__"`) — string-level table with data columns
//!   `ind` (index 0) and `x` (index 1). The table's activator is `ah`.
//! - `CHAR_LABEL` (`"__char__"`) — character-level table with data
//!   columns `src` (index 0) and `x'` (index 1). The table's activator
//!   is `ac`.
//!
//! Reduces to a single [`col_toolbox::lookup::LookupPIOP`] on the
//! fingerprinted pairs `(src + r·x')` ⊑ `(ind + r·x)` at a challenge `r`.
//! Distinct `ind` values across active string rows is a well-formedness
//! precondition on the caller.
use std::marker::PhantomData;

use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_piop::{
    SnarkBackend,
    errors::SnarkResult,
    piop::PIOP,
};
use col_toolbox::lookup::{LookupPIOP, LookupProverInput, LookupVerifierInput};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, NodeId, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub const STR_LABEL: &str = "__str__";
pub const CHAR_LABEL: &str = "__char__";

/// Gadget node for the broadcast relation `x'[c] = x[src[c]]`.
pub struct GadgetNode<B: SnarkBackend>(PhantomData<B>);

impl<B: SnarkBackend> Default for GadgetNode<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "BroadcastCheck".to_string()
    }

    fn display(&self) -> String {
        crate::irs::nodes::display_with_inputs(&self.name(), &self.children())
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![]
    }
}

impl<B: SnarkBackend> ProverNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        let (str_col, char_col, src_col, ind_col) = payload_prover(gadget_ready_ir, id);
        let r = prover.get_and_append_challenge(b"broadcast_check_r")?;

        // Fingerprint char side: src + r * x'. Data poly is virtual; the
        // char activator masks inactive chars via the resulting col.
        let looked_up_data =
            &src_col.data_tracked_poly() + &(char_col.data_tracked_poly() * r);
        let looked_up_col = TrackedCol::new(
            looked_up_data,
            char_col.activator_tracked_poly(),
            char_col.field_ref(),
        );

        // Fingerprint string side: ind + r * x. Activator: ah (from ind_col).
        let super_data = &ind_col.data_tracked_poly() + &(str_col.data_tracked_poly() * r);
        let super_col = TrackedCol::new(
            super_data,
            str_col.activator_tracked_poly(),
            str_col.field_ref(),
        );

        LookupPIOP::<B>::prove(
            prover,
            LookupProverInput {
                included_cols: vec![looked_up_col],
                super_col,
            },
        )?;
        Ok(())
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        use ark_ff::Zero;
        use ark_piop::{
            errors::SnarkError,
            prover::errors::{HonestProverError, ProverError},
        };

        let (str_col, char_col, src_col, ind_col) = payload_prover(gadget_ready_ir, id);

        let str_data = str_col.data_tracked_poly().evaluations();
        let str_act = str_col.activator_tracked_poly().map(|a| a.evaluations());
        let ind_data = ind_col.data_tracked_poly().evaluations();

        // Build ind_value -> str_value over active string rows.
        let mut ind_to_str: IndexMap<B::F, B::F> = IndexMap::with_capacity(str_data.len());
        for (i, (&ind_i, &x_i)) in ind_data.iter().zip(str_data.iter()).enumerate() {
            let active = str_act.as_ref().map(|a| !a[i].is_zero()).unwrap_or(true);
            if !active {
                continue;
            }
            if ind_to_str.insert(ind_i, x_i).is_some() {
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }

        let char_data = char_col.data_tracked_poly().evaluations();
        let char_act = char_col.activator_tracked_poly().map(|a| a.evaluations());
        let src_data = src_col.data_tracked_poly().evaluations();

        for (c, (&x_prime_c, &src_c)) in char_data.iter().zip(src_data.iter()).enumerate() {
            let active = char_act.as_ref().map(|a| !a[c].is_zero()).unwrap_or(true);
            if !active {
                continue;
            }
            let expected = ind_to_str.get(&src_c).copied().unwrap_or_else(|| {
                // Encode "no matching string" as a mismatch below.
                x_prime_c + B::F::from(1u64)
            });
            if x_prime_c != expected {
                return Err(SnarkError::ProverError(ProverError::HonestProverError(
                    HonestProverError::FalseClaim,
                )));
            }
        }
        Ok(())
    }

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: NodeId,
    ) -> SnarkResult<()> {
        let (str_col_o, char_col_o, src_col_o, ind_col_o) =
            payload_verifier(gadget_ready_ir, id);
        let r = verifier.get_and_append_challenge(b"broadcast_check_r")?;

        let looked_up_data =
            &src_col_o.data_tracked_oracle() + &(char_col_o.data_tracked_oracle() * r);
        let looked_up_oracle = TrackedColOracle::new(
            looked_up_data,
            char_col_o.activator_tracked_oracle(),
            char_col_o.field_ref(),
        );

        let super_data =
            &ind_col_o.data_tracked_oracle() + &(str_col_o.data_tracked_oracle() * r);
        let super_oracle = TrackedColOracle::new(
            super_data,
            str_col_o.activator_tracked_oracle(),
            str_col_o.field_ref(),
        );

        LookupPIOP::<B>::verify(
            verifier,
            LookupVerifierInput {
                included_tracked_col_oracles: vec![looked_up_oracle],
                super_tracked_col_oracle: super_oracle,
            },
        )?;
        Ok(())
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

fn payload_prover<B: SnarkBackend>(
    gadget_ready_ir: &GadgetReadyIr<B>,
    id: NodeId,
) -> (
    TrackedCol<B>, // str_col (data = x, activator = ah)
    TrackedCol<B>, // char_col (data = x', activator = ac)
    TrackedCol<B>, // src_col (data = src, activator = ac)
    TrackedCol<B>, // ind_col (data = ind, activator = ah)
) {
    let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
    else {
        panic!("Expected gadget payload for BroadcastCheck gadget node");
    };
    let str_table = payload
        .get(STR_LABEL)
        .expect("BroadcastCheck: missing STR payload");
    let char_table = payload
        .get(CHAR_LABEL)
        .expect("BroadcastCheck: missing CHAR payload");

    let str_indices = str_table.data_tracked_polys_indices();
    assert_eq!(
        str_indices.len(),
        2,
        "BroadcastCheck STR must have exactly two data columns (ind, x)"
    );
    let char_indices = char_table.data_tracked_polys_indices();
    assert_eq!(
        char_indices.len(),
        2,
        "BroadcastCheck CHAR must have exactly two data columns (src, x')"
    );

    let ind_col = str_table.tracked_col_by_ind(str_indices[0]);
    let str_col = str_table.tracked_col_by_ind(str_indices[1]);
    let src_col = char_table.tracked_col_by_ind(char_indices[0]);
    let char_col = char_table.tracked_col_by_ind(char_indices[1]);
    (str_col, char_col, src_col, ind_col)
}

fn payload_verifier<B: SnarkBackend>(
    gadget_ready_ir: &VerifierGadgetReadyIr<B>,
    id: NodeId,
) -> (
    TrackedColOracle<B>,
    TrackedColOracle<B>,
    TrackedColOracle<B>,
    TrackedColOracle<B>,
) {
    let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
    else {
        panic!("Expected gadget payload for BroadcastCheck gadget node");
    };
    let str_table = payload
        .get(STR_LABEL)
        .expect("BroadcastCheck: missing STR payload");
    let char_table = payload
        .get(CHAR_LABEL)
        .expect("BroadcastCheck: missing CHAR payload");

    let str_indices = str_table.data_tracked_oracles_indices();
    assert_eq!(
        str_indices.len(),
        2,
        "BroadcastCheck STR must have exactly two data columns (ind, x)"
    );
    let char_indices = char_table.data_tracked_oracles_indices();
    assert_eq!(
        char_indices.len(),
        2,
        "BroadcastCheck CHAR must have exactly two data columns (src, x')"
    );

    let ind_col = str_table.tracked_col_oracle_by_ind(str_indices[0]);
    let str_col = str_table.tracked_col_oracle_by_ind(str_indices[1]);
    let src_col = char_table.tracked_col_oracle_by_ind(char_indices[0]);
    let char_col = char_table.tracked_col_oracle_by_ind(char_indices[1]);
    (str_col, char_col, src_col, ind_col)
}

#[cfg(test)]
mod tests;
