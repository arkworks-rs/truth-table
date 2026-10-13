//! Bind output cardinality to SQL LIMIT.
//!
//! The plan node binds output to a physical prefix of input. This gadget proves
//! the input activator Boolean and requires the domain capacity to be below the
//! field characteristic. A sumcheck then authenticates the output count `m`,
//! which must not exceed fetch. If `m < fetch`, a zerocheck requires all input
//! rows to survive; otherwise `m = fetch`. Thus `m = min(fetch, |input|)` in
//! either case. Without a fetch, all input rows must survive. The proof exposes
//! both `m` and the physical prefix endpoint `s` as transcript-bound constants;
//! callers must include both in their leakage model. On a sparse activator,
//! `s` can reveal more than the result cardinality.

use ark_ff::{One, PrimeField, Zero};
use ark_piop::{
    SnarkBackend, arithmetic::mat_poly::mle::MLE, errors::SnarkResult,
    prover::structs::polynomial::TrackedPoly, verifier::structs::oracle::TrackedOracle,
};
use datafusion_expr::Limit;
use indexmap::IndexMap;

use super::{checked_capacity, ensure_no_skip, field_to_usize, limit_check_error};

#[cfg(test)]
mod tests;

use crate::irs::{
    nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
    payloads::PayloadStructure,
};
use crate::prover::irs::GadgetReadyIr;
use crate::verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr;
pub const INPUT_ACTIVATOR_LABEL: &str = "__input_activator__";
pub const OUTPUT_ACTIVATOR_LABEL: &str = "__output_activator__";
pub struct GadgetNode<B: SnarkBackend> {
    pub phantom: std::marker::PhantomData<B>,
    limit: Limit,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Limit".to_string()
    }

    fn display(&self) -> String {
        let name = self.name();
        crate::irs::nodes::display_with_inputs(&name, &self.children())
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
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> VerifierNodeOps<B> for GadgetNode<B> {
    fn add_virtual_witness(
        &self,
        _id: crate::irs::nodes::NodeId,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
    fn initialize_gadgets(
        &self,
        _id: crate::irs::nodes::NodeId,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn initialize_gadget_plans(
        &self,
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        ensure_no_skip(&self.limit)?;
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Err(limit_check_error("LIMIT gadget payload is missing"));
        };
        let Some(input_table) = payload.get(INPUT_ACTIVATOR_LABEL).cloned() else {
            return Err(limit_check_error("LIMIT input activator is missing"));
        };
        let Some(output_table) = payload.get(OUTPUT_ACTIVATOR_LABEL).cloned() else {
            return Err(limit_check_error("LIMIT output activator is missing"));
        };

        if input_table.log_size() != output_table.log_size() {
            return Err(limit_check_error("LIMIT activator dimensions differ"));
        }
        let input_indices = input_table.data_tracked_polys_indices();
        let input_act = match input_indices.as_slice() {
            [idx] => input_table.tracked_col_by_ind(*idx).data_tracked_poly(),
            _ => {
                return Err(limit_check_error(
                    "LIMIT expects one input activator column",
                ));
            }
        };
        let data_indices = output_table.data_tracked_polys_indices();
        let output_act = match data_indices.as_slice() {
            [idx] => output_table.tracked_col_by_ind(*idx).data_tracked_poly(),
            _ => {
                return Err(limit_check_error(
                    "LIMIT expects one output activator column",
                ));
            }
        };

        let output_count = output_act.evaluations().iter().copied().sum::<B::F>();
        let committed_count = prover
            .track_and_commit_mat_mv_poly(&MLE::from_evaluations_vec(0, vec![output_count]))?;
        let keep_all = requires_all_input(&self.limit, output_count, input_table.log_size())?;
        let input_boolean = &input_act * &input_act.sub_scalar_poly(B::F::one());
        match input_boolean.as_constant() {
            Some(value) if !value.is_zero() => {
                return Err(limit_check_error("LIMIT input activator is not Boolean"));
            }
            Some(_) => {}
            None => prover.add_mv_zerocheck_claim(input_boolean.id())?,
        }
        match output_act.as_constant() {
            Some(value) => {
                let capacity = checked_capacity::<B::F>(output_table.log_size())?;
                let capacity_u64 = u64::try_from(capacity)
                    .map_err(|_| limit_check_error("LIMIT capacity does not fit into u64"))?;
                if output_count != value * B::F::from(capacity_u64) {
                    return Err(limit_check_error("LIMIT output count is incorrect"));
                }
            }
            None => {
                let difference = count_difference_prover(&output_act, &committed_count)?;
                prover.add_mv_sumcheck_claim(difference.id(), B::F::zero())?;
            }
        }
        if keep_all {
            let omitted_rows = &input_act - &output_act;
            match omitted_rows.as_constant() {
                Some(value) if !value.is_zero() => {
                    return Err(limit_check_error("LIMIT omitted an input row"));
                }
                Some(_) => {}
                None => prover.add_mv_zerocheck_claim(omitted_rows.id())?,
            }
        }
        Ok(())
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        ensure_no_skip(&self.limit)?;
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Err(limit_check_error("LIMIT gadget payload is missing"));
        };
        let Some(input_table) = payload.get(INPUT_ACTIVATOR_LABEL).cloned() else {
            return Err(limit_check_error("LIMIT input activator is missing"));
        };
        let Some(output_table) = payload.get(OUTPUT_ACTIVATOR_LABEL).cloned() else {
            return Err(limit_check_error("LIMIT output activator is missing"));
        };

        if input_table.log_size() != output_table.log_size() {
            return Err(limit_check_error("LIMIT activator dimensions differ"));
        }
        let input_indices = input_table.data_tracked_oracles_indices();
        let input_act = match input_indices.as_slice() {
            [idx] => input_table
                .tracked_col_oracle_by_ind(*idx)
                .data_tracked_oracle(),
            _ => {
                return Err(limit_check_error(
                    "LIMIT expects one input activator column",
                ));
            }
        };
        let data_indices = output_table.data_tracked_oracles_indices();
        let output_act = match data_indices.as_slice() {
            [idx] => output_table
                .tracked_col_oracle_by_ind(*idx)
                .data_tracked_oracle(),
            _ => {
                return Err(limit_check_error(
                    "LIMIT expects one output activator column",
                ));
            }
        };

        let committed_count = verifier.track_next_mv_com()?;
        if committed_count.log_size() != 0 {
            return Err(limit_check_error(
                "LIMIT output count committed scalar has variables",
            ));
        }
        let output_count = committed_count
            .as_constant()
            .ok_or_else(|| limit_check_error("LIMIT output count is not a committed scalar"))?;
        let keep_all = requires_all_input(&self.limit, output_count, input_table.log_size())?;
        let input_boolean = &input_act * &input_act.sub_scalar_oracle(B::F::one());
        match input_boolean.as_constant() {
            Some(value) if !value.is_zero() => {
                return Err(limit_check_error("LIMIT input activator is not Boolean"));
            }
            Some(_) => {}
            None => verifier.add_mv_zerocheck_claim(input_boolean.id()),
        }
        match output_act.as_constant() {
            Some(value) => {
                let capacity = checked_capacity::<B::F>(output_table.log_size())?;
                let capacity_u64 = u64::try_from(capacity)
                    .map_err(|_| limit_check_error("LIMIT capacity does not fit into u64"))?;
                if output_count != value * B::F::from(capacity_u64) {
                    return Err(limit_check_error("LIMIT output count is incorrect"));
                }
            }
            None => {
                let difference = count_difference_verifier(&output_act, &committed_count)?;
                verifier.add_mv_sumcheck_claim(difference.id(), B::F::zero());
            }
        }
        if keep_all {
            // A smaller result is allowed only when there are no omitted rows.
            let omitted_rows = &input_act - &output_act;
            match omitted_rows.as_constant() {
                Some(value) if !value.is_zero() => {
                    return Err(limit_check_error("LIMIT omitted an input row"));
                }
                Some(_) => {}
                None => verifier.add_mv_zerocheck_claim(omitted_rows.id()),
            }
        }
        Ok(())
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new(limit: Limit) -> Self {
        Self {
            limit,
            phantom: std::marker::PhantomData,
        }
    }
}

fn inverse_domain_size<F: PrimeField>(log_size: usize) -> SnarkResult<F> {
    F::from(2u64)
        .pow([log_size as u64])
        .inverse()
        .ok_or_else(|| limit_check_error("LIMIT domain size is not invertible"))
}

/// Build a polynomial whose hypercube sum is `sum(values) - count`.
///
/// The count is a committed zero-variable constant. Scaling it by the inverse
/// domain size makes its sum over `values`' domain exactly `count`.
fn count_difference_prover<B: SnarkBackend>(
    values: &TrackedPoly<B>,
    count: &TrackedPoly<B>,
) -> SnarkResult<TrackedPoly<B>> {
    let density = count.mul_scalar_poly(inverse_domain_size::<B::F>(values.log_size())?);
    Ok(values - &density)
}

fn count_difference_verifier<B: SnarkBackend>(
    values: &TrackedOracle<B>,
    count: &TrackedOracle<B>,
) -> SnarkResult<TrackedOracle<B>> {
    let density = count.mul_scalar_oracle(inverse_domain_size::<B::F>(values.log_size())?);
    Ok(values - &density)
}

fn requires_all_input<F: PrimeField>(
    limit: &Limit,
    output_count: F,
    log_size: usize,
) -> SnarkResult<bool> {
    let capacity = checked_capacity::<F>(log_size)?;
    let count = field_to_usize(output_count)?;
    if count > capacity {
        return Err(limit_check_error(
            "LIMIT output count exceeds the input capacity",
        ));
    }
    match limit.get_fetch_type() {
        Ok(datafusion_expr::FetchType::Literal(Some(fetch))) if count <= fetch => Ok(count < fetch),
        Ok(datafusion_expr::FetchType::Literal(Some(_))) => Err(limit_check_error(
            "LIMIT output count exceeds the public fetch",
        )),
        Ok(datafusion_expr::FetchType::Literal(None)) => Ok(true),
        _ => Err(limit_check_error(
            "LIMIT fetch must be a nonnegative literal",
        )),
    }
}
