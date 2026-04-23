use std::{collections::HashMap, sync::Arc};

use arithmetic::{ACTIVATOR_COL_NAME, table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::{SnarkBackend, errors::SnarkError, piop::PIOP};
use indexmap::IndexMap;

use crate::{
    irs::nodes::utils::nodup::perm_check::{PermPIOP, PermPIOPProverInput, PermPIOPVerifierInput},
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};

pub const INPUT_LABEL: &str = "__input__";
pub const OUTPUT_LABEL: &str = "__output__";

pub struct GadgetNode<B: SnarkBackend>(std::marker::PhantomData<B>);

impl<B: SnarkBackend> Default for GadgetNode<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "ResultCheck".to_string()
    }

    fn display(&self) -> String {
        self.name()
    }

    fn cost(
        &self,
        _statistics: datafusion_common::Statistics,
        _schema: arrow_schema::SchemaRef,
    ) -> crate::irs::nodes::cost::ProvingCost {
        todo!()
    }

    fn children(&self) -> Vec<Arc<Node<B>>> {
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
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let t_table = payload
            .get(INPUT_LABEL)
            .unwrap_or_else(|| panic!("ResultCheck gadget missing {}", INPUT_LABEL));
        let res_table = payload
            .get(OUTPUT_LABEL)
            .unwrap_or_else(|| panic!("ResultCheck gadget missing {}", OUTPUT_LABEL));
        prove_result_check(prover, t_table, res_table)
    }

    fn honest_prover_check(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        gadget_ready_ir: &mut GadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let Some(t_table) = payload.get(INPUT_LABEL) else {
            return Ok(());
        };
        println!("{}", t_table);
        let Some(r_table) = payload.get(OUTPUT_LABEL) else {
            return Ok(());
        };
        println!("{}", r_table);
        if active_row_multiset(t_table)? == active_row_multiset(r_table)? {
            Ok(())
        } else {
            Err(false_claim())
        }
    }

    fn verify(
        &self,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) = gadget_ready_ir.payload_for_node(&id)
        else {
            return Ok(());
        };
        let Some(t_table) = payload.get(INPUT_LABEL) else {
            return Ok(());
        };
        let Some(r_table) = payload.get(OUTPUT_LABEL) else {
            return Ok(());
        };
        verify_result_check(verifier, t_table, r_table).map_err(|err| {
            SnarkError::VerifierError(
                ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(format!(
                    "ResultCheck failed during final verifier checks: {err:?}"
                )),
            )
        })
    }

    fn prover_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }

    fn verifier_hints(&self) -> IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

fn prove_result_check<B: SnarkBackend>(
    prover: &mut ark_piop::prover::ArgProver<B>,
    t_table: &TrackedTable<B>,
    r_table: &TrackedTable<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let num_challenges = std::cmp::max(t_table.num_data_tracked_cols(), 1);
    let mut challenges = Vec::with_capacity(num_challenges);
    for _ in 0..num_challenges {
        challenges.push(prover.get_and_append_challenge(b"result_check_fold")?);
    }
    let t_fold = fold_table_for_result_check(t_table, &challenges);
    let r_fold = fold_table_for_result_check(r_table, &challenges);
    PermPIOP::<B>::prove(
        prover,
        PermPIOPProverInput {
            left_col: t_fold,
            right_col: r_fold,
        },
    )
}

fn verify_result_check<B: SnarkBackend>(
    verifier: &mut ark_piop::verifier::ArgVerifier<B>,
    t_table: &TrackedTableOracle<B>,
    r_table: &TrackedTableOracle<B>,
) -> ark_piop::errors::SnarkResult<()> {
    let num_challenges = std::cmp::max(t_table.num_data_tracked_col_oracles(), 1);
    let mut challenges = Vec::with_capacity(num_challenges);
    for _ in 0..num_challenges {
        challenges.push(verifier.get_and_append_challenge(b"result_check_fold")?);
    }
    let t_fold = fold_table_oracle_for_result_check(t_table, &challenges);
    let r_fold = fold_table_oracle_for_result_check(r_table, &challenges);
    PermPIOP::<B>::verify(
        verifier,
        PermPIOPVerifierInput {
            left_tracked_col_oracle: t_fold,
            right_tracked_col_oracle: r_fold,
        },
    )
}

fn active_positions<F: PrimeField>(evals: &[F]) -> Vec<usize> {
    evals
        .iter()
        .enumerate()
        .filter_map(|(idx, value)| (!value.is_zero()).then_some(idx))
        .collect()
}

fn tracked_row_key<B: SnarkBackend>(
    table: &TrackedTable<B>,
    row_idx: usize,
) -> ark_piop::errors::SnarkResult<String> {
    let schema = table
        .schema_ref()
        .expect("ResultCheck table schema missing");
    let mut parts = Vec::new();
    for field in schema.fields() {
        if field.name() == ACTIVATOR_COL_NAME {
            continue;
        }
        let value = table
            .tracked_polys_iter()
            .find_map(|(candidate, poly)| {
                (candidate.name() == field.name()).then_some(poly.evaluations())
            })
            .expect("ResultCheck row field missing");
        parts.push(format!("{:?}", value[row_idx]));
    }
    Ok(parts.join("|"))
}

fn active_row_multiset<B: SnarkBackend>(
    table: &TrackedTable<B>,
) -> ark_piop::errors::SnarkResult<HashMap<String, usize>> {
    let activator = table
        .activator_tracked_poly()
        .expect("ResultCheck table activator missing")
        .evaluations();
    let mut counts = HashMap::new();
    for row_idx in active_positions(&activator) {
        let key = tracked_row_key(table, row_idx)?;
        *counts.entry(key).or_insert(0) += 1;
    }
    Ok(counts)
}

fn fold_table_for_result_check<B: SnarkBackend>(
    table: &TrackedTable<B>,
    challenges: &[B::F],
) -> arithmetic::col::TrackedCol<B> {
    if table.num_data_tracked_cols() == 0 {
        arithmetic::col::TrackedCol::new(
            table
                .activator_tracked_poly()
                .expect("ResultCheck expects table activator")
                .clone(),
            None,
            None,
        )
    } else {
        table.fold_all_data_columns(challenges)
    }
}

fn fold_table_oracle_for_result_check<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    challenges: &[B::F],
) -> arithmetic::col_oracle::TrackedColOracle<B> {
    if table.num_data_tracked_col_oracles() == 0 {
        arithmetic::col_oracle::TrackedColOracle::new(
            table
                .activator_tracked_poly()
                .expect("ResultCheck expects table activator")
                .clone(),
            None,
            None,
        )
    } else {
        table.fold_all_data_oracles(challenges)
    }
}

fn false_claim() -> ark_piop::errors::SnarkError {
    ark_piop::errors::SnarkError::ProverError(
        ark_piop::prover::errors::ProverError::HonestProverError(
            ark_piop::prover::errors::HonestProverError::FalseClaim,
        ),
    )
}
