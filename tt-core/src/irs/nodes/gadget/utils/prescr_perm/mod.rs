use std::sync::Arc;

use arithmetic::{table::TrackedTable, table_oracle::TrackedTableOracle};
use ark_ff::PrimeField;
use ark_piop::{
    SnarkBackend,
    arithmetic::mat_poly::mle::MLE,
    prover::structs::polynomial::get_or_insert_shift_poly,
    verifier::structs::oracle::{Oracle, get_or_insert_shift_oracle},
};
use datafusion::arrow::datatypes::{DataType, Field, FieldRef, Schema};
use indexmap::IndexMap;

use crate::{
    irs::{
        nodes::{IsGadgetNode, IsNode, Node, ProverNodeOps, VerifierNodeOps},
        payloads::PayloadStructure,
    },
    prover::irs::GadgetReadyIr,
    verifier::irs::GadgetReadyIr as VerifierGadgetReadyIr,
};
pub const LEFT_LABEL: &str = "__left__";
pub const PERM_LABEL: &str = "__perm__";
pub const RIGHT_LABEL: &str = "__right__";
const INDEX_LABEL: &str = "__index__";

pub struct GadgetNode<B: SnarkBackend> {
    perm: Arc<Node<B>>,
}

impl<B: SnarkBackend> IsNode<B> for GadgetNode<B> {
    fn name(&self) -> String {
        "Prescribed Permutation".to_string()
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

    fn initialize_gadget_plans(
        &self,
        _id: crate::irs::nodes::NodeId,
        _planned_ir: &mut crate::irs::shared_ir::OutputPlannedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn children(&self) -> Vec<std::sync::Arc<Node<B>>> {
        vec![self.perm.clone()]
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
        id: crate::irs::nodes::NodeId,
        prover: &mut ark_piop::prover::ArgProver<B>,
        virtualized_ir: &mut crate::prover::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            panic!("Expected gadget payload for Prescribed Permutation gadget");
        };

        let left = payload
            .get(LEFT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Prescribed Permutation missing {}", LEFT_LABEL));
        let right = payload
            .get(RIGHT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Prescribed Permutation missing {}", RIGHT_LABEL));
        let perm = payload
            .get(PERM_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Prescribed Permutation missing {}", PERM_LABEL));

        let padded_left = append_perm_col_prover(&left, &perm);
        let padded_right = append_index_col_prover(prover, &right);

        let mut perm_payload = match virtualized_ir.payload_for_node(&self.perm.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        perm_payload.insert(
            crate::irs::nodes::gadget::utils::perm::LEFT_LABEL.to_string(),
            padded_left,
        );
        perm_payload.insert(
            crate::irs::nodes::gadget::utils::perm::RIGHT_LABEL.to_string(),
            padded_right,
        );
        virtualized_ir.set_payload_for_node(
            self.perm.id(),
            Some(PayloadStructure::GadgetPayload(perm_payload)),
        );
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
        id: crate::irs::nodes::NodeId,
        verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        virtualized_ir: &mut crate::verifier::irs::VirtualizedIr<B>,
    ) -> ark_piop::errors::SnarkResult<()> {
        let Some(PayloadStructure::GadgetPayload(payload)) =
            virtualized_ir.payload_for_node(&id).cloned()
        else {
            panic!("Expected gadget payload for Prescribed Permutation gadget");
        };

        let left = payload
            .get(LEFT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Prescribed Permutation missing {}", LEFT_LABEL));
        let right = payload
            .get(RIGHT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Prescribed Permutation missing {}", RIGHT_LABEL));
        let perm = payload
            .get(PERM_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Prescribed Permutation missing {}", PERM_LABEL));

        let padded_left = append_perm_col_verifier(&left, &perm);
        let padded_right = append_index_col_verifier(verifier, &right);

        let mut perm_payload = match virtualized_ir.payload_for_node(&self.perm.id()) {
            Some(PayloadStructure::GadgetPayload(map)) => map.clone(),
            _ => IndexMap::new(),
        };
        perm_payload.insert(
            crate::irs::nodes::gadget::utils::perm::LEFT_LABEL.to_string(),
            padded_left,
        );
        perm_payload.insert(
            crate::irs::nodes::gadget::utils::perm::RIGHT_LABEL.to_string(),
            padded_right,
        );
        virtualized_ir.set_payload_for_node(
            self.perm.id(),
            Some(PayloadStructure::GadgetPayload(perm_payload)),
        );
        Ok(())
    }
}

impl<B: SnarkBackend> IsGadgetNode<B> for GadgetNode<B> {
    fn prove(
        &self,
        _prover: &mut ark_piop::prover::ArgProver<B>,
        _gadget_ready_ir: &mut GadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
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
        let left = payload
            .get(LEFT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Prescribed Permutation missing {}", LEFT_LABEL));
        let right = payload
            .get(RIGHT_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Prescribed Permutation missing {}", RIGHT_LABEL));
        let perm = payload
            .get(PERM_LABEL)
            .cloned()
            .unwrap_or_else(|| panic!("Prescribed Permutation missing {}", PERM_LABEL));

        // Basic permutation sanity check for honest prover mode.
        if !prescribed_perm_honest_check::<B>(&left, &right, &perm) {
            return Err(ark_piop::errors::SnarkError::ProverError(
                ark_piop::prover::errors::ProverError::HonestProverError(
                    ark_piop::prover::errors::HonestProverError::FalseClaim,
                ),
            ));
        }
        Ok(())
    }

    fn verify(
        &self,
        _verifier: &mut ark_piop::verifier::ArgVerifier<B>,
        _gadget_ready_ir: &mut VerifierGadgetReadyIr<B>,
        _id: crate::irs::nodes::NodeId,
    ) -> ark_piop::errors::SnarkResult<()> {
        Ok(())
    }

    fn hints(&self) -> indexmap::IndexMap<String, crate::irs::nodes::hints::HintDF> {
        IndexMap::new()
    }
}

impl<B: SnarkBackend> Default for GadgetNode<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: SnarkBackend> GadgetNode<B> {
    pub fn new() -> Self {
        let perm = Arc::new(Node::<B>::Gadget(Arc::new(
            crate::irs::nodes::gadget::utils::perm::GadgetNode::new(),
        )));
        Self { perm }
    }
}

fn append_perm_col_prover<B: SnarkBackend>(
    left: &TrackedTable<B>,
    perm: &TrackedTable<B>,
) -> TrackedTable<B> {
    let perm_indices = perm.data_tracked_polys_indices();
    if perm_indices.len() != 1 {
        panic!("Prescribed Permutation perm table must have exactly one data column");
    }
    let perm_polys = perm.tracked_polys();
    let (perm_field, perm_poly) = perm_polys
        .get_index(perm_indices[0])
        .expect("perm column index out of bounds");
    append_tracked_col(left, perm_field.clone(), perm_poly.clone())
}

fn append_index_col_prover<B: SnarkBackend>(
    prover: &mut ark_piop::prover::ArgProver<B>,
    right: &TrackedTable<B>,
) -> TrackedTable<B> {
    let data_poly = if let Some(idx) = right.data_tracked_polys_indices().first().copied() {
        right.tracked_col_by_ind(idx).data_tracked_poly()
    } else if let Some(activator) = right.activator_tracked_poly() {
        activator
    } else if let Some(col) = right.all_tracked_cols().first() {
        col.data_tracked_poly()
    } else {
        panic!("Prescribed Permutation expects at least one column on right table");
    };
    let log_size = data_poly.log_size();
    let index_tracked_poly = get_or_insert_shift_poly(prover, log_size, 0, true);

    let index_field = Arc::new(Field::new(INDEX_LABEL, DataType::UInt64, false));
    append_tracked_col(right, index_field, index_tracked_poly)
}

fn append_tracked_col<B: SnarkBackend>(
    table: &TrackedTable<B>,
    field: FieldRef,
    poly: ark_piop::prover::structs::polynomial::TrackedPoly<B>,
) -> TrackedTable<B> {
    let mut tracked_polys = table.tracked_polys();
    tracked_polys.insert(field.clone(), poly);
    let schema = table.schema_ref().map(|schema| {
        let mut fields = schema
            .fields()
            .iter()
            .map(|f| f.as_ref().clone())
            .collect::<Vec<_>>();
        fields.push(field.as_ref().clone());
        Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    let schema = schema.or_else(|| {
        Some(Schema::new(
            tracked_polys
                .keys()
                .map(|f| f.as_ref().clone())
                .collect::<Vec<_>>(),
        ))
    });
    TrackedTable::new(schema, tracked_polys, table.log_size())
}

fn append_perm_col_verifier<B: SnarkBackend>(
    left: &TrackedTableOracle<B>,
    perm: &TrackedTableOracle<B>,
) -> TrackedTableOracle<B> {
    let perm_indices = perm.data_tracked_oracles_indices();
    if perm_indices.len() != 1 {
        panic!("Prescribed Permutation perm table must have exactly one data column");
    }
    let perm_oracles = perm.tracked_oracles();
    let (perm_field, perm_oracle) = perm_oracles
        .get_index(perm_indices[0])
        .expect("perm column index out of bounds");
    append_tracked_oracle(left, perm_field.clone(), perm_oracle.clone())
}

fn append_index_col_verifier<B: SnarkBackend>(
    verifier: &mut ark_piop::verifier::ArgVerifier<B>,
    right: &TrackedTableOracle<B>,
) -> TrackedTableOracle<B> {
    let data_oracle = if let Some(idx) = right.data_tracked_oracles_indices().first().copied() {
        right.tracked_col_oracle_by_ind(idx).data_tracked_oracle()
    } else if let Some(activator) = right.activator_tracked_poly() {
        activator
    } else if let Some(col) = right.all_tracked_col_oracles().first() {
        col.data_tracked_oracle()
    } else {
        panic!("Prescribed Permutation expects at least one column on right table");
    };
    let log_size = data_oracle.log_size();
    let index_tracked_oracle = get_or_insert_shift_oracle(verifier, log_size, 0, true);

    let index_field = Arc::new(Field::new(INDEX_LABEL, DataType::UInt64, false));
    append_tracked_oracle(right, index_field, index_tracked_oracle)
}

fn append_tracked_oracle<B: SnarkBackend>(
    table: &TrackedTableOracle<B>,
    field: FieldRef,
    oracle: ark_piop::verifier::structs::oracle::TrackedOracle<B>,
) -> TrackedTableOracle<B> {
    let mut tracked_oracles = table.tracked_oracles();
    tracked_oracles.insert(field.clone(), oracle);
    let schema = table.schema_ref().map(|schema| {
        let mut fields = schema
            .fields()
            .iter()
            .map(|f| f.as_ref().clone())
            .collect::<Vec<_>>();
        fields.push(field.as_ref().clone());
        Schema::new_with_metadata(fields, schema.metadata().clone())
    });
    let schema = schema.or_else(|| {
        Some(Schema::new(
            tracked_oracles
                .keys()
                .map(|f| f.as_ref().clone())
                .collect::<Vec<_>>(),
        ))
    });
    TrackedTableOracle::new(schema, tracked_oracles, table.log_size())
}

fn prescribed_perm_honest_check<B: SnarkBackend>(
    left: &TrackedTable<B>,
    right: &TrackedTable<B>,
    perm: &TrackedTable<B>,
) -> bool {
    if left.log_size() != right.log_size() || left.log_size() != perm.log_size() {
        return false;
    }
    let size = left.size();

    let perm_indices = perm.data_tracked_polys_indices();
    if perm_indices.len() != 1 {
        return false;
    }
    let perm_vals = perm
        .tracked_col_by_ind(perm_indices[0])
        .data_tracked_poly()
        .evaluations();
    if perm_vals.len() != size {
        return false;
    }

    let left_data = data_columns_evals::<B>(left);
    let right_data = data_columns_evals::<B>(right);
    if left_data.len() != right_data.len() {
        return false;
    }

    let mut used = vec![false; size];

    for (row, perm_val) in perm_vals.iter().enumerate() {
        let target = (0..size).find(|idx| *perm_val == B::F::from(*idx as u64));
        let Some(target) = target else {
            return false;
        };
        if used[target] {
            return false;
        }
        if !rows_match(&left_data, &right_data, row, target) {
            return false;
        }
        used[target] = true;
    }
    true
}

fn data_columns_evals<B: SnarkBackend>(table: &TrackedTable<B>) -> Vec<Vec<B::F>> {
    table
        .data_tracked_polys_indices()
        .into_iter()
        .map(|idx| {
            // Compare activated values so inactive padded rows do not create
            // false mismatches during the honest permutation check.
            table
                .tracked_col_by_ind(idx)
                .activated_data_tracked_poly()
                .evaluations()
        })
        .collect()
}

fn rows_match<F: PartialEq>(
    left: &[Vec<F>],
    right: &[Vec<F>],
    left_row: usize,
    right_row: usize,
) -> bool {
    left.iter().zip(right.iter()).all(|(lcol, rcol)| {
        lcol.get(left_row)
            .zip(rcol.get(right_row))
            .map(|(l, r)| l == r)
            .unwrap_or(false)
    })
}

/// Builds a permutation polynomial representing a cyclic rotation of the
/// identity mapping.
///
/// # Arguments
/// * `log_size` - number of variables (domain size `2^log_size`)
/// * `shift` - rotation distance (normalized modulo domain size)
/// * `right` - when `true` rotates right, otherwise rotates left
pub fn shift_permutation_mle<F: PrimeField>(log_size: usize, shift: usize, right: bool) -> MLE<F> {
    let domain_size = 1usize << log_size;
    let normalized_shift = if domain_size == 0 {
        0
    } else {
        shift % domain_size
    };

    let mut evals: Vec<F> = (0..domain_size).map(|idx| F::from(idx as u64)).collect();

    if domain_size > 0 {
        if right {
            evals.rotate_right(normalized_shift);
        } else {
            evals.rotate_left(normalized_shift);
        }
    }

    MLE::from_evaluations_vec(log_size, evals)
}

/// Builds an oracle representing the cyclic permutation shift without
/// materialising the dense MLE. Everything that only depends on `log_size`,
/// `shift`, and `right` is pre-computed up front so that the closure only
/// performs point-dependent work.
pub fn shift_permutation_oracle<F: PrimeField>(
    log_size: usize,
    shift: usize,
    right: bool,
) -> Oracle<F> {
    // Domain size of the Boolean hypercube (2^log_size) and normalized shift.
    let domain_size = 1usize << log_size;
    let shift_mod = if domain_size == 0 {
        0
    } else {
        shift % domain_size
    };

    // Pre-compute the weights of the sparse range polynomial Σ x_i · 2^i.
    let mut weights = Vec::with_capacity(log_size);
    let mut coeff = F::one();
    for _ in 0..log_size {
        weights.push(coeff);
        coeff += coeff;
    }

    // Determine the additive offset and the threshold that marks wrap-around.
    let (delta_int, overflow_threshold) = if shift_mod == 0 {
        (0usize, None)
    } else if right {
        ((domain_size - shift_mod) % domain_size, Some(shift_mod))
    } else {
        (shift_mod, Some(domain_size - shift_mod))
    };

    // Convert the additive offset into the field once.
    let mut delta_f = F::zero();
    for (i, weight) in weights.iter().enumerate() {
        if ((delta_int >> i) & 1) == 1 {
            delta_f += *weight;
        }
    }

    // Field representation of 2^{log_size}, only needed when an overflow occurs.
    let domain_f = overflow_threshold.map(|_| {
        let mut value = F::one();
        for _ in 0..log_size {
            value += value;
        }
        value
    });

    // Cache the overflow threshold bits (least-significant bit first).
    let threshold_bits = overflow_threshold.map(|thr| {
        (0..log_size)
            .map(|i| ((thr >> i) & 1) == 1)
            .collect::<Vec<bool>>()
    });

    Oracle::new_multivariate(log_size, move |mut point: Vec<F>| {
        // 1. Normalise the input length to exactly `log_size`.
        if point.len() > log_size {
            point.truncate(log_size);
        } else if point.len() < log_size {
            point.resize(log_size, F::zero());
        }

        // 2. Evaluate the sparse range polynomial Σ x_i · 2^i using the cached weights.
        let range_value = point
            .iter()
            .zip(weights.iter())
            .fold(F::zero(), |acc, (bit, weight)| acc + (*bit * *weight));

        // 3. Apply the additive shift offset.
        let mut result = range_value + delta_f;

        // 4. Subtract 2^{log_size} if the rotation would overflow past the domain.
        if let (Some(bits), Some(domain)) = (threshold_bits.as_ref(), domain_f) {
            let overflow = evaluate_ge_bits(&point, bits);
            result -= domain * overflow;
        }

        Ok(result)
    })
}

/// Evaluates a polynomial that outputs 1 when `vars` encodes an integer that is
/// greater than or equal to the threshold defined by `threshold_bits` (LSB
/// first).
fn evaluate_ge_bits<F: PrimeField>(vars: &[F], threshold_bits: &[bool]) -> F {
    let one = F::one();
    let mut prefix_equal = F::one();
    let mut greater = F::zero();

    for i in (0..vars.len()).rev() {
        let bit_val = vars[i];
        if !threshold_bits[i] {
            greater += prefix_equal * bit_val;
            prefix_equal *= one - bit_val;
        } else {
            prefix_equal *= bit_val;
        }
    }

    greater + prefix_equal
}
