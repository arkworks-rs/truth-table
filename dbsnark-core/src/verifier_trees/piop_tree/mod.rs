use std::collections::HashMap;

use arithmetic::table_oracle::TrackedTableOracle;
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};
use indexmap::IndexMap;

use crate::{id::NodeId, verifier_trees::proof_tree::VerifierProofTree};

/// Virtualized tables indexed by proof-plan node identifier.
pub struct VerifierPIOPTree<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>> + 'static,
    UvPCS: PCS<F, Poly = LDE<F>> + 'static,
{
    tables: IndexMap<NodeId, HashMap<String, TrackedTableOracle<F, MvPCS, UvPCS>>>,
    inner_proof_tree: VerifierProofTree<F, MvPCS, UvPCS>,
}
