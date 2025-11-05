use arithmetic::{ctx::SharedCtx, table_oracle::ArithTableOracle};
use ark_piop::arithmetic::mat_poly::{lde::LDE, mle::MLE};
use ark_serialize::CanonicalDeserialize;
use datafusion::{logical_expr::LogicalPlan, prelude::SessionContext};
use indexmap::IndexMap;
use std::{fs::File, io::BufReader};
use tpch_data::test_data_path;
use truthtable_core::{
    proof_nodes::id::NodeId, prover::trees::proof_tree::ProverProofTree,
    verifier::trees::proof_tree::VerifierProofTree,
};

pub mod analyzer;
pub mod optimizer;

pub(crate) fn build_prover_proof_tree<F, MvPCS, UvPCS>(
    df_session_ctx: &SessionContext,
    unoptimized_plan: LogicalPlan,
    optimized_plan: LogicalPlan,
    prover_ctx: SharedCtx<F, MvPCS, UvPCS>,
) -> ProverProofTree<F, MvPCS, UvPCS>
where
    F: ark_ff::PrimeField,
    MvPCS: ark_piop::pcs::PCS<F, Poly = MLE<F>>,
    UvPCS: ark_piop::pcs::PCS<F, Poly = LDE<F>> + Sync,
{
    let proof_tree: ProverProofTree<F, MvPCS, UvPCS> =
        ProverProofTree::from_lp(df_session_ctx, prover_ctx, &optimized_plan, &NodeId::None);
    proof_tree
}

pub(crate) fn build_verifier_proof_tree<F, MvPCS, UvPCS>(
    df_session_ctx: &SessionContext,
    unoptimized_plan: LogicalPlan,
    optimized_plan: LogicalPlan,
    verifier_ctx: SharedCtx<F, MvPCS, UvPCS>,
) -> VerifierProofTree<F, MvPCS, UvPCS>
where
    F: ark_ff::PrimeField,
    MvPCS: ark_piop::pcs::PCS<F, Poly = MLE<F>>,
    UvPCS: ark_piop::pcs::PCS<F, Poly = LDE<F>> + Sync,
{
    let proof_tree: VerifierProofTree<F, MvPCS, UvPCS> =
        VerifierProofTree::from_lp(df_session_ctx, verifier_ctx, &optimized_plan, &NodeId::None);
    proof_tree
}

pub(crate) fn default_shared_ctx<F, MvPCS, UvPCS>() -> SharedCtx<F, MvPCS, UvPCS>
where
    F: ark_ff::PrimeField,
    MvPCS: ark_piop::pcs::PCS<F, Poly = MLE<F>>,
    UvPCS: ark_piop::pcs::PCS<F, Poly = LDE<F>> + Sync,
{
    let mut table_oracles = IndexMap::new();
    for table in ["lineitem"] {
        let oracle_path = test_data_path(format!("{table}.oracle"));
        if !oracle_path.exists() {
            continue;
        }
        let table_oracle_file = File::open(&oracle_path).expect("open table oracle commitment");
        let mut reader = BufReader::new(table_oracle_file);
        let table_serializable =
            ArithTableOracle::<F, MvPCS, UvPCS>::deserialize_uncompressed(&mut reader)
                .expect("deserialize table oracle");
        if let Some(schema) = table_serializable.schema() {
            table_oracles.insert(schema, table_serializable);
        }
    }

    SharedCtx::new(table_oracles)
}
