use std::sync::Arc;

use ark_piop::{verifier::ArgVerifier, SnarkBackend};
use datafusion::{arrow::datatypes::Schema, datasource::MemTable};
use datafusion_common::DFSchema;
use truthtable_core::{
    errors::TTResult,
    irs::{ir::Ir, nodes::Node, tree::Tree},
};

use crate::{shared::TTSharedConfig, structs::TTProof};

pub struct TTVerifierConfig<B: SnarkBackend> {
    phantom: std::marker::PhantomData<B>,
}
impl<B: SnarkBackend> TTVerifierConfig<B> {
    pub fn new() -> Self {
        Self {
            phantom: std::marker::PhantomData,
        }
    }
}

impl<B: SnarkBackend> Default for TTVerifierConfig<B> {
    fn default() -> Self {
        Self::new()
    }
}

/// Verifier configuration that bundles planner rules and context oracles.
pub struct TTVerifier<B: SnarkBackend> {
    verifier_config: TTVerifierConfig<B>,
    shared_config: TTSharedConfig<B>,
    arg_verifier: ArgVerifier<B>,
}

impl<B: SnarkBackend> TTVerifier<B> {
    pub fn new(
        verifier_config: TTVerifierConfig<B>,
        shared_config: TTSharedConfig<B>,
        arg_verifier: ArgVerifier<B>,
    ) -> Self {
        Self {
            verifier_config,
            shared_config,
            arg_verifier,
        }
    }

    pub fn verifier_config(&self) -> &TTVerifierConfig<B> {
        &self.verifier_config
    }
    pub fn shared_config(&self) -> &TTSharedConfig<B> {
        &self.shared_config
    }
    pub fn arg_verifier(&self) -> &ArgVerifier<B> {
        &self.arg_verifier
    }

    pub async fn prove(&self, query: &str) -> TTResult<(Arc<MemTable>, TTProof<B>)> {
        let initial_lp = self.shared_config().query_to_lp(query).await;
        let analyzed_and_optimized_lp = self
            .shared_config()
            .analyze_and_optimize_lp(initial_lp)
            .await;
        let tree: Tree<B> = Tree::from_logical_plan(&analyzed_and_optimized_lp);
        todo!()
    }
    // async fn perform_primary_passes(&self, tree: Tree<B>) -> MaterializedIr<B> {}
    // async fn perform_secondary_passes(&self) {}
}
