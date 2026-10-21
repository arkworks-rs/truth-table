use std::any::Any;
use std::sync::Arc;

use ark_piop::SnarkBackend;
use datafusion_expr::LogicalPlan;
use tt_core::irs::nodes::plan::lps::join::{
    LpNode as JoinLpNode,
    modes::{JoinMode, decide_join_mode},
};
use tt_core::irs::nodes::{IsNode, Node, PlanNode};
use tt_core::irs::shared_ir::InitialIr;
use tt_core::irs::tree::Tree;

use super::ProofPlanOptimizerRule;

/// Upgrades each join from the `MANY_TO_MANY` default chosen at LP→IR
/// ingestion to the variant (`ONE_TO_MANY`, `MANY_TO_ONE`, `ONE_TO_ONE`) its
/// PK/FK schema metadata supports. Without this rule every join runs the
/// general protocol on both prover and verifier.
pub struct PkFkSpecializationRule;

pub(super) const NAME: &str = "PkFkSpecialization";

impl<B: SnarkBackend> ProofPlanOptimizerRule<B> for PkFkSpecializationRule {
    fn name(&self) -> &'static str {
        NAME
    }

    fn optimize(&self, ir: InitialIr<B>) -> InitialIr<B> {
        // `set_join_mode` swaps the join's `Gadgets` variant in place and
        // drops the old variant's sub-gadgets, which the tree's arena still
        // indexes. Rebuild the tree from the root once any join changed.
        let root = ir.tree().root().clone();
        let mut mutated = false;
        specialize_in_place(&root, &mut mutated);
        if mutated {
            InitialIr::new_empty(Tree::new_from_root(root))
        } else {
            ir
        }
    }
}

fn specialize_in_place<B: SnarkBackend>(node: &Arc<Node<B>>, mutated: &mut bool) {
    if let Node::Plan(PlanNode::LpBased(lp_node)) = node.as_ref() {
        let any = lp_node.as_ref() as &dyn Any;
        if let Some(join_lp_node) = any.downcast_ref::<JoinLpNode<B>>()
            && let LogicalPlan::Join(join) = lp_node.lp()
        {
            let mode = decide_join_mode(&join);
            if mode != JoinMode::MANY_TO_MANY {
                join_lp_node.set_join_mode(mode);
                *mutated = true;
            }
        }
    }
    for child in node.children() {
        specialize_in_place(&child, mutated);
    }
}
