pub mod aggregate_check;
pub mod analyze_check;
pub mod distinct_check;
pub mod explain_check;
pub mod extension_check;
pub mod filter_check;
pub mod join_check;
pub mod limit_check;
pub mod other_check;
pub mod projection_check;
pub mod repartition_check;
pub mod sort_check;
pub mod subquery_alias_check;
pub mod subquery_check;
pub mod table_scan_check;
pub mod union_check;
pub mod values_check;
pub mod window_check;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    piop::PIOP,
};
use datafusion::logical_expr::LogicalPlan;
use planner::{
    arithmetized_plan::ArithmetizedPlan,
    ra_proof_plan::{ProofPlan, ProofPlanNodeId},
};
use std::sync::Arc;

use crate::logical_piop::projection_check::{ProjectionPIOP, ProjectionPIOPProverInput};

pub fn dispatch_logical_piop<F, MvPCS, UvPCS>(
    prover: &mut ark_piop::prover::Prover<F, MvPCS, UvPCS>,
    proof_node: &Arc<dyn ProofPlan>,
    arith_plan: &ArithmetizedPlan<F, MvPCS, UvPCS>,
) where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    let inner_logical_plan = match proof_node.node_id() {
        ProofPlanNodeId::LogicalPlan(plan) => plan,
        _ => panic!("Expected LogicalPlan node"),
    };
    match &inner_logical_plan {
        LogicalPlan::Projection(projection) => {
            dbg!(arith_plan);
            let expr_tables = projection
                .expr
                .iter()
                .map(|e| {
                    arith_plan
                        .table_for(&ProofPlanNodeId::Expr(e.clone()), "output")
                        .cloned()
                        .expect("missing expr arithmetized table")
                })
                .collect::<Vec<_>>();
            let input_tables = arith_plan
                .tables_for(&ProofPlanNodeId::LogicalPlan(
                    projection.input.as_ref().clone(),
                ))
                .expect("missing input arithmetized tables");
            let projection_piop_prover_input = ProjectionPIOPProverInput {
                projection: projection.clone(),
                input: input_tables["output"].clone(),
                expr: expr_tables,
            };
            ProjectionPIOP::prove(prover, projection_piop_prover_input).unwrap();
        },
        LogicalPlan::Filter(_) => todo!("dispatch filter logical plan node"),
        LogicalPlan::Limit(_) => todo!("dispatch limit logical plan node"),
        LogicalPlan::Aggregate(_) => todo!("dispatch aggregate logical plan node"),
        LogicalPlan::Sort(_) => todo!("dispatch sort logical plan node"),
        LogicalPlan::TableScan(ts) => {
            let table_scan_piop_prover_input = table_scan_check::TableScanPIOPProverInput {
                table_scan: ts.clone(),
            };
            table_scan_check::TableScanPIOP::prove(prover, table_scan_piop_prover_input).unwrap();
        },
        LogicalPlan::Join(_) => todo!("dispatch join logical plan node"),
        LogicalPlan::Repartition(_) => todo!("dispatch repartition logical plan node"),
        LogicalPlan::Union(_) => todo!("dispatch union logical plan node"),
        LogicalPlan::Values(_) => todo!("dispatch values logical plan node"),
        LogicalPlan::Window(_) => todo!("dispatch window logical plan node"),
        LogicalPlan::Subquery(_) => todo!("dispatch subquery logical plan node"),
        LogicalPlan::SubqueryAlias(_) => todo!("dispatch subquery alias logical plan node"),
        LogicalPlan::Distinct(_) => todo!("dispatch distinct logical plan node"),
        LogicalPlan::Explain(_) => todo!("dispatch explain logical plan node"),
        LogicalPlan::Extension(_) => todo!("dispatch extension logical plan node"),
        LogicalPlan::Analyze(_) => todo!("dispatch analyze logical plan node"),
        LogicalPlan::Statement(_) => todo!("dispatch statement logical plan node"),
        LogicalPlan::EmptyRelation(_) => todo!("dispatch empty relation logical plan node"),
        LogicalPlan::Copy(_) => todo!("dispatch copy logical plan node"),
        LogicalPlan::DescribeTable(_) => todo!("dispatch describe table logical plan node"),
        LogicalPlan::Unnest(_) => todo!("dispatch unnest logical plan node"),
        LogicalPlan::RecursiveQuery(_) => todo!("dispatch recursive query logical plan node"),
        LogicalPlan::Dml(_) => todo!("dispatch dml logical plan node"),
        LogicalPlan::Ddl(_) => todo!("dispatch ddl logical plan node"),
    }
}
