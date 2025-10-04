/// A structure to represent the cost of executing a node in the proof tree.
/// This is a struct copied from older version of datafusion
/// physical_optimizer/cost_model/struct.PlanCost
pub struct ProvingCost {
    cpu_cost: f64,
    memory_cost: f64,
    disk_cost: f64,
    network_cost: f64,
}
