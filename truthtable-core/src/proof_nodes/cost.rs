/// A structure to represent the cost of executing a node in the proof tree.
/// This is a struct copied from older version of datafusion
/// physical_optimizer/cost_model/struct.PlanCost
pub struct ProvingCost {
    _cpu_cost: f64,
    _memory_cost: f64,
    _disk_cost: f64,
    _network_cost: f64,
}
