/// A structure to represent the cost of executing a node in the proof tree.
/// This is a struct copied from older version of datafusion
/// physical_optimizer/cost_model/struct.PlanCost
pub struct ProvingCost {
    _cpu_cost: f64,
    _memory_cost: f64,
    _disk_cost: f64,
    _network_cost: f64,
}

impl ProvingCost {
    pub const fn new(cpu_cost: f64, memory_cost: f64, disk_cost: f64, network_cost: f64) -> Self {
        Self {
            _cpu_cost: cpu_cost,
            _memory_cost: memory_cost,
            _disk_cost: disk_cost,
            _network_cost: network_cost,
        }
    }

    pub const fn zero() -> Self {
        Self::new(0.0, 0.0, 0.0, 0.0)
    }
}

impl Default for ProvingCost {
    fn default() -> Self {
        Self::zero()
    }
}
