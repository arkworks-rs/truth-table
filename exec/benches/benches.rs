// Single entry point for all exec benchmarks; module files register the benches.
mod aggregate;
mod filter;
mod limit;
mod prover;
mod support;
mod tpch;

fn main() {
    // Initialize tracing once, then run all registered Divan benches.
    support::init_bench_tracing();
    divan::main();
}
