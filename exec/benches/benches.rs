// Single entry point for all exec benchmarks; module files register the benches.
mod support;
mod filter;
mod aggregate;
mod tpch;
mod prover;

fn main() {
    // Initialize tracing once, then run all registered Divan benches.
    support::init_bench_tracing();
    divan::main();
}
