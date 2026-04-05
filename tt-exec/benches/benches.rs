// Single entry point for all exec benchmarks; module files register the benches.
mod aggregate;
mod commit;
mod filter;
mod join;
mod limit;
mod order_by;
mod prover;
mod support;
mod tpch;

use std::{fs, io};

fn relocate_benches_json() -> io::Result<()> {
    let current_dir = std::env::current_dir()?;
    let source = current_dir.join("benches.json");
    if !source.exists() {
        return Ok(());
    }

    let Some(workspace_root) = current_dir.parent() else {
        return Ok(());
    };
    let destination_dir = workspace_root.join("tt-results").join("raw");
    fs::create_dir_all(&destination_dir)?;
    let destination = destination_dir.join("benches.json");

    if destination.exists() {
        fs::remove_file(&destination)?;
    }

    match fs::rename(&source, &destination) {
        Ok(()) => Ok(()),
        Err(_) => {
            fs::copy(&source, &destination)?;
            fs::remove_file(source)
        }
    }
}

fn main() {
    // Initialize tracing once, then run all registered Divan benches.
    support::init_bench_tracing();
    divan::main();
    if let Err(err) = relocate_benches_json() {
        eprintln!("failed to move benches.json into tt-results/raw: {err}");
    }
}
