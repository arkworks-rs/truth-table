test:
    RUST_LOG=off cargo test --release --features "honest-prover, test-utils"
    RUST_LOG=off cargo test --release --features "test-utils"