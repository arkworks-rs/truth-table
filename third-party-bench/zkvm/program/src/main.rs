//! The SP1 guest: hashes the input columns, runs the query, and commits the
//! query, the input hashes and the result hash (`tt_zkvm_lib::PublicValues`).

#![no_main]
sp1_zkvm::entrypoint!(main);

use tt_zkvm_lib::{hash, result_hash, Column, PublicValues, Query};

pub fn main() {
    let query: Query = sp1_zkvm::io::read();
    let mut input_hashes = Vec::new();
    let mut inputs = Vec::new();
    for _ in query.inputs() {
        let bytes = sp1_zkvm::io::read_vec();
        input_hashes.push(hash(&bytes));
        inputs.push(Column::decode(&bytes));
    }
    let result = query.run(&inputs);
    sp1_zkvm::io::commit(&PublicValues {
        query,
        input_hashes,
        result_hash: result_hash(&result),
    });
}
