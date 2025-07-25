use ark_piop::{
    pcs::{kzg10::KZG10, pst13::PST13},
    test_utils::prelude_with_vars,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};

#[divan::bench(consts = [
   16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,
])]
fn setup<const N: usize>() {
    let _ = prelude_with_vars::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(N);
}
