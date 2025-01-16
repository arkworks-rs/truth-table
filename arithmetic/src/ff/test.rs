use crate::{ff::sort_permute_ff, to_field_vec};
use ark_test_curves::bls12_381::Fr;

// #[test]
// fn sort_ff_works() {
//     let vec = to_field_vec!([6, 1, 0, 5, 2, 3, 4, 1], Fr);
//     let (sorted_vec, perm, inv_perm) = sort_permute_ff(&vec);
//     assert_eq!(sorted_vec, to_field_vec!([0, 1, 1, 2, 3, 4, 5, 6], Fr));
//     assert_eq!(perm, vec![2, 1, 7, 4, 5, 6, 3, 0]);
// }
