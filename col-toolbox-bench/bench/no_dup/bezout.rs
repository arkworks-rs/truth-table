use ark_ff::UniformRand;
use ark_piop::arithmetic::mat_poly::lde::LDE;
use ark_poly::DenseUVPolynomial;
use ark_std::rand::Rng;
use ark_test_curves::bls12_381::Fr;
use col_toolbox::no_dup_check::bez_polys;
use rayon::ThreadPoolBuilder;
fn main() {
    ThreadPoolBuilder::new()
        .num_threads(10)
        .build_global()
        .unwrap();

    let start = 128.0_f64; // Explicitly declare as f64
    let end = 1_000_000.0_f64;
    let steps = 20; // Number of exponential steps

    // Properly calculate exponential growth factor
    let factor: usize = 2;
    let mut size: usize = start as usize;
    for _ in 0..steps {
        // Create a random vector of field elements of size `size`
        let mut rng = ark_std::test_rng();
        let a_elems: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
        let b_elems: Vec<Fr> = (0..size - 1).map(|_| Fr::rand(&mut rng)).collect();

        let a = LDE::from_coefficients_vec(a_elems);
        let b = LDE::from_coefficients_vec(b_elems);
        let start = std::time::Instant::now();
        let _x = bez_polys(&a, &b);
        let duration = start.elapsed();
        println!("Time elapsed for size {}: {:?}", size, duration);
        size *= factor; // Multiply by growth factor
    }
}
