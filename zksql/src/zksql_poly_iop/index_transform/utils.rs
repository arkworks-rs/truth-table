use ark_ec::pairing::Pairing;
use ark_ff::Field;

use crate::subroutines::pcs::PolynomialCommitmentScheme;
use crate::tracker::prelude::*;

// samples a random challenge from the transcript
// and uses it to take random linear combinations of the input bags
// C0 + r*C1 + r^2*C2 + ... + r^n*Cn
pub fn table_row_prover_agg<E, PCS>(
    table: &Table<E, PCS>,
    rand_coeffs: &Vec<E::ScalarField>,
) -> Result<Bag<E, PCS>, PolyIOPErrors>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    let mut res_poly = table.selector.clone();
    for i in 0..table.col_vals.len() {
        res_poly = res_poly.mul_poly(&table.col_vals[i].mul_scalar(rand_coeffs[i]));
    }
    let res_bag = Bag::new(res_poly, table.selector.clone());

    Ok(res_bag)
}

// samples a random challenge from the transcript
// and uses it to take random linear combinations of the input BagComms
// C0 + r*C1 + r^2*C2 + ... + r^n*Cn
pub fn table_row_verifier_agg<E, PCS>(
    table_comm: &TableComm<E, PCS>,
    rand_coeffs: &Vec<E::ScalarField>,
) -> Result<BagComm<E, PCS>, PolyIOPErrors>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    let mut res_poly = table_comm.selector.clone();
    for i in 0..table_comm.col_vals.len() {
        res_poly = res_poly.mul_comms(&table_comm.col_vals[i].mul_scalar(rand_coeffs[i]));
    }
    let res_bag = BagComm::new(res_poly, table_comm.selector.clone(), table_comm.num_vars);

    Ok(res_bag)
}


/// For sample rands there are two options: 
/// 1. sample once and take powers of it to get other rands
/// 2. sample many times for each rand you need
/// The pro of the first option is less sampling
/// the pro of the second option is Ex if values are boolean, can sample 128 bit challenges and keep numbers smaller 

pub fn prover_sample_rands<E, PCS>(
    prover_tracker: &mut ProverTrackerRef<E, PCS>,
    num_rands: usize,
) -> Result<Vec<E::ScalarField>, PolyIOPErrors>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    let mut res = Vec::<E::ScalarField>::new();
    for _ in 0..num_rands {
        res.push(prover_tracker.get_and_append_challenge(b"r")?);
    }
    Ok(res)
}

pub fn verifier_sample_rands<E, PCS>(
    verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
    num_rands: usize,
) -> Result<Vec<E::ScalarField>, PolyIOPErrors>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    let mut res = Vec::<E::ScalarField>::new();
    for _ in 0..num_rands {
        res.push(verifier_tracker.get_and_append_challenge(b"r")?);
    }
    Ok(res)
}

pub fn prover_sample_rand_powers<E, PCS>(
    prover_tracker: &mut ProverTrackerRef<E, PCS>,
    num_rands: usize,
) -> Result<Vec<E::ScalarField>, PolyIOPErrors> 
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    let r = prover_tracker.get_and_append_challenge(b"r")?;
    let mut res = Vec::<E::ScalarField>::new();
    for i in 0..num_rands {
        let i_slice = &[i as u64]; // formating input correctly for the pow function
        res.push(r.pow(&i_slice));
    }
    Ok(res)
}

pub fn verifier_sample_rand_powers<E, PCS>(
    verifier_tracker: &mut VerifierTrackerRef<E, PCS>,
    num_rands: usize,
) -> Result<Vec<E::ScalarField>, PolyIOPErrors> 
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<E>,
{
    let r = verifier_tracker.get_and_append_challenge(b"r")?;
    let mut res = Vec::<E::ScalarField>::new();
    for i in 0..num_rands {
        let i_slice = &[i as u64]; // formating input correctly for the pow function
        res.push(r.pow(&i_slice));
    }
    Ok(res)
}