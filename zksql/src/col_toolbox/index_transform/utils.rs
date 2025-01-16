use ark_ec::pairing::Pairing;
use ark_ff::Field;

use crate::pcs::PolynomialCommitmentScheme;
use crate::tracker::prelude::*;

// samples a random challenge from the transcript
// and uses it to take random linear combinations of the input cols
// C0 + r*C1 + r^2*C2 + ... + r^n*Cn
pub fn table_row_prover_agg<F, PCS>(
    table: &Table<F, PCS>,
    rand_coeffs: &Vec<F>,
) -> Result<Col<F, PCS>, PolyIOPErrors>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<F>,
{
    let mut res_poly = table.selector.clone();
    for i in 0..table.col_vals.len() {
        res_poly = res_poly.mul_poly(&table.col_vals[i].mul_scalar(rand_coeffs[i]));
    }
    let res_col = Col::new(res_poly, table.selector.clone());

    Ok(res_col)
}

// samples a random challenge from the transcript
// and uses it to take random linear combinations of the input ColComms
// C0 + r*C1 + r^2*C2 + ... + r^n*Cn
pub fn table_row_verifier_agg<F, PCS>(
    table_comm: &TableComm<F, PCS>,
    rand_coeffs: &Vec<F>,
) -> Result<ColComm<F, PCS>, PolyIOPErrors>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<F>,
{
    let mut res_poly = table_comm.selector.clone();
    for i in 0..table_comm.col_vals.len() {
        res_poly = res_poly.mul_comms(&table_comm.col_vals[i].mul_scalar(rand_coeffs[i]));
    }
    let res_col = ColComm::new(res_poly, table_comm.selector.clone(), table_comm.num_vars);

    Ok(res_col)
}


/// For sample rands there are two options: 
/// 1. sample once and take powers of it to get other rands
/// 2. sample many times for each rand you need
/// The pro of the first option is less sampling
/// the pro of the second option is Ex if values are boolean, can sample 128 bit challenges and keep numbers smaller 

pub fn prover_sample_rands<F, PCS>(
    prover_tracker: &mut ProverTrackerRef<F, PCS>,
    num_rands: usize,
) -> Result<Vec<F>, PolyIOPErrors>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<F>,
{
    let mut res = Vec::<F>::new();
    for _ in 0..num_rands {
        res.push(prover_tracker.get_and_append_challenge(b"r")?);
    }
    Ok(res)
}

pub fn verifier_sample_rands<F, PCS>(
    verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
    num_rands: usize,
) -> Result<Vec<F>, PolyIOPErrors>
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<F>,
{
    let mut res = Vec::<F>::new();
    for _ in 0..num_rands {
        res.push(verifier_tracker.get_and_append_challenge(b"r")?);
    }
    Ok(res)
}

pub fn prover_sample_rand_powers<F, PCS>(
    prover_tracker: &mut ProverTrackerRef<F, PCS>,
    num_rands: usize,
) -> Result<Vec<F>, PolyIOPErrors> 
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<F>,
{
    let r = prover_tracker.get_and_append_challenge(b"r")?;
    let mut res = Vec::<F>::new();
    for i in 0..num_rands {
        let i_slice = &[i as u64]; // formating input correctly for the pow function
        res.push(r.pow(&i_slice));
    }
    Ok(res)
}

pub fn verifier_sample_rand_powers<F, PCS>(
    verifier_tracker: &mut VerifierTrackerRef<F, PCS>,
    num_rands: usize,
) -> Result<Vec<F>, PolyIOPErrors> 
where
    E: Pairing,
    PCS: PolynomialCommitmentScheme<F>,
{
    let r = verifier_tracker.get_and_append_challenge(b"r")?;
    let mut res = Vec::<F>::new();
    for i in 0..num_rands {
        let i_slice = &[i as u64]; // formating input correctly for the pow function
        res.push(r.pow(&i_slice));
    }
    Ok(res)
}