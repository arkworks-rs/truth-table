//! A PIOP to check if the mulltisets of two columns are equal considering their
//! multiplicities.
//!
//! More precisely, this PIOP checks if the union of the multisets of the activated elements in a set of columns with certain multiplicity polynomials is equal to the union of the multisets of the activated elements in another set of columns with other multiplicity polynomials. It's a genralization of the [Logup](https://eprint.iacr.org/2022/1530.pdf) protocol and is heavily used throughout other PIOPs in the `col-toolbox`.

mod honest_prover;
#[cfg(test)]
mod test;
use arithmetic::col::{ArithCol, ColCom};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{
        InputShapeError::{EmptyInput, InputLengthMismatch},
        SnarkError, SnarkResult,
    },
    pcs::PCS,
    piop::PIOP,
    prover::{Prover, structs::polynomial::TrackedPoly},
    structs::TrackerID,
    timed,
    verifier::{
        Verifier,
        errors::VerifierError::{self, VerifierInputShapeError},
        structs::oracle::TrackedOracle,
    },
};
use std::marker::PhantomData;

pub struct MultiplicityCheck<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    #[doc(hidden)] PhantomData<F>,
    #[doc(hidden)] PhantomData<MvPCS>,
    #[doc(hidden)] PhantomData<UvPCS>,
);

pub struct MultiplicityCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub fxs: Vec<ArithCol<F, MvPCS, UvPCS>>,
    pub gxs: Vec<ArithCol<F, MvPCS, UvPCS>>,
    pub mfxs: Vec<Option<TrackedPoly<F, MvPCS, UvPCS>>>,
    pub mgxs: Vec<Option<TrackedPoly<F, MvPCS, UvPCS>>>,
}

pub struct MultiplicityCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub fxs: Vec<ColCom<F, MvPCS, UvPCS>>,
    pub gxs: Vec<ColCom<F, MvPCS, UvPCS>>,
    pub mfxs: Vec<Option<TrackedOracle<F, MvPCS, UvPCS>>>,
    pub mgxs: Vec<Option<TrackedOracle<F, MvPCS, UvPCS>>>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for MultiplicityCheck<F, MvPCS, UvPCS>
{
    type ProverInput = MultiplicityCheckProverInput<F, MvPCS, UvPCS>;

    type ProverOutput = ();

    type VerifierOutput = ();

    type VerifierInput = MultiplicityCheckVerifierInput<F, MvPCS, UvPCS>;

    #[timed]
    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        Self::honest_prover_check_helper(&input)
    }

    #[timed]
    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        // Get the challenge gamma for the check -- Gamma appears in the denominator of
        // the sum
        let gamma = prover.and_append_challenge(b"gamma")?;
        // iterate over vector elements and generate subclaims:
        for i in 0..input.fxs.len() {
            println!("Proving subclaims for fxs[{}]", i);
            Self::prove_generate_subclaims(
                prover,
                input.fxs[i].clone(),
                input.mfxs[i].clone(),
                gamma,
            )?;
        }

        for i in 0..input.gxs.len() {
            println!("Proving subclaims for gxs[{}]", i);
            Self::prove_generate_subclaims(
                prover,
                input.gxs[i].clone(),
                input.mgxs[i].clone(),
                gamma,
            )?;
        }
        Ok(())
    }

    #[timed]
    fn verify(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        // check input shapes are correct
        if input.fxs.is_empty() {
            return Err(SnarkError::VerifierError(VerifierInputShapeError(
                EmptyInput,
            )));
        }
        if input.fxs.len() != input.mfxs.len() {
            return Err(SnarkError::VerifierError(VerifierInputShapeError(
                InputLengthMismatch {
                    expected: input.fxs.len(),
                    actual: input.mfxs.len(),
                },
            )));
        }
        if input.gxs.is_empty() {
            return Err(SnarkError::VerifierError(VerifierInputShapeError(
                EmptyInput,
            )));
        }

        if input.gxs.len() != input.mgxs.len() {
            return Err(SnarkError::VerifierError(VerifierInputShapeError(
                InputLengthMismatch {
                    expected: input.gxs.len(),
                    actual: input.mgxs.len(),
                },
            )));
        }

        // create challenges and commitments in same fashion as prover
        // assumption is that proof inputs are already added to the tracker
        let gamma = verifier.and_append_challenge(b"gamma")?;
        // iterate over vector elements and generate subclaims:
        let max_nv_f = input.fxs.iter().map(|x| x.num_vars()).max().unwrap();
        let max_nv_g = input.gxs.iter().map(|x| x.num_vars()).max().unwrap();
        let max_nv = max_nv_f.max(max_nv_g);
        let mut lhs_v: F = F::zero();
        let mut rhs_v: F = F::zero();
        for i in 0..input.fxs.len() {
            println!("verifying subclaims for fxs[{}]", i);
            let sum_claim_v = Self::verify_generate_subclaims(
                verifier,
                input.fxs[i].clone(),
                input.mfxs[i].clone(),
                gamma,
            )?;
            let ratio = 2_usize.pow((max_nv - input.fxs[i].num_vars()) as u32);
            let sum_claim_v_adj = sum_claim_v / F::from(ratio as u64);
            lhs_v += sum_claim_v_adj;
        }

        for i in 0..input.gxs.len() {
            println!("verifying subclaims for gxs[{}]", i);
            let sum_claim_v = Self::verify_generate_subclaims(
                verifier,
                input.gxs[i].clone(),
                input.mgxs[i].clone(),
                gamma,
            )?;
            let ratio = 2_usize.pow((max_nv - input.gxs[i].num_vars()) as u32);
            let sum_claim_v_adj = sum_claim_v / F::from(ratio as u64);
            rhs_v += sum_claim_v_adj;
        }

        // check that the values of claimed sums are equal
        if lhs_v != rhs_v {
            let mut err_msg = "LHS and RHS have different sums".to_string();
            err_msg.push_str(&format!(" LHS: {}, RHS: {}", lhs_v, rhs_v));
            return Err(SnarkError::VerifierError(
                VerifierError::VerifierCheckFailed(err_msg),
            ));
        }

        Ok(())
    }
}

impl<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>> MultiplicityCheck<F, MvPCS, UvPCS>
where
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    F: PrimeField,
{
    #[timed]
    fn prove_generate_subclaims(
        tracker: &mut Prover<F, MvPCS, UvPCS>,
        col: ArithCol<F, MvPCS, UvPCS>,
        m: Option<TrackedPoly<F, MvPCS, UvPCS>>,
        gamma: F,
    ) -> SnarkResult<()> {
        let nv = col.num_vars();
        // construct phat = 1/(col.p(x) - gamma), i.e. the denominator of the sum
        let p = col.data_poly();
        let mut p_evals = p.evaluations().to_vec();
        let mut p_minus_gamma: Vec<F> = p_evals.iter_mut().map(|x| *x - gamma).collect();
        let phat_evals = p_minus_gamma.as_mut_slice();
        ark_ff::fields::batch_inversion(phat_evals);
        let phat_mle = MLE::from_evaluations_slice(nv, phat_evals);

        // calculate what the final sum should be
        let mut v = F::zero();
        let phat = tracker.track_and_commit_mat_mv_poly(&phat_mle)?;
        let (sumcheck_challenge_poly, v) = match (col.actvtr_poly().as_ref(), m) {
            (Some(actv), Some(m)) => {
                let selector_evals = &actv.evaluations();
                let m_evals = m.evaluations();
                for i in 0..2_usize.pow(nv as u32) {
                    v += phat_mle[i] * m_evals[i] * selector_evals[i];
                }
                (&(&phat * &m) * *actv, v)
            },
            (None, Some(m)) => {
                let m_evals = m.evaluations();
                for i in 0..2_usize.pow(nv as u32) {
                    v += phat_mle[i] * m_evals[i];
                }
                (&phat * &m, v)
            },
            (Some(actv), None) => {
                let selector_evals = &actv.evaluations();
                for i in 0..2_usize.pow(nv as u32) {
                    v += phat_mle[i] * selector_evals[i];
                }
                (&phat * *actv, v)
            },
            (None, None) => {
                for i in 0..2_usize.pow(nv as u32) {
                    v += phat_mle[i];
                }
                (phat.clone(), v)
            },
        };

        // Create Zerocheck claim for proving phat(x) is created correctly,
        // i.e. ZeroCheck [(p(x)-gamma) * phat(x) - 1] = [(p * phat) - gamma * phat - 1]
        let phat_check_poly = &(&(p * &phat) - &(&phat * gamma)) + F::one().neg();
        // add the delayed prover claims to the tracker
        tracker.add_mv_sumcheck_claim(sumcheck_challenge_poly.id(), v)?;
        tracker.add_mv_zerocheck_claim(phat_check_poly.id())?;
        Ok(())
    }

    #[timed]
    fn verify_generate_subclaims(
        tracker: &mut Verifier<F, MvPCS, UvPCS>,
        col: ColCom<F, MvPCS, UvPCS>,
        m: Option<TrackedOracle<F, MvPCS, UvPCS>>,
        gamma: F,
    ) -> SnarkResult<F> {
        let p: TrackedOracle<F, MvPCS, UvPCS> = col.inner;
        // get phat mat comm from proof and add it to the tracker
        let phat_id: TrackerID = tracker.peek_next_id();
        let phat = tracker.track_mv_com_by_id(phat_id)?;
        // make the virtual comms as prover does
        let sumcheck_challenge_comm = match (col.actv.as_ref(), m) {
            (Some(actv), Some(m)) => &(&phat * &m) * actv,
            (None, Some(m)) => &phat * &m,
            (Some(actv), None) => &phat * actv,
            (None, None) => phat.clone(),
        };

        let phat_check_poly = &(&(&p * &phat) - &(&phat * gamma)) + F::one().neg();
        // add the delayed prover claims to the tracker
        let sum_claim_v = tracker.prover_claimed_sum(sumcheck_challenge_comm.id)?;
        tracker.add_sumcheck_claim(sumcheck_challenge_comm.id, sum_claim_v);
        tracker.add_zerocheck_claim(phat_check_poly.id);

        Ok(sum_claim_v)
    }
}
