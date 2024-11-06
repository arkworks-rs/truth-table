#[cfg(test)]
mod test {
    use std::{
        ops::Neg,
        sync::Arc,
    };
    
    use ark_bls12_381::{Bls12_381, Fr};
    use ark_ff::UniformRand;
    use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
    use ark_std::{One, test_rng, Zero};
    
    use crate::tracker::prelude::*;
    
    use crate::subroutines::{
        MultilinearKzgPCS,
        PolyIOP,
        pcs::PolynomialCommitmentScheme,
        poly_iop::{
            sum_check::SumCheck,
            // errors::PolyIOPErrors,
        },
    };
    
    use crate::transcript::IOPTranscript;
    

    #[test]
    fn test_track_mat_poly() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 4;
         let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;
        let mut tracker = ProverTrackerRef::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new_from_pcs_params(pcs_param);
        

        let rand_mle_1 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly1 = tracker.track_and_commit_poly(rand_mle_1.clone())?;
        let poly2 = tracker.track_and_commit_poly(rand_mle_2.clone())?;
        
        // assert polys get different ids
        assert_ne!(poly1.id, poly2.id);

        // assert that we can get the polys back
        let lookup_poly1 = tracker.get_mat_poly(poly1.id);
        assert_eq!(lookup_poly1, Arc::new(rand_mle_1));
        Ok(())
    }

    #[test]
    fn test_add_mat_polys() -> Result<(),  PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 4;
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;
        let mut tracker = ProverTrackerRef::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new_from_pcs_params(pcs_param);

        let rand_mle_1 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly1 = tracker.track_and_commit_poly(rand_mle_1.clone())?;
        let poly2 = tracker.track_and_commit_poly(rand_mle_2.clone())?;
        let sum_poly = poly1.add_poly(&poly2);

        // assert addition list is constructed correctly
        let sum_poly_id_repr = tracker.get_virt_poly(sum_poly.id);
        assert_eq!(sum_poly_id_repr.len(), 2);
        assert_eq!(sum_poly_id_repr[0].0, Fr::one());
        assert_eq!(sum_poly_id_repr[0].1, vec![poly1.id]);
        assert_eq!(sum_poly_id_repr[1].0, Fr::one());
        assert_eq!(sum_poly_id_repr[1].1, vec![poly2.id]);

        // test evalutation at a random point
        let test_eval_pt: Vec<Fr> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();
        let sum_eval = sum_poly.evaluate(&test_eval_pt).unwrap();
        let poly1_eval = rand_mle_1.evaluate(&test_eval_pt).unwrap();
        let poly2_eval = rand_mle_2.evaluate(&test_eval_pt).unwrap();
        assert_eq!(sum_eval, poly1_eval + poly2_eval);

        Ok(())
    }

    #[test]
    fn test_add_mat_poly_to_virtual_poly() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 4;
         let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;
        let mut tracker = ProverTrackerRef::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new_from_pcs_params(pcs_param);

        let rand_mle_1 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_3 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly1 = tracker.track_and_commit_poly(rand_mle_1.clone())?;
        let poly2 = tracker.track_and_commit_poly(rand_mle_2.clone())?;
        let poly3 = tracker.track_and_commit_poly(rand_mle_3.clone())?;

        let p1_plus_p2 = poly1.add_poly(&poly2);
        let p1_plus_p2_plus_p3 = p1_plus_p2.add_poly(&poly3);
        let p3_plus_p1_plus_p2 = poly3.add_poly(&p1_plus_p2);

        // assert addition list is constructed correctly
        let p1_plus_p2_plus_p3_repr = tracker.get_virt_poly(p1_plus_p2_plus_p3.id);
        assert_eq!(p1_plus_p2_plus_p3_repr.len(), 3);
        assert_eq!(p1_plus_p2_plus_p3_repr[0].0, Fr::one());
        assert_eq!(p1_plus_p2_plus_p3_repr[0].1, vec![poly1.id]);
        assert_eq!(p1_plus_p2_plus_p3_repr[1].0, Fr::one());
        assert_eq!(p1_plus_p2_plus_p3_repr[1].1, vec![poly2.id]);
        assert_eq!(p1_plus_p2_plus_p3_repr[2].0, Fr::one());
        assert_eq!(p1_plus_p2_plus_p3_repr[2].1, vec![poly3.id]);

        let p3_plus_p1_plus_p2_repr = tracker.get_virt_poly(p3_plus_p1_plus_p2.id);
        assert_eq!(p3_plus_p1_plus_p2_repr.len(), 3);
        assert_eq!(p3_plus_p1_plus_p2_repr[0].0, Fr::one());
        assert_eq!(p3_plus_p1_plus_p2_repr[0].1, vec![poly3.id]);
        assert_eq!(p3_plus_p1_plus_p2_repr[1].0, Fr::one());
        assert_eq!(p3_plus_p1_plus_p2_repr[1].1, vec![poly1.id]);
        assert_eq!(p3_plus_p1_plus_p2_repr[2].0, Fr::one());
        assert_eq!(p3_plus_p1_plus_p2_repr[2].1, vec![poly2.id]);

        // assert evaluations at a random point are equal
        let test_eval_pt: Vec<Fr> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();
        let p1_plus_p2_plus_p3_eval = p1_plus_p2_plus_p3.evaluate(&test_eval_pt).unwrap();
        let p3_plus_p1_plus_p2_eval = p3_plus_p1_plus_p2.evaluate(&test_eval_pt).unwrap();
        assert_eq!(p1_plus_p2_plus_p3_eval, p3_plus_p1_plus_p2_eval);

        Ok(())
    }

    #[test]
    fn test_virtual_polynomial_additions() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 4;
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;
        let mut tracker = ProverTrackerRef::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new_from_pcs_params(pcs_param);
        
        let rand_mle_1 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_3 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_4 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_5 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_6 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_7 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly1 = tracker.track_and_commit_poly(rand_mle_1.clone())?;
        let poly2 = tracker.track_and_commit_poly(rand_mle_2.clone())?;
        let poly3 = tracker.track_and_commit_poly(rand_mle_3.clone())?;
        let poly4 = tracker.track_and_commit_poly(rand_mle_4.clone())?;
        let poly5 = tracker.track_and_commit_poly(rand_mle_5.clone())?;
        let poly6 = tracker.track_and_commit_poly(rand_mle_6.clone())?;
        let poly7 = tracker.track_and_commit_poly(rand_mle_7.clone())?;

        let mut addend1 = poly1.add_poly(&poly2);
        addend1 = addend1.mul_poly(&poly3);
        addend1 = addend1.mul_poly(&poly4);

        let mut addend2 = poly5.mul_poly(&poly6);
        addend2 = addend2.add_poly(&poly7);
        
        let sum = addend1.add_poly(&addend2);

        let test_eval_pt: Vec<Fr> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();
        let addend1_expected_eval = (rand_mle_1.evaluate(&test_eval_pt).unwrap() + 
                                    rand_mle_2.evaluate(&test_eval_pt).unwrap()) * 
                                    rand_mle_3.evaluate(&test_eval_pt).unwrap() * 
                                    rand_mle_4.evaluate(&test_eval_pt).unwrap();
        let addend2_expected_eval = (rand_mle_5.evaluate(&test_eval_pt).unwrap() * 
                                    rand_mle_6.evaluate(&test_eval_pt).unwrap()) + 
                                    rand_mle_7.evaluate(&test_eval_pt).unwrap();
        let sum_expected_eval = addend1_expected_eval + addend2_expected_eval;

        let sum_eval = sum.evaluate(test_eval_pt.as_slice()).unwrap();
        assert_eq!(sum_expected_eval, sum_eval);

        Ok(())
    }

    #[test]
    fn test_poly_sub() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 4;
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;
        let mut tracker = ProverTrackerRef::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new_from_pcs_params(pcs_param);

        let rand_mle_1 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_3 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_4 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let poly1 = tracker.track_and_commit_poly(rand_mle_1.clone())?;
        let poly2 = tracker.track_and_commit_poly(rand_mle_2.clone())?;
        let poly3 = tracker.track_and_commit_poly(rand_mle_3.clone())?;
        let poly4 = tracker.track_and_commit_poly(rand_mle_4.clone())?;
        let test_eval_pt: Vec<Fr> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();
        let poly1_eval: Fr = rand_mle_1.evaluate(test_eval_pt.as_slice()).unwrap();
        let poly2_eval: Fr = rand_mle_2.evaluate(test_eval_pt.as_slice()).unwrap();
        let poly3_eval: Fr = rand_mle_3.evaluate(test_eval_pt.as_slice()).unwrap();
        let poly4_eval: Fr = rand_mle_4.evaluate(test_eval_pt.as_slice()).unwrap();


        // test two mat polys
        let poly1_minus_poly2 = poly1.sub_poly(&poly2);
        let poly1_minus_poly2_eval: Fr = poly1_minus_poly2.evaluate(test_eval_pt.as_slice()).unwrap();
        assert_eq!(poly1_minus_poly2_eval, poly1_eval - poly2_eval);

        // test mat - virt
        let mat_minus_virt = poly3.sub_poly(&poly1_minus_poly2);
        let mat_minus_virt_eval: Fr = mat_minus_virt.evaluate(test_eval_pt.as_slice()).unwrap();
        assert_eq!(mat_minus_virt_eval, poly3_eval - (poly1_eval - poly2_eval));

        // test virt - mat
        let virt_minus_mat = poly1_minus_poly2.sub_poly(&poly3);
        let virt_minus_mat_eval: Fr = virt_minus_mat.evaluate(test_eval_pt.as_slice()).unwrap();
        assert_eq!(virt_minus_mat_eval, (poly1_eval - poly2_eval) - poly3_eval);

        // test mat - mat
        let poly3_minus_poly4 = poly3.sub_poly(&poly4);
        let mat_minus_mat = poly1_minus_poly2.sub_poly(&poly3_minus_poly4);
        let mat_minus_mat_eval: Fr = mat_minus_mat.evaluate(test_eval_pt.as_slice()).unwrap();
        assert_eq!(mat_minus_mat_eval, (poly1_eval - poly2_eval)- (poly3_eval - poly4_eval));

        Ok(())
    }

    #[test]
    fn test_tracked_poly_same_tracker() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 4;
         let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;
        let mut tracker1 = ProverTrackerRef::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new_from_pcs_params(pcs_param.clone());
        let mut tracker2 = ProverTrackerRef::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new_from_pcs_params(pcs_param);
        
        let rand_mle = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly_1a = tracker1.track_and_commit_poly(rand_mle.clone())?;
        let poly_2a = tracker2.track_and_commit_poly(rand_mle.clone())?;
        let poly_1b = tracker1.track_and_commit_poly(rand_mle.clone())?;

        assert!(!poly_1a.same_tracker(&poly_2a));
        assert!(poly_1a.same_tracker(&poly_1b));
        Ok(())
    }

    #[test]
    fn test_tracked_poly_mat_evaluations() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 4;
         let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;
        let mut tracker = ProverTrackerRef::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new_from_pcs_params(pcs_param);
        
        let rand_mle = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly = tracker.track_and_commit_poly(rand_mle.clone())?;

        // assert evaluations correctly returns evals for a mat poly
        let evals = poly.evaluations();
        assert_eq!(evals, rand_mle.evaluations);
        Ok(())
    }

    #[test]
    fn test_tracked_poly_virt_evaluations() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 4;
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;
        let mut tracker = ProverTrackerRef::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new_from_pcs_params(pcs_param);
        
        let rand_mle_1 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_3 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);

        let poly1 = tracker.track_and_commit_poly(rand_mle_1.clone())?;
        let poly2 = tracker.track_and_commit_poly(rand_mle_2.clone())?;
        let poly3 = tracker.track_and_commit_poly(rand_mle_3.clone())?;

        let virt_poly = poly1.add_poly(&poly2).mul_poly(&poly3);
        let virt_poly_evals = virt_poly.evaluations();
        let mut expected_poly_evals = (rand_mle_1 + rand_mle_2).to_evaluations();
        for i in 0..expected_poly_evals.len() {
            expected_poly_evals[i] *= rand_mle_3[i];
        }
        assert_eq!(virt_poly_evals, expected_poly_evals);
        Ok(())
    }

    #[test]
    fn test_to_arithmatic_virtual_poly() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 4;
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (pcs_param, _) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(nv))?;
        let mut tracker = ProverTrackerRef::<Bls12_381, MultilinearKzgPCS::<Bls12_381>>::new_from_pcs_params(pcs_param);
        
        let rand_mle_1 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let rand_mle_3 = DenseMultilinearExtension::<Fr>::rand(nv,  &mut rng);
        let poly1 = tracker.track_and_commit_poly(rand_mle_1.clone())?;
        let poly2 = tracker.track_and_commit_poly(rand_mle_2.clone())?;
        let poly3 = tracker.track_and_commit_poly(rand_mle_3.clone())?;


        // test sumcheck on mat poly
        let sum1: Fr = rand_mle_1.clone().evaluations.into_iter().sum();
        let arith_virt_poly = poly1.to_arithmatic_virtual_poly();
        let transcript = IOPTranscript::<Fr>::new(b"test");
        let proof = <PolyIOP<Fr> as SumCheck<Fr>>::prove(&arith_virt_poly, &mut transcript.clone()).unwrap();
        <PolyIOP<Fr> as SumCheck<Fr>>::verify(sum1, &proof, &arith_virt_poly.aux_info, &mut transcript.clone()).unwrap();
        assert!(<PolyIOP<Fr> as SumCheck<Fr>>::verify(Fr::zero(), &proof, &arith_virt_poly.aux_info, &mut transcript.clone()).is_err());

        // test sumcheck on virtual poly
        let complex_virt_poly = poly1.add_poly(&poly2).mul_poly(&poly3).mul_poly(&poly3);
        let sum: Fr = complex_virt_poly.evaluations().iter().sum();
        let arith_virt_poly = complex_virt_poly.to_arithmatic_virtual_poly();
        let proof = <PolyIOP<Fr> as SumCheck<Fr>>::prove(&arith_virt_poly, &mut transcript.clone()).unwrap();
        <PolyIOP<Fr> as SumCheck<Fr>>::verify(sum, &proof, &arith_virt_poly.aux_info, &mut transcript.clone()).unwrap();
        assert!(<PolyIOP<Fr> as SumCheck<Fr>>::verify(Fr::zero(), &proof, &arith_virt_poly.aux_info, &mut transcript.clone()).is_err());

        Ok(())
    }


    #[test]
    fn test_eval_comm() -> Result<(), PolyIOPErrors> {
        println!("starting eval comm test");
        // set up randomness
        let mut rng = test_rng();
        const NV: usize = 4;
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, NV)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(NV))?;

        // set up a mock conpiled proof
        let poly1 = DenseMultilinearExtension::<Fr>::rand(NV, &mut rng);
        let poly2 = DenseMultilinearExtension::<Fr>::rand(NV, &mut rng);
        let point = [Fr::rand(&mut rng); NV].to_vec();
        let eval1 = poly1.evaluate(&point).unwrap();
        let eval2 = poly2.evaluate(&point).unwrap();
        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        prover_tracker.track_and_commit_poly(poly1.clone())?;
        prover_tracker.track_and_commit_poly(poly2.clone())?;
        let mut proof = prover_tracker.compile_proof()?;
        proof.query_map.insert((TrackerID(0), point.clone()), eval1.clone());
        proof.query_map.insert((TrackerID(1), point.clone()), eval2.clone());

        
        // simulate interaction phase
        // [(p(x) + gamma) * phat(x)  - 1]
        println!("making virtual comms");
        let mut tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);
        let comm1 = tracker.track_mat_comm(proof.comms.get(&TrackerID(0)).unwrap().clone())?;
        let comm2 = tracker.track_mat_comm(proof.comms.get(&TrackerID(1)).unwrap().clone())?;
        let gamma = tracker.get_and_append_challenge(b"gamma")?;
        let mut res_comm = comm1.add_scalar(gamma);
        res_comm = res_comm.mul_comms(&comm2);
        let res_comm = res_comm.add_scalar(Fr::one().neg());

        // simulate decision phase
        println!("evaluating virtual comm");
        tracker.set_compiled_proof(proof);
        tracker.transfer_proof_poly_evals();
        let res_eval = res_comm.eval_virtual_comm(&point)?;
        let expected_eval = (eval1 + gamma) * eval2 - Fr::one();
        assert_eq!(expected_eval, res_eval);

        Ok(())
    }

    #[test]
    fn test_increase_nv_front() -> Result<(), PolyIOPErrors> {
        println!("starting increase_nv_front test");

        let mut rng = test_rng();
        const NV: usize = 4;
        let resized_nv: usize = 7;
        let added_nv = resized_nv - NV;
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, resized_nv)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(resized_nv))?;

        let poly = DenseMultilinearExtension::<Fr>::rand(NV, &mut rng);
        let point = [Fr::rand(&mut rng); NV].to_vec();
        let eval = poly.evaluate(&point).unwrap();
        let mut resized_point = vec![Fr::rand(&mut rng); added_nv];
        resized_point.extend(point.clone());

        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        let tracked_poly = prover_tracker.track_and_commit_poly(poly.clone())?;
        let poly2 = DenseMultilinearExtension::<Fr>::rand(NV, &mut rng);
        let _ = prover_tracker.track_and_commit_poly(poly2.clone())?; // if this isn't here Hyperplonk's PCS multi_open breaks
        let resized_poly = tracked_poly.increase_nv_front(added_nv);

        // check resized_poly evaluates the same as the original poly
        assert_eq!(resized_poly.num_vars(), resized_nv);
        assert_eq!(resized_poly.evaluate(resized_point.as_slice()).unwrap(), eval);
       
        // set up to check that an IOP passes
        let resized_sum = resized_poly.evaluations().iter().sum::<Fr>();
        prover_tracker.add_sumcheck_claim(resized_poly.id, resized_sum);
        let mut proof = prover_tracker.compile_proof()?;
        proof.query_map.insert((TrackerID(1), resized_point.clone()), eval.clone());

        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);
        verifier_tracker.set_compiled_proof(proof);
        let og_comm = verifier_tracker.transfer_prover_comm(TrackerID(0));
        let _ = verifier_tracker.transfer_prover_comm(TrackerID(1)); // to match extra poly above
        let resized_comm = og_comm.increase_nv_front(added_nv);
        verifier_tracker.add_sumcheck_claim(resized_comm.id, resized_sum);

        // check that an IOP passes
        verifier_tracker.verify_claims()?;

        // check that the ProverTracker and VerifierTracker are in the same state
        let p_tracker = prover_tracker.clone_underlying_tracker();
        let v_tracker = verifier_tracker.clone_underlying_tracker();
        assert_eq!(p_tracker.id_counter, v_tracker.id_counter);

        Ok(())
    }
    
    #[test]
    fn test_increase_nv_back() -> Result<(), PolyIOPErrors> {
        println!("starting increase_nv_front test");

        let mut rng = test_rng();
        const NV: usize = 4;
        let resized_nv: usize = 7;
        let added_nv = resized_nv - NV;
        let srs = MultilinearKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, resized_nv)?;
        let (pcs_prover_param, pcs_verifier_param) = MultilinearKzgPCS::<Bls12_381>::trim(&srs, None, Some(resized_nv))?;

        let poly = DenseMultilinearExtension::<Fr>::rand(NV, &mut rng);
        let point = [Fr::rand(&mut rng); NV].to_vec();
        let eval = poly.evaluate(&point).unwrap();
        let mut resized_point = point.clone();
        resized_point.extend(vec![Fr::rand(&mut rng); added_nv]);

        let mut prover_tracker: ProverTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = ProverTrackerRef::new_from_pcs_params(pcs_prover_param);
        let tracked_poly = prover_tracker.track_and_commit_poly(poly.clone())?;
        let poly2 = DenseMultilinearExtension::<Fr>::rand(NV, &mut rng);
        let _ = prover_tracker.track_and_commit_poly(poly2.clone())?; // if this isn't here Hyperplonk's PCS multi_open breaks
        let resized_poly = tracked_poly.increase_nv_back(added_nv);

        // check resized_poly evaluates the same as the original poly
        assert_eq!(resized_poly.num_vars(), resized_nv);
        assert_eq!(resized_poly.evaluate(resized_point.as_slice()).unwrap(), eval);
       
        // set up to check that an IOP passes
        let resized_sum = resized_poly.evaluations().iter().sum::<Fr>();
        prover_tracker.add_sumcheck_claim(resized_poly.id, resized_sum);
        let mut proof = prover_tracker.compile_proof()?;
        proof.query_map.insert((TrackerID(1), resized_point.clone()), eval.clone());

        let mut verifier_tracker: VerifierTrackerRef<Bls12_381, MultilinearKzgPCS<Bls12_381>> = VerifierTrackerRef::new_from_pcs_params(pcs_verifier_param);
        verifier_tracker.set_compiled_proof(proof);
        let og_comm = verifier_tracker.transfer_prover_comm(TrackerID(0));
        let _ = verifier_tracker.transfer_prover_comm(TrackerID(1)); // to match extra poly above
        let resized_comm = og_comm.increase_nv_back(added_nv);
        verifier_tracker.add_sumcheck_claim(resized_comm.id, resized_sum);

        // check that an IOP passes
        verifier_tracker.verify_claims()?;

        // check that the ProverTracker and VerifierTracker are in the same state
        let p_tracker = prover_tracker.clone_underlying_tracker();
        let v_tracker = verifier_tracker.clone_underlying_tracker();
        assert_eq!(p_tracker.id_counter, v_tracker.id_counter);

        Ok(())
    }
}