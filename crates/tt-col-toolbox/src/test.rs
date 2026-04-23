    use std::{
        ops::Neg,
        sync::Arc,
    };
    
    use crate::arithmetic::ark_ff::UniformRand;
    use crate::arithmetic::ark_poly::{MLE, MultilinearExtension};
    use crate::errors::PolyIOPErrors;
    use crate::piop::sum_check::SumCheck;
    use crate::prover_wrapper::ProverTrackerRef;
    use crate::tracker_structs::TrackerID;
    use crate::verifier_wrapper::Verifier;
    use crate::{arithmetic, transcript};
    use ark_test_curves::bls12_381::{Bls12_381, Fr};
    use ark_ec;
    use crate::pcs::kzg10::KZG10;
    use crate::pcs::pst13::PST13;
    use crate::pcs::PCS;
    use ark_std::{One, test_rng, Zero};
    
    
    use transcript::Tr;
    use arithmetic::ark_poly::Polynomial; 

    #[test]
    fn test_track_mat_poly() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 4;
         let mv_srs = PST13::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (mv_pcs_param, _) = PST13::<Bls12_381>::trim(&mv_srs, None, Some(nv))?;
         let uv_srs = KZG10::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (uv_pcs_param, _) = KZG10::<Bls12_381>::trim(&uv_srs, Some(nv), None)?;
        let mut tracker = ProverTrackerRef::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>, KZG10<Bls12_381>>::new_from_pcs_params(mv_pcs_param, uv_pcs_param);
        

        let rand_mle_1 = MLE::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = MLE::<Fr>::rand(nv,  &mut rng);

        let poly1 = tracker.track_and_commit_poly(rand_mle_1.clone())?;
        let poly2 = tracker.track_and_commit_poly(rand_mle_2.clone())?;
        
        // assert polys get different ids
        assert_ne!(poly1.id, poly2.id);

        // assert that we can get the polys back
        let lookup_poly1 = tracker.mat_poly(poly1.id);
        assert_eq!(lookup_poly1, Arc::new(rand_mle_1));
        Ok(())
    }

    #[test]
    fn test_add_mat_polys() -> Result<(),  PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 4;
        let mv_srs = PST13::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (mv_pcs_param, _) = PST13::<Bls12_381>::trim(&mv_srs, None, Some(nv))?;
         let uv_srs = KZG10::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (uv_pcs_param, _) = KZG10::<Bls12_381>::trim(&uv_srs, Some(nv), None)?;
        let mut tracker = ProverTrackerRef::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>, KZG10<Bls12_381>>::new_from_pcs_params(mv_pcs_param, uv_pcs_param);

        let rand_mle_1 = MLE::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = MLE::<Fr>::rand(nv,  &mut rng);

        let poly1 = tracker.track_and_commit_poly(rand_mle_1.clone())?;
        let poly2 = tracker.track_and_commit_poly(rand_mle_2.clone())?;
        let sum_poly = poly1.add_poly(&poly2);

        // assert addition list is constructed correctly
        let sum_poly_id_repr = tracker.virt_poly(sum_poly.id);
        assert_eq!(sum_poly_id_repr.len(), 2);
        assert_eq!(sum_poly_id_repr[0].0, Fr::one());
        assert_eq!(sum_poly_id_repr[0].1, vec![poly1.id]);
        assert_eq!(sum_poly_id_repr[1].0, Fr::one());
        assert_eq!(sum_poly_id_repr[1].1, vec![poly2.id]);

        // test evalutation at a random point
        let test_eval_pt: Vec<Fr> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();
        let sum_eval = sum_poly.evaluate(&test_eval_pt).unwrap();
        let poly1_eval = rand_mle_1.evaluate(&test_eval_pt);
        let poly2_eval = rand_mle_2.evaluate(&test_eval_pt);
        assert_eq!(sum_eval, poly1_eval + poly2_eval);

        Ok(())
    }

    
    #[test]
    fn test_add_mat_poly_to_virtual_poly() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 4;
        let mv_srs = PST13::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (mv_pcs_param, _) = PST13::<Bls12_381>::trim(&mv_srs, None, Some(nv))?;
         let uv_srs = KZG10::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (uv_pcs_param, _) = KZG10::<Bls12_381>::trim(&uv_srs, Some(nv), None)?;
        let mut tracker = ProverTrackerRef::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>, KZG10<Bls12_381>>::new_from_pcs_params(mv_pcs_param, uv_pcs_param);

        let rand_mle_1 = MLE::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = MLE::<Fr>::rand(nv,  &mut rng);
        let rand_mle_3 = MLE::<Fr>::rand(nv,  &mut rng);

        let poly1 = tracker.track_and_commit_poly(rand_mle_1.clone())?;
        let poly2 = tracker.track_and_commit_poly(rand_mle_2.clone())?;
        let poly3 = tracker.track_and_commit_poly(rand_mle_3.clone())?;

        let p1_plus_p2 = poly1.add_poly(&poly2);
        let p1_plus_p2_plus_p3 = p1_plus_p2.add_poly(&poly3);
        let p3_plus_p1_plus_p2 = poly3.add_poly(&p1_plus_p2);

        // assert addition list is constructed correctly
        let p1_plus_p2_plus_p3_repr = tracker.virt_poly(p1_plus_p2_plus_p3.id);
        assert_eq!(p1_plus_p2_plus_p3_repr.len(), 3);
        assert_eq!(p1_plus_p2_plus_p3_repr[0].0, Fr::one());
        assert_eq!(p1_plus_p2_plus_p3_repr[0].1, vec![poly1.id]);
        assert_eq!(p1_plus_p2_plus_p3_repr[1].0, Fr::one());
        assert_eq!(p1_plus_p2_plus_p3_repr[1].1, vec![poly2.id]);
        assert_eq!(p1_plus_p2_plus_p3_repr[2].0, Fr::one());
        assert_eq!(p1_plus_p2_plus_p3_repr[2].1, vec![poly3.id]);

        let p3_plus_p1_plus_p2_repr = tracker.virt_poly(p3_plus_p1_plus_p2.id);
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
        let mv_srs = PST13::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (mv_pcs_param, _) = PST13::<Bls12_381>::trim(&mv_srs, None, Some(nv))?;
         let uv_srs = KZG10::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (uv_pcs_param, _) = KZG10::<Bls12_381>::trim(&uv_srs, Some(nv), None)?;
        let mut tracker = ProverTrackerRef::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>, KZG10<Bls12_381>>::new_from_pcs_params(mv_pcs_param, uv_pcs_param);
        
        let rand_mle_1 = MLE::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = MLE::<Fr>::rand(nv,  &mut rng);
        let rand_mle_3 = MLE::<Fr>::rand(nv,  &mut rng);
        let rand_mle_4 = MLE::<Fr>::rand(nv,  &mut rng);
        let rand_mle_5 = MLE::<Fr>::rand(nv,  &mut rng);
        let rand_mle_6 = MLE::<Fr>::rand(nv,  &mut rng);
        let rand_mle_7 = MLE::<Fr>::rand(nv,  &mut rng);

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
        let addend1_expected_eval = (rand_mle_1.evaluate(&test_eval_pt) + 
                                    rand_mle_2.evaluate(&test_eval_pt)) * 
                                    rand_mle_3.evaluate(&test_eval_pt) * 
                                    rand_mle_4.evaluate(&test_eval_pt);
        let addend2_expected_eval = (rand_mle_5.evaluate(&test_eval_pt)* 
                                    rand_mle_6.evaluate(&test_eval_pt)) + 
                                    rand_mle_7.evaluate(&test_eval_pt);
        let sum_expected_eval = addend1_expected_eval + addend2_expected_eval;

        let sum_eval = sum.evaluate(test_eval_pt.as_slice()).unwrap();
        assert_eq!(sum_expected_eval, sum_eval);

        Ok(())
    }

    #[test]
    fn test_poly_sub() -> Result<(), PolyIOPErrors> {
        let mut rng = test_rng();
        let nv = 4;
        let mv_srs = PST13::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (mv_pcs_param, _) = PST13::<Bls12_381>::trim(&mv_srs, None, Some(nv))?;
         let uv_srs = KZG10::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (uv_pcs_param, _) = KZG10::<Bls12_381>::trim(&uv_srs, Some(nv), None)?;
        let mut tracker = ProverTrackerRef::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>, KZG10<Bls12_381>>::new_from_pcs_params(mv_pcs_param, uv_pcs_param);

        let rand_mle_1 = MLE::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = MLE::<Fr>::rand(nv,  &mut rng);
        let rand_mle_3 = MLE::<Fr>::rand(nv,  &mut rng);
        let rand_mle_4 = MLE::<Fr>::rand(nv,  &mut rng);
        let poly1 = tracker.track_and_commit_poly(rand_mle_1.clone())?;
        let poly2 = tracker.track_and_commit_poly(rand_mle_2.clone())?;
        let poly3 = tracker.track_and_commit_poly(rand_mle_3.clone())?;
        let poly4 = tracker.track_and_commit_poly(rand_mle_4.clone())?;
        let test_eval_pt: Vec<Fr> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();
        let poly1_eval: Fr = rand_mle_1.evaluate(&test_eval_pt);
        let poly2_eval: Fr = rand_mle_2.evaluate(&test_eval_pt);
        let poly3_eval: Fr = rand_mle_3.evaluate(&test_eval_pt);
        let poly4_eval: Fr = rand_mle_4.evaluate(&test_eval_pt);


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
        let mv_srs = PST13::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (mv_pcs_param, _) = PST13::<Bls12_381>::trim(&mv_srs, None, Some(nv))?;
         let uv_srs = KZG10::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (uv_pcs_param, _) = KZG10::<Bls12_381>::trim(&uv_srs, Some(nv),None )?;
        let mut tracker1 = ProverTrackerRef::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>, KZG10<Bls12_381>>::new_from_pcs_params(mv_pcs_param.clone(), uv_pcs_param.clone());
        let mut tracker2 = ProverTrackerRef::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>, KZG10<Bls12_381>>::new_from_pcs_params(mv_pcs_param, uv_pcs_param);
        
        let rand_mle = MLE::<Fr>::rand(nv,  &mut rng);

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
        let mv_srs = PST13::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (mv_pcs_param, _) = PST13::<Bls12_381>::trim(&mv_srs, None, Some(nv))?;
         let uv_srs = KZG10::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (uv_pcs_param, _) = KZG10::<Bls12_381>::trim(&uv_srs, Some(nv), None)?;
        let mut tracker = ProverTrackerRef::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>, KZG10<Bls12_381>>::new_from_pcs_params(mv_pcs_param, uv_pcs_param);
        
        let rand_mle = MLE::<Fr>::rand(nv,  &mut rng);

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
        let mv_srs = PST13::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (mv_pcs_param, _) = PST13::<Bls12_381>::trim(&mv_srs, None, Some(nv))?;
         let uv_srs = KZG10::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (uv_pcs_param, _) = KZG10::<Bls12_381>::trim(&uv_srs, Some(nv), None)?;
        let mut tracker = ProverTrackerRef::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>, KZG10<Bls12_381>>::new_from_pcs_params(mv_pcs_param, uv_pcs_param);
        
        let rand_mle_1 = MLE::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = MLE::<Fr>::rand(nv,  &mut rng);
        let rand_mle_3 = MLE::<Fr>::rand(nv,  &mut rng);

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
        let mv_srs = PST13::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (mv_pcs_param, _) = PST13::<Bls12_381>::trim(&mv_srs, None, Some(nv))?;
         let uv_srs = KZG10::<Bls12_381>::gen_srs_for_testing(&mut rng, nv)?;
        let (uv_pcs_param, _) = KZG10::<Bls12_381>::trim(&uv_srs, Some(nv), None)?;
        let mut tracker = ProverTrackerRef::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>, KZG10<Bls12_381>>::new_from_pcs_params(mv_pcs_param, uv_pcs_param);
        
        let rand_mle_1 = MLE::<Fr>::rand(nv,  &mut rng);
        let rand_mle_2 = MLE::<Fr>::rand(nv,  &mut rng);
        let rand_mle_3 = MLE::<Fr>::rand(nv,  &mut rng);
        let poly1 = tracker.track_and_commit_poly(rand_mle_1.clone())?;
        let poly2 = tracker.track_and_commit_poly(rand_mle_2.clone())?;
        let poly3 = tracker.track_and_commit_poly(rand_mle_3.clone())?;


        // test sumcheck on mat poly
        let sum1: Fr = rand_mle_1.clone().evaluations.into_iter().sum();
        let arith_virt_poly = poly1.to_arithmatic_virtual_poly();
        let transcript = Tr::<Fr>::new(b"test");
        let proof = SumCheck::<Fr>::prove(&arith_virt_poly, &mut transcript.clone()).unwrap();
        SumCheck::<Fr>::verify(sum1, &proof, &arith_virt_poly.aux_info, &mut transcript.clone()).unwrap();
        assert!(SumCheck::<Fr>::verify(Fr::zero(), &proof, &arith_virt_poly.aux_info, &mut transcript.clone()).is_err());

        // test sumcheck on virtual poly
        let complex_virt_poly = poly1.add_poly(&poly2).mul_poly(&poly3).mul_poly(&poly3);
        let sum: Fr = complex_virt_poly.evaluations().iter().sum();
        let arith_virt_poly = complex_virt_poly.to_arithmatic_virtual_poly();
        let proof = SumCheck::<Fr>::prove(&arith_virt_poly, &mut transcript.clone()).unwrap();
        SumCheck::<Fr>::verify(sum, &proof, &arith_virt_poly.aux_info, &mut transcript.clone()).unwrap();
        assert!(SumCheck::<Fr>::verify(Fr::zero(), &proof, &arith_virt_poly.aux_info, &mut transcript.clone()).is_err());

        Ok(())
    }


    #[test]
    fn test_eval_comm() -> Result<(), PolyIOPErrors> {
        println!("starting eval comm test");
        // set up randomness
        let mut rng = test_rng();
        const NV: usize = 4;
        let mv_srs = PST13::<Bls12_381>::gen_srs_for_testing(&mut rng, NV)?;
        let (mv_pcs_param,mv_pcs_verifier_param) = PST13::<Bls12_381>::trim(&mv_srs, None, Some(NV))?;
         let uv_srs = KZG10::<Bls12_381>::gen_srs_for_testing(&mut rng, NV)?;
        let (uv_pcs_param, uv_pcs_verifier_param) = KZG10::<Bls12_381>::trim(&uv_srs, Some(NV),None)?;

        // set up a mock conpiled proof
        let poly1 = MLE::<Fr>::rand(NV, &mut rng);
        let poly2 = MLE::<Fr>::rand(NV, &mut rng);
        let point = [Fr::rand(&mut rng); NV].to_vec();
        let eval1 = poly1.evaluate(&point);
        let eval2 = poly2.evaluate(&point);
        let mut prover = ProverTrackerRef::<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13::<Bls12_381>, KZG10<Bls12_381>>::new_from_pcs_params(mv_pcs_param, uv_pcs_param);
        prover.track_and_commit_poly(poly1.clone())?;
        prover.track_and_commit_poly(poly2.clone())?;
        let mut proof = prover.compile_proof()?;
        proof.mv_query_map.insert((TrackerID(0), point.clone()), eval1.clone());
        proof.mv_query_map.insert((TrackerID(1), point.clone()), eval2.clone());

        
        // simulate interaction phase
        // [(p(x) + gamma) * phat(x)  - 1]
        println!("making virtual comms");
        let mut tracker: Verifier<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13<Bls12_381>, KZG10<Bls12_381>> = Verifier::new_from_pcs_params( mv_pcs_verifier_param, uv_pcs_verifier_param);
        let comm1 = tracker.track_mat_mv_com(proof.mv_comms.get(&TrackerID(0)).unwrap().clone())?;
        let comm2 = tracker.track_mat_mv_com(proof.mv_comms.get(&TrackerID(1)).unwrap().clone())?;
        let gamma = tracker.get_and_append_challenge(b"gamma")?;
        let mut res_comm = comm1.add_scalar(gamma);
        res_comm = res_comm.mul_polys(&comm2);
        let res_comm = res_comm.add_scalar(Fr::one().neg());

        // simulate decision phase
        println!("evaluating virtual comm");
        tracker.set_proof(proof);
        tracker.transfer_proof_poly_evals();
        let res_eval = res_comm.eval_virtual_oracle(&point)?;
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
        let mv_srs = PST13::<Bls12_381>::gen_srs_for_testing(&mut rng, resized_nv)?;
        let ( mv_pcs_prover_param,  mv_pcs_verifier_param) = PST13::<Bls12_381>::trim(&mv_srs, None, Some(resized_nv))?;

        let uv_srs = KZG10::<Bls12_381>::gen_srs_for_testing(&mut rng, resized_nv)?;
        let ( uv_pcs_prover_param,  uv_pcs_verifier_param) = KZG10::<Bls12_381>::trim(&uv_srs, Some(resized_nv), None)?;

        let poly = MLE::<Fr>::rand(NV, &mut rng);
        let point = [Fr::rand(&mut rng); NV].to_vec();
        let eval = poly.evaluate(&point);
        let mut resized_point = vec![Fr::rand(&mut rng); added_nv];
        resized_point.extend(point.clone());

        let mut prover: ProverTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13<Bls12_381>, KZG10<Bls12_381>> = ProverTrackerRef::new_from_pcs_params( mv_pcs_prover_param, uv_pcs_prover_param);
        let tracked_poly = prover.track_and_commit_poly(poly.clone())?;
        let poly2 = MLE::<Fr>::rand(NV, &mut rng);
        let _ = prover.track_and_commit_poly(poly2.clone())?; // if this isn't here Hyperplonk's PCS multi_open breaks
        let resized_poly = tracked_poly.increase_nv_front(added_nv);

        // check resized_poly evaluates the same as the original poly
        assert_eq!(resized_poly.num_vars(), resized_nv);
        assert_eq!(resized_poly.evaluate(resized_point.as_slice()).unwrap(), eval);
       
        // set up to check that an IOP passes
        let resized_sum = resized_poly.evaluations().iter().sum::<Fr>();
        prover.add_mv_sumcheck_claim(resized_poly.id, resized_sum);
        let mut proof = prover.compile_proof()?;
        proof.mv_query_map.insert((TrackerID(1), resized_point.clone()), eval.clone());

        let mut verifier: Verifier<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13<Bls12_381>, KZG10<Bls12_381>> = Verifier::new_from_pcs_params( mv_pcs_verifier_param, uv_pcs_verifier_param);
        verifier.set_proof(proof);
        let og_comm = verifier.track_mv_com_by_id(TrackerID(0));
        let _ = verifier.track_mv_com_by_id(TrackerID(1)); // to match extra poly above
        let resized_comm = og_comm.increase_nv_front(added_nv);
        verifier.add_mv_sumcheck_claim(resized_comm.id, resized_sum);

        // check that an IOP passes
        verifier.verify()?;

        // check that the ProverTracker and VerifierTracker are in the same state
        let p_tracker = prover.clone_underlying_tracker();
        let verifier = verifier.clone_underlying_tracker();
        assert_eq!(p_tracker.num_tracked_polys, verifier.num_tracked_polys);

        Ok(())
    }
    
    #[test]
    fn test_increase_nv_back() -> Result<(), PolyIOPErrors> {
        println!("starting increase_nv_front test");

        let mut rng = test_rng();
        const NV: usize = 4;
        let resized_nv: usize = 7;
        let added_nv = resized_nv - NV;
        let mv_srs = PST13::<Bls12_381>::gen_srs_for_testing(&mut rng, resized_nv)?;
        let ( mv_pcs_prover_param,  mv_pcs_verifier_param) = PST13::<Bls12_381>::trim(&mv_srs, None, Some(resized_nv))?;
        let uv_srs = KZG10::<Bls12_381>::gen_srs_for_testing(&mut rng, resized_nv)?;
        let ( uv_pcs_prover_param,  uv_pcs_verifier_param) = KZG10::<Bls12_381>::trim(&uv_srs, Some(resized_nv), None)?;

        let poly = MLE::<Fr>::rand(NV, &mut rng);
        let point = [Fr::rand(&mut rng); NV].to_vec();
        let eval = poly.evaluate(&point);
        let mut resized_point = point.clone();
        resized_point.extend(vec![Fr::rand(&mut rng); added_nv]);

        let mut prover: ProverTrackerRef<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13<Bls12_381>, KZG10<Bls12_381>> = ProverTrackerRef::new_from_pcs_params( mv_pcs_prover_param, uv_pcs_prover_param);
        let tracked_poly = prover.track_and_commit_poly(poly.clone())?;
        let poly2 = MLE::<Fr>::rand(NV, &mut rng);
        let _ = prover.track_and_commit_poly(poly2.clone())?; // if this isn't here Hyperplonk's PCS multi_open breaks
        let resized_poly = tracked_poly.increase_nv_back(added_nv);

        // check resized_poly evaluates the same as the original poly
        assert_eq!(resized_poly.num_vars(), resized_nv);
        assert_eq!(resized_poly.evaluate(resized_point.as_slice()).unwrap(), eval);
       
        // set up to check that an IOP passes
        let resized_sum = resized_poly.evaluations().iter().sum::<Fr>();
        prover.add_mv_sumcheck_claim(resized_poly.id, resized_sum);
        let mut proof = prover.compile_proof()?;
        proof.mv_query_map.insert((TrackerID(1), resized_point.clone()), eval.clone());

        let mut verifier: Verifier<<ark_ec::bls12::Bls12<ark_test_curves::bls12_381::Config> as ark_ec::pairing::Pairing>::ScalarField, PST13<Bls12_381>, KZG10<Bls12_381>> = Verifier::new_from_pcs_params( mv_pcs_verifier_param, uv_pcs_verifier_param);
        verifier.set_proof(proof);
        let og_comm = verifier.track_mv_com_by_id(TrackerID(0));
        let _ = verifier.track_mv_com_by_id(TrackerID(1)); // to match extra poly above
        let resized_comm = og_comm.increase_nv_back(added_nv);
        verifier.add_mv_sumcheck_claim(resized_comm.id, resized_sum);

        // check that an IOP passes
        verifier.verify()?;

        // check that the ProverTracker and VerifierTracker are in the same state
        let p_tracker = prover.clone_underlying_tracker();
        let verifier = verifier.clone_underlying_tracker();
        assert_eq!(p_tracker.num_tracked_polys, verifier.num_tracked_polys);

        Ok(())
    }