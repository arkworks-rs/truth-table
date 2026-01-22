use super::{KeyedSumcheck, KeyedSumcheckProverInput, KeyedSumcheckVerifierInput};
use arithmetic::{col::TrackedCol, col_oracle::TrackedColOracle};
use ark_piop::{
    DefaultSnarkBackend, SnarkBackend, arithmetic::mat_poly::mle::MLE, errors::SnarkResult,
    piop::PIOP, prover::structs::polynomial::TrackedPoly, test_utils::test_prelude, to_field_vec,
    verifier::structs::oracle::TrackedOracle,
};
use ark_test_curves::bls12_381::Fr;
use std::str::FromStr;

// Test cases for multiplicity check completeness, where the active and
// multiplicative columns are None, meaning that everything is activated and the
// multiplicities are all one
#[test]
fn keyed_sumcheck_with_activator_and_mul_none_is_complete() -> SnarkResult<()> {
    multiplicity_test_helper::<DefaultSnarkBackend>(
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![None],
        vec![None],
        vec![3],
        vec![to_field_vec!([3, 7, 18, 2, 1, 20, 12, 4], Fr)],
        vec![None],
        vec![None],
    )?;
    multiplicity_test_helper::<DefaultSnarkBackend>(
        vec![2, 2],
        vec![
            to_field_vec!([4, 20, 1, 2], Fr),
            to_field_vec!([3, 7, 12, 18], Fr),
        ],
        vec![None, None],
        vec![None, None],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![None],
        vec![None],
    )?;
    multiplicity_test_helper::<DefaultSnarkBackend>(
        vec![2, 2],
        vec![
            to_field_vec!([4, 7, 1, 20], Fr),
            to_field_vec!([18, 2, 12, 3], Fr),
        ],
        vec![None, None],
        vec![None, None],
        vec![1, 1, 1, 1],
        vec![
            to_field_vec!([3, 7], Fr),
            to_field_vec!([12, 2], Fr),
            to_field_vec!([18, 20], Fr),
            to_field_vec!([1, 4], Fr),
        ],
        vec![None, None, None, None],
        vec![None, None, None, None],
    )?;

    // exit successfully
    Ok(())
}

// Test cases for multiplicity check soundness, where the active and
// multiplicative columns are None, meaning that everything is activated and the
// multiplicities are all one
#[test]
fn keyed_sumcheck_with_activator_and_mul_none_is_sound() -> SnarkResult<()> {
    multiplicity_test_soundness_helper::<DefaultSnarkBackend>(
        vec![3],
        vec![to_field_vec!([4, 1, 1, 20, 18, 2, 12, 3], Fr)],
        vec![None],
        vec![None],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![None],
        vec![None],
    )?;

    multiplicity_test_soundness_helper::<DefaultSnarkBackend>(
        vec![2, 2],
        vec![
            to_field_vec!([4, 7, 1, 20], Fr),
            to_field_vec!([1, 2, 12, 3], Fr),
        ],
        vec![None, None],
        vec![None, None],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![None],
        vec![None],
    )?;
    multiplicity_test_soundness_helper::<DefaultSnarkBackend>(
        vec![2, 2],
        vec![
            to_field_vec!([4, 7, 1, 20], Fr),
            to_field_vec!([18, 2, 12, 3], Fr),
        ],
        vec![None, None],
        vec![None, None],
        vec![1, 1, 1, 1],
        vec![
            to_field_vec!([4, 7], Fr),
            to_field_vec!([1, 20], Fr),
            to_field_vec!([18, 20], Fr),
            to_field_vec!([12, 3], Fr),
        ],
        vec![None, None, None, None],
        vec![None, None, None, None],
    )?;

    // exit successfully
    Ok(())
}

// Test cases for multiplicity check completeness, where the active
// columns are None, meaning that everything is activated
#[test]
fn keyed_sumcheck_with_activator_none_is_complete() -> SnarkResult<()> {
    multiplicity_test_helper::<DefaultSnarkBackend>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 4, 18, 2], Fr)],
        vec![None],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![None],
        vec![None],
    )?;
    multiplicity_test_helper::<DefaultSnarkBackend>(
        vec![3],
        vec![to_field_vec!([1, 7, 12, 20, 1, 4, 18, 2], Fr)],
        vec![None],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![None],
        vec![Some(to_field_vec!([1, 1, 2, 1, 1, 1, 1, 0], Fr))],
    )?;

    multiplicity_test_helper::<DefaultSnarkBackend>(
        vec![2, 2],
        vec![
            to_field_vec!([1, 7, 12, 20], Fr),
            to_field_vec!([1, 4, 18, 2], Fr),
        ],
        vec![None, None],
        vec![
            Some(to_field_vec!([10, 1, 3, 1], Fr)),
            Some(to_field_vec!([1, 1, 1, 1], Fr)),
        ],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![None],
        vec![Some(to_field_vec!([1, 1, 11, 1, 1, 1, 3, 0], Fr))],
    )?;

    multiplicity_test_helper::<DefaultSnarkBackend>(
        vec![2, 2],
        vec![
            to_field_vec!([1, 7, 12, 20], Fr),
            to_field_vec!([1, 4, 18, 2], Fr),
        ],
        vec![None, None],
        vec![
            Some(to_field_vec!([10, 1, 3, 1], Fr)),
            Some(to_field_vec!([1, 1, 1, 1], Fr)),
        ],
        vec![1, 1, 1, 1],
        vec![
            to_field_vec!([4, 7], Fr),
            to_field_vec!([1, 20], Fr),
            to_field_vec!([18, 2], Fr),
            to_field_vec!([12, 3], Fr),
        ],
        vec![None, None, None, None],
        vec![
            Some(to_field_vec!([1, 1], Fr)),
            Some(to_field_vec!([11, 1], Fr)),
            Some(to_field_vec!([1, 1], Fr)),
            Some(to_field_vec!([3, 0], Fr)),
        ],
    )?;

    multiplicity_test_helper::<DefaultSnarkBackend>(
        vec![2, 2],
        vec![
            to_field_vec!([1, 7, 12, 20], Fr),
            to_field_vec!([1, 4, 18, 2], Fr),
        ],
        vec![None, None],
        vec![
            Some(to_field_vec!([10, 1, 3, 1], Fr)),
            Some(to_field_vec!([1, 1, 1, 1], Fr)),
        ],
        vec![1, 1, 1, 1],
        vec![
            to_field_vec!([4, 7], Fr),
            to_field_vec!([1, 20], Fr),
            to_field_vec!([18, 2], Fr),
            to_field_vec!([12, 3], Fr),
        ],
        vec![None, None, None, None],
        vec![
            Some(to_field_vec!([1, 1], Fr)),
            Some(to_field_vec!([11, 1], Fr)),
            None,
            Some(to_field_vec!([3, 0], Fr)),
        ],
    )?;

    // exit successfully
    Ok(())
}

// Test cases for multiplicity check soundness, where the active
// columns are None, meaning that everything is activated
#[test]
fn keyed_sumcheck_with_activator_none_is_sound() -> SnarkResult<()> {
    multiplicity_test_soundness_helper::<DefaultSnarkBackend>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 4, 18, 2], Fr)],
        vec![None],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![3],
        vec![to_field_vec!([4, 7, 5, 20, 18, 2, 12, 3], Fr)],
        vec![None],
        vec![None],
    )?;

    multiplicity_test_soundness_helper::<DefaultSnarkBackend>(
        vec![3],
        vec![to_field_vec!([1, 7, 12, 20, 1, 4, 18, 2], Fr)],
        vec![None],
        vec![Some(to_field_vec!([1, 1, 1, 1, 10, 1, 1, 1], Fr))],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![None],
        vec![Some(to_field_vec!([1, 1, 2, 1, 1, 1, 1, 0], Fr))],
    )?;

    // exit successfully
    Ok(())
}

// Test cases for multiplicity check, where the Multiplicity
// columns are None, meaning that everything has a multiplcity of one
#[test]
fn keyed_sumcheck_with_mul_none_is_complete() -> SnarkResult<()> {
    multiplicity_test_helper::<DefaultSnarkBackend>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 4, 18, 2], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![None],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![None],
    )?;
    multiplicity_test_helper::<DefaultSnarkBackend>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 4, 18, 2], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 0], Fr))],
        vec![None],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 0, 1, 1], Fr))],
        vec![None],
    )?;

    multiplicity_test_helper::<DefaultSnarkBackend>(
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3,], Fr)],
        vec![Some(to_field_vec!([1, 0, 0, 1, 0, 0, 1, 1,], Fr))],
        vec![None],
        vec![2],
        vec![to_field_vec!([4, 20, 12, 3], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1], Fr))],
        vec![None],
    )?;

    multiplicity_test_helper::<DefaultSnarkBackend>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 4, 18, 2], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 0], Fr))],
        vec![None],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 0, 1, 1], Fr))],
        vec![None],
    )?;

    multiplicity_test_helper::<DefaultSnarkBackend>(
        vec![2, 2],
        vec![
            to_field_vec!([3, 7, 12, 20], Fr),
            to_field_vec!([1, 4, 18, 2], Fr),
        ],
        vec![
            Some(to_field_vec!([1, 1, 1, 1], Fr)),
            Some(to_field_vec!([1, 1, 1, 0], Fr)),
        ],
        vec![None, None],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 0, 1, 1], Fr))],
        vec![None],
    )?;
    // exit successfully
    Ok(())
}

// Test cases for multiplicity check soundness, where the Multiplicity
// columns are None, meaning that everything has a multiplcity of one
#[test]
fn keyed_sumcheck_with_mul_none_is_sound() -> SnarkResult<()> {
    multiplicity_test_soundness_helper::<DefaultSnarkBackend>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 4, 18, 2], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 0, 1], Fr))],
        vec![None],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 0, 1, 1], Fr))],
        vec![None],
    )?;
    // exit successfully
    Ok(())
}

// Test cases for multiplicity check,in the general form where both the
// activator and multiplicities are non-None
#[test]
fn keyed_sumcheck_is_complete() -> SnarkResult<()> {
    multiplicity_test_helper::<DefaultSnarkBackend>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 4, 18, 2], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr))],
    )?;

    multiplicity_test_helper::<DefaultSnarkBackend>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 4, 18, 2], Fr)],
        vec![Some(to_field_vec!([0, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![Some(to_field_vec!([1100, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 0], Fr))],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 12412], Fr))],
    )?;

    multiplicity_test_helper::<DefaultSnarkBackend>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 4, 18, 2], Fr)],
        vec![Some(to_field_vec!([0, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![Some(to_field_vec!([1100, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 0], Fr))],
    )?;

    multiplicity_test_helper::<DefaultSnarkBackend>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 3, 1, 2], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 0, 1, 1, 1, 0], Fr))],
        vec![Some(to_field_vec!([10, 11, 0, 13, 14, 15, 16, 17], Fr))],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 3, 3], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 0, 1, 1, 1], Fr))],
        vec![Some(to_field_vec!([0, 11, 30, 0, 1, 0, 3, 22], Fr))],
    )?;
    multiplicity_test_helper::<DefaultSnarkBackend>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 3, 1, 2], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 0, 1, 1, 1, 0], Fr))],
        vec![Some(to_field_vec!([10, 11, 0, 13, 14, 15, 16, 17], Fr))],
        vec![3, 3],
        vec![
            to_field_vec!([4, 7, 1, 20, 18, 2, 3, 3], Fr),
            to_field_vec!([4, 7, 1, 20, 18, 3, 3, 3], Fr),
        ],
        vec![
            Some(to_field_vec!([1, 1, 1, 1, 0, 1, 1, 1], Fr)),
            Some(to_field_vec!([0, 0, 0, 0, 0, 1, 0, 1], Fr)),
        ],
        vec![
            Some(to_field_vec!([0, 11, 30, 0, 1, 0, 3, 18], Fr)),
            Some(to_field_vec!([0, 0, 0, 0, 0, 1, 0, 3], Fr)),
        ],
    )?;
    // exit successfully
    Ok(())
}

// Test cases for multiplicity check,in the general form where both the
// activator and multiplicities are non-None
#[test]
fn keyed_sumcheck_is_sound() -> SnarkResult<()> {
    multiplicity_test_soundness_helper::<DefaultSnarkBackend>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 3, 1, 2], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 0, 1, 1, 1, 0], Fr))],
        vec![Some(to_field_vec!([10, 11, 0, 13, 14, 15, 16, 17], Fr))],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 3, 3], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 0, 1, 1, 1], Fr))],
        vec![Some(to_field_vec!([0, 11, 30, 0, 1, 0, 3, 28], Fr))],
    )?;

    // exit successfully
    Ok(())
}

#[test]
fn special_test() -> SnarkResult<()> {
    multiplicity_test_helper::<DefaultSnarkBackend>(
        vec![3],
        vec![vec![
            Fr::from_str(
                "45584234805114094044899314500923099258792321069689244803988588572072325616536",
            )
            .unwrap(),
            Fr::from_str(
                "32048712687851757665117014551432256299130172996866620258981046939777681949812",
            )
            .unwrap(),
            Fr::from_str(
                "45584234805114094044899314500923099258792321069689244803988588572072325616536",
            )
            .unwrap(),
            Fr::from_str(
                "32048712687851757665117014551432256299130172996866620258981046939777681949812",
            )
            .unwrap(),
            Fr::from_str(
                "17283835039591520621336439211961930603298780952470092181903976316483174253886",
            )
            .unwrap(),
            Fr::from_str(
                "3748312922329184241554139262471087643636632879647467636896434684188530587162",
            )
            .unwrap(),
            Fr::from_str(
                "17283835039591520621336439211961930603298780952470092181903976316483174253886",
            )
            .unwrap(),
            Fr::from_str(
                "3748312922329184241554139262471087643636632879647467636896434684188530587162",
            )
            .unwrap(),
        ]],
        vec![None],
        vec![None],
        vec![2],
        vec![vec![
            Fr::from_str(
                "45584234805114094044899314500923099258792321069689244803988588572072325616536",
            )
            .unwrap(),
            Fr::from_str(
                "32048712687851757665117014551432256299130172996866620258981046939777681949812",
            )
            .unwrap(),
            Fr::from_str(
                "17283835039591520621336439211961930603298780952470092181903976316483174253886",
            )
            .unwrap(),
            Fr::from_str(
                "3748312922329184241554139262471087643636632879647467636896434684188530587162",
            )
            .unwrap(),
        ]],
        vec![None],
        vec![Some(to_field_vec!([2, 2, 2, 2], Fr))],
    )?;

    // exit successfully
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn multiplicity_test_soundness_helper<B: SnarkBackend>(
    f_nvs: Vec<usize>,
    f_vals: Vec<Vec<B::F>>,
    f_activator_vals: Vec<Option<Vec<B::F>>>,
    f_mul_vals: Vec<Option<Vec<B::F>>>,
    g_nvs: Vec<usize>,
    g_vals: Vec<Vec<B::F>>,
    g_activator_vals: Vec<Option<Vec<B::F>>>,
    g_mul_vals: Vec<Option<Vec<B::F>>>,
) -> SnarkResult<()> {
    let err = multiplicity_test_helper::<B>(
        f_nvs,
        f_vals,
        f_activator_vals,
        f_mul_vals,
        g_nvs,
        g_vals,
        g_activator_vals,
        g_mul_vals,
    )
    .unwrap_err();

    #[cfg(feature = "honest-prover")]
    {
        assert!(matches!(
            err,
            ark_piop::errors::SnarkError::ProverError(
                ark_piop::prover::errors::ProverError::HonestProverError(
                    ark_piop::prover::errors::HonestProverError::FalseClaim
                )
            )
        ));
    }

    #[cfg(not(feature = "honest-prover"))]
    {
        assert!(matches!(
            err,
            ark_piop::errors::SnarkError::VerifierError(
                ark_piop::verifier::errors::VerifierError::VerifierCheckFailed(_)
            )
        ));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn multiplicity_test_helper<B: SnarkBackend>(
    f_nvs: Vec<usize>,
    f_vals: Vec<Vec<B::F>>,
    f_activator_vals: Vec<Option<Vec<B::F>>>,
    f_mul_vals: Vec<Option<Vec<B::F>>>,
    g_nvs: Vec<usize>,
    g_vals: Vec<Vec<B::F>>,
    g_activator_vals: Vec<Option<Vec<B::F>>>,
    g_mul_vals: Vec<Option<Vec<B::F>>>,
) -> SnarkResult<()> {
    assert_eq!(f_nvs.len(), f_vals.len());
    assert_eq!(f_nvs.len(), f_activator_vals.len());
    assert_eq!(f_nvs.len(), f_mul_vals.len());
    assert_eq!(g_nvs.len(), g_vals.len());
    assert_eq!(g_nvs.len(), g_activator_vals.len());
    assert_eq!(g_nvs.len(), g_mul_vals.len());

    let (mut prover, mut verifier) = test_prelude::<B>()?;

    let f_mles: Vec<MLE<B::F>> = f_vals
        .iter()
        .zip(f_nvs.iter())
        .map(|(vals, nv)| MLE::from_evaluations_vec(*nv, vals.to_vec()))
        .collect::<Vec<_>>();
    let f_activator_mles: Vec<Option<MLE<B::F>>> = f_activator_vals
        .iter()
        .zip(f_nvs.iter())
        .map(|(vals, nv)| {
            vals.as_ref()
                .map(|vals| MLE::from_evaluations_vec(*nv, vals.to_vec()))
        })
        .collect::<Vec<_>>();
    let f_mul_mles: Vec<Option<MLE<B::F>>> = f_mul_vals
        .iter()
        .zip(f_nvs.iter())
        .map(|(vals, nv)| {
            vals.as_ref()
                .map(|vals| MLE::from_evaluations_vec(*nv, vals.to_vec()))
        })
        .collect::<Vec<_>>();
    /////////////////////////////////////////////////////////////////
    let g_mles = g_vals
        .iter()
        .zip(g_nvs.iter())
        .map(|(vals, nv)| MLE::from_evaluations_vec(*nv, vals.clone()))
        .collect::<Vec<_>>();
    let g_activator_mles: Vec<Option<MLE<B::F>>> = g_activator_vals
        .iter()
        .zip(g_nvs.iter())
        .map(|(vals, nv)| {
            vals.as_ref()
                .map(|vals| MLE::from_evaluations_vec(*nv, vals.to_vec()))
        })
        .collect::<Vec<_>>();
    let g_mul_mles: Vec<Option<MLE<B::F>>> = g_mul_vals
        .iter()
        .zip(g_nvs.iter())
        .map(|(vals, nv)| {
            vals.as_ref()
                .map(|vals| MLE::from_evaluations_vec(*nv, vals.to_vec()))
        })
        .collect::<Vec<_>>();
    //////////////////////////////////////////////////////////////////////
    let f_tr = f_mles
        .iter()
        .map(|mle| prover.track_and_commit_mat_mv_poly(mle).unwrap())
        .collect::<Vec<_>>();
    let f_activator_tr: Vec<Option<TrackedPoly<B>>> = f_activator_mles
        .iter()
        .map(|mle| {
            mle.as_ref()
                .map(|mle| prover.track_and_commit_mat_mv_poly(mle).unwrap())
        })
        .collect::<Vec<_>>();
    let f_mul_tr: Vec<Option<TrackedPoly<B>>> = f_mul_mles
        .iter()
        .map(|mle| {
            mle.as_ref()
                .map(|mle| prover.track_and_commit_mat_mv_poly(mle).unwrap())
        })
        .collect::<Vec<_>>();
    let g_tr = g_mles
        .iter()
        .map(|mle| prover.track_and_commit_mat_mv_poly(mle).unwrap())
        .collect::<Vec<_>>();
    let g_activator_tr: Vec<Option<TrackedPoly<B>>> = g_activator_mles
        .iter()
        .map(|mle| {
            mle.as_ref()
                .map(|mle| prover.track_and_commit_mat_mv_poly(mle).unwrap())
        })
        .collect::<Vec<_>>();
    let g_mul_tr: Vec<Option<TrackedPoly<B>>> = g_mul_mles
        .iter()
        .map(|mle| {
            mle.as_ref()
                .map(|mle| prover.track_and_commit_mat_mv_poly(mle).unwrap())
        })
        .collect::<Vec<_>>();
    /////////////////////////////////////////////////////////////////
    let f_cols = f_tr
        .iter()
        .zip(f_activator_tr.iter())
        .map(|(tr, activator)| TrackedCol::new(tr.clone(), activator.clone(), None))
        .collect::<Vec<_>>();
    let g_cols = g_tr
        .iter()
        .zip(g_activator_tr.iter())
        .map(|(tr, activator)| TrackedCol::new(tr.clone(), activator.clone(), None))
        .collect::<Vec<_>>();
    let keyed_sumcheck_prover_input = KeyedSumcheckProverInput {
        fxs: f_cols,
        gxs: g_cols,
        mfxs: f_mul_tr.clone(),
        mgxs: g_mul_tr.clone(),
    };
    KeyedSumcheck::<B>::prove(&mut prover, keyed_sumcheck_prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);
    //////////////////////////////////////////////////////////////////////
    let f_tr_comms = f_tr
        .iter()
        .map(|tr| verifier.track_mv_com_by_id(tr.id()).unwrap())
        .collect::<Vec<_>>();
    let f_activator_comms: Vec<Option<TrackedOracle<B>>> = f_activator_tr
        .iter()
        .map(|tr| {
            tr.as_ref()
                .map(|tr| verifier.track_mv_com_by_id(tr.id()).unwrap())
        })
        .collect::<Vec<_>>();
    let f_mul_tr_comms = f_mul_tr
        .iter()
        .map(|tr| {
            tr.as_ref()
                .map(|tr| verifier.track_mv_com_by_id(tr.id()).unwrap())
        })
        .collect::<Vec<_>>();
    //////////////////////////////////////////////////////////////////////
    let g_tr_comms = g_tr
        .iter()
        .map(|tr| verifier.track_mv_com_by_id(tr.id()).unwrap())
        .collect::<Vec<_>>();
    let g_activator_comms: Vec<Option<TrackedOracle<B>>> = g_activator_tr
        .iter()
        .map(|tr| {
            tr.as_ref()
                .map(|tr| verifier.track_mv_com_by_id(tr.id()).unwrap())
        })
        .collect::<Vec<_>>();
    let g_mul_tr_comms = g_mul_tr
        .iter()
        .map(|tr| {
            tr.as_ref()
                .map(|tr| verifier.track_mv_com_by_id(tr.id()).unwrap())
        })
        .collect::<Vec<_>>();
    //////////////////////////////////////////////////////////////////////
    let f_tracked_col_oracles = f_tr_comms
        .iter()
        .zip(f_activator_comms.iter())
        .map(|(tr, activator)| TrackedColOracle::new(tr.clone(), activator.clone(), None))
        .collect::<Vec<_>>();
    let g_tracked_col_oracles = g_tr_comms
        .iter()
        .zip(g_activator_comms.iter())
        .map(|(tr, activator)| TrackedColOracle::new(tr.clone(), activator.clone(), None))
        .collect::<Vec<_>>();

    let keyed_sumcheck_verifier_input = KeyedSumcheckVerifierInput {
        fxs: f_tracked_col_oracles,
        gxs: g_tracked_col_oracles,
        mfxs: f_mul_tr_comms.clone(),
        mgxs: g_mul_tr_comms.clone(),
    };

    KeyedSumcheck::<B>::verify(&mut verifier, keyed_sumcheck_verifier_input)?;
    verifier.verify()?;
    Ok(())
}
