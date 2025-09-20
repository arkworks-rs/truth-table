use super::{MultiplicityCheck, MultiplicityCheckProverInput, MultiplicityCheckVerifierInput};
use arithmetic::col::{ArithCol, ColCom};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::{PCS, kzg10::KZG10, pst13::PST13},
    piop::PIOP,
    prover::structs::polynomial::TrackedPoly,
    test_utils::test_prelude,
    to_field_vec,
    verifier::structs::oracle::TrackedOracle,
};
use ark_test_curves::bls12_381::{Bls12_381, Fr};
use std::str::FromStr;

// Test cases for multiplicity check completeness, where the active and
// multiplicative columns are None, meaning that everything is activated and the
// multiplicities are all one
#[test]
fn multiplicity_check_with_actv_and_mul_none_is_complete() -> SnarkResult<()> {
    multiplicity_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![None],
        vec![None],
        vec![3],
        vec![to_field_vec!([3, 7, 18, 2, 1, 20, 12, 4], Fr)],
        vec![None],
        vec![None],
    )?;
    multiplicity_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
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
    multiplicity_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
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
fn multiplicity_check_with_actv_and_mul_none_is_sound() -> SnarkResult<()> {
    multiplicity_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![3],
        vec![to_field_vec!([4, 1, 1, 20, 18, 2, 12, 3], Fr)],
        vec![None],
        vec![None],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![None],
        vec![None],
    )?;

    multiplicity_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
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
    multiplicity_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
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
fn multiplicity_check_with_actv_none_is_complete() -> SnarkResult<()> {
    multiplicity_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 4, 18, 2], Fr)],
        vec![None],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![None],
        vec![None],
    )?;
    multiplicity_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![3],
        vec![to_field_vec!([1, 7, 12, 20, 1, 4, 18, 2], Fr)],
        vec![None],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![None],
        vec![Some(to_field_vec!([1, 1, 2, 1, 1, 1, 1, 0], Fr))],
    )?;

    multiplicity_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
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

    multiplicity_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
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

    multiplicity_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
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
fn multiplicity_check_with_actv_none_is_sound() -> SnarkResult<()> {
    multiplicity_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 4, 18, 2], Fr)],
        vec![None],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![3],
        vec![to_field_vec!([4, 7, 5, 20, 18, 2, 12, 3], Fr)],
        vec![None],
        vec![None],
    )?;

    multiplicity_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
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
fn multiplicity_check_with_mul_none_is_complete() -> SnarkResult<()> {
    multiplicity_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 4, 18, 2], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![None],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![None],
    )?;
    multiplicity_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 4, 18, 2], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 0], Fr))],
        vec![None],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 0, 1, 1], Fr))],
        vec![None],
    )?;

    multiplicity_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3,], Fr)],
        vec![Some(to_field_vec!([1, 0, 0, 1, 0, 0, 1, 1,], Fr))],
        vec![None],
        vec![2],
        vec![to_field_vec!([4, 20, 12, 3], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1], Fr))],
        vec![None],
    )?;

    multiplicity_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 4, 18, 2], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 0], Fr))],
        vec![None],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 0, 1, 1], Fr))],
        vec![None],
    )?;

    multiplicity_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
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
fn multiplicity_check_with_mul_none_is_sound() -> SnarkResult<()> {
    multiplicity_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
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
fn multiplicity_check_is_complete() -> SnarkResult<()> {
    multiplicity_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 4, 18, 2], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr))],
    )?;

    multiplicity_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 4, 18, 2], Fr)],
        vec![Some(to_field_vec!([0, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![Some(to_field_vec!([1100, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 0], Fr))],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 12412], Fr))],
    )?;

    multiplicity_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 4, 18, 2], Fr)],
        vec![Some(to_field_vec!([0, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![Some(to_field_vec!([1100, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 12, 3], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 1], Fr))],
        vec![Some(to_field_vec!([1, 1, 1, 1, 1, 1, 1, 0], Fr))],
    )?;

    multiplicity_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
        vec![3],
        vec![to_field_vec!([3, 7, 12, 20, 1, 3, 1, 2], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 0, 1, 1, 1, 0], Fr))],
        vec![Some(to_field_vec!([10, 11, 0, 13, 14, 15, 16, 17], Fr))],
        vec![3],
        vec![to_field_vec!([4, 7, 1, 20, 18, 2, 3, 3], Fr)],
        vec![Some(to_field_vec!([1, 1, 1, 1, 0, 1, 1, 1], Fr))],
        vec![Some(to_field_vec!([0, 11, 30, 0, 1, 0, 3, 22], Fr))],
    )?;
    multiplicity_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
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
fn multiplicity_check_is_sound() -> SnarkResult<()> {
    multiplicity_test_soundness_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
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
    multiplicity_test_helper::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>>(
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
fn multiplicity_test_soundness_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    f_nvs: Vec<usize>,
    f_vals: Vec<Vec<Fr>>,
    f_actv_vals: Vec<Option<Vec<Fr>>>,
    f_mul_vals: Vec<Option<Vec<Fr>>>,
    g_nvs: Vec<usize>,
    g_vals: Vec<Vec<Fr>>,
    g_actv_vals: Vec<Option<Vec<Fr>>>,
    g_mul_vals: Vec<Option<Vec<Fr>>>,
) -> SnarkResult<()> {
    let err = multiplicity_test_helper::<Fr, MvPCS, UvPCS>(
        f_nvs,
        f_vals,
        f_actv_vals,
        f_mul_vals,
        g_nvs,
        g_vals,
        g_actv_vals,
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
fn multiplicity_test_helper<
    Fr: PrimeField,
    MvPCS: PCS<Fr, Poly = MLE<Fr>>,
    UvPCS: PCS<Fr, Poly = LDE<Fr>>,
>(
    f_nvs: Vec<usize>,
    f_vals: Vec<Vec<Fr>>,
    f_actv_vals: Vec<Option<Vec<Fr>>>,
    f_mul_vals: Vec<Option<Vec<Fr>>>,
    g_nvs: Vec<usize>,
    g_vals: Vec<Vec<Fr>>,
    g_actv_vals: Vec<Option<Vec<Fr>>>,
    g_mul_vals: Vec<Option<Vec<Fr>>>,
) -> SnarkResult<()> {
    assert_eq!(f_nvs.len(), f_vals.len());
    assert_eq!(f_nvs.len(), f_actv_vals.len());
    assert_eq!(f_nvs.len(), f_mul_vals.len());
    assert_eq!(g_nvs.len(), g_vals.len());
    assert_eq!(g_nvs.len(), g_actv_vals.len());
    assert_eq!(g_nvs.len(), g_mul_vals.len());

    let (mut prover, mut verifier) = test_prelude::<Fr, MvPCS, UvPCS>()?;

    let f_mles: Vec<MLE<Fr>> = f_vals
        .iter()
        .zip(f_nvs.iter())
        .map(|(vals, nv)| MLE::from_evaluations_vec(*nv, vals.to_vec()))
        .collect::<Vec<_>>();
    let f_actv_mles: Vec<Option<MLE<Fr>>> = f_actv_vals
        .iter()
        .zip(f_nvs.iter())
        .map(|(vals, nv)| {
            vals.as_ref()
                .map(|vals| MLE::from_evaluations_vec(*nv, vals.to_vec()))
        })
        .collect::<Vec<_>>();
    let f_mul_mles: Vec<Option<MLE<Fr>>> = f_mul_vals
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
    let g_actv_mles: Vec<Option<MLE<Fr>>> = g_actv_vals
        .iter()
        .zip(g_nvs.iter())
        .map(|(vals, nv)| {
            vals.as_ref()
                .map(|vals| MLE::from_evaluations_vec(*nv, vals.to_vec()))
        })
        .collect::<Vec<_>>();
    let g_mul_mles: Vec<Option<MLE<Fr>>> = g_mul_vals
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
    let f_actv_tr: Vec<Option<TrackedPoly<Fr, MvPCS, UvPCS>>> = f_actv_mles
        .iter()
        .map(|mle| {
            mle.as_ref()
                .map(|mle| prover.track_and_commit_mat_mv_poly(mle).unwrap())
        })
        .collect::<Vec<_>>();
    let f_mul_tr: Vec<Option<TrackedPoly<Fr, MvPCS, UvPCS>>> = f_mul_mles
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
    let g_actv_tr: Vec<Option<TrackedPoly<Fr, MvPCS, UvPCS>>> = g_actv_mles
        .iter()
        .map(|mle| {
            mle.as_ref()
                .map(|mle| prover.track_and_commit_mat_mv_poly(mle).unwrap())
        })
        .collect::<Vec<_>>();
    let g_mul_tr: Vec<Option<TrackedPoly<Fr, MvPCS, UvPCS>>> = g_mul_mles
        .iter()
        .map(|mle| {
            mle.as_ref()
                .map(|mle| prover.track_and_commit_mat_mv_poly(mle).unwrap())
        })
        .collect::<Vec<_>>();
    /////////////////////////////////////////////////////////////////
    let f_cols = f_tr
        .iter()
        .zip(f_actv_tr.iter())
        .map(|(tr, actv)| ArithCol::new(None, tr.clone(), actv.clone()))
        .collect::<Vec<_>>();
    let g_cols = g_tr
        .iter()
        .zip(g_actv_tr.iter())
        .map(|(tr, actv)| ArithCol::new(None, tr.clone(), actv.clone()))
        .collect::<Vec<_>>();
    let multiplicity_check_prover_input = MultiplicityCheckProverInput {
        fxs: f_cols,
        gxs: g_cols,
        mfxs: f_mul_tr.clone(),
        mgxs: g_mul_tr.clone(),
    };
    MultiplicityCheck::<Fr, MvPCS, UvPCS>::prove(&mut prover, multiplicity_check_prover_input)?;
    let proof = prover.build_proof()?;
    verifier.set_proof(proof);
    //////////////////////////////////////////////////////////////////////
    let f_tr_comms = f_tr
        .iter()
        .map(|tr| verifier.track_mv_com_by_id(tr.id()).unwrap())
        .collect::<Vec<_>>();
    let f_actv_comms: Vec<Option<TrackedOracle<Fr, MvPCS, UvPCS>>> = f_actv_tr
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
    let g_actv_comms: Vec<Option<TrackedOracle<Fr, MvPCS, UvPCS>>> = g_actv_tr
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
    let f_col_coms = f_tr_comms
        .iter()
        .zip(f_actv_comms.iter())
        .zip(f_nvs.iter())
        .map(|((tr, actv), nv)| ColCom::new(None, tr.clone(), actv.clone(), *nv))
        .collect::<Vec<_>>();
    let g_col_coms = g_tr_comms
        .iter()
        .zip(g_actv_comms.iter())
        .zip(g_nvs.iter())
        .map(|((tr, actv), nv)| ColCom::new(None, tr.clone(), actv.clone(), *nv))
        .collect::<Vec<_>>();

    let multiplicity_check_verifier_input = MultiplicityCheckVerifierInput {
        fxs: f_col_coms,
        gxs: g_col_coms,
        mfxs: f_mul_tr_comms.clone(),
        mgxs: g_mul_tr_comms.clone(),
    };

    MultiplicityCheck::<Fr, MvPCS, UvPCS>::verify(
        &mut verifier,
        multiplicity_check_verifier_input,
    )?;
    verifier.verify()?;
    Ok(())
}
