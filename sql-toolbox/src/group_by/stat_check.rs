////////////// Imports //////////////

use super::{
    structs::{AggregationType, GroupByConfig},
    utils::{fold_coms, fold_polys},
};

use arithmetic::{
    col::{ArithCol, ColCom},
    table::{ArithTable, TableComm},
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::{SnarkError, SnarkResult},
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{Prover, structs::polynomial::TrackedPoly},
    timed,
    verifier::{Verifier, structs::oracle::TrackedOracle},
};
use ark_std::{cfg_iter, cfg_iter_mut, end_timer, start_timer};
use col_toolbox::{
    inclusion_check::{InclusionCheckPIOP, InclusionCheckProverInput, InclusionCheckVerifierInput},
    multiplicity_check::{
        MultiplicityCheck, MultiplicityCheckProverInput, MultiplicityCheckVerifierInput,
    },
    sign_check::{SignCheckPIOP, SignCheckProverInput, SignCheckVerifierInput},
    supp_check::{SuppCheckPIOP, SuppCheckProverInput, SuppCheckVerifierInput},
};
use core::panic;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use std::{
    clone,
    collections::{BTreeMap, HashMap},
    marker::PhantomData,
};
pub struct StatCheckPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    PhantomData<F>,
    PhantomData<MvPCS>,
    PhantomData<UvPCS>,
);
pub struct StatCheckProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub query_input_table: ArithTable<F, MvPCS, UvPCS>,
    pub query_output_table: ArithTable<F, MvPCS, UvPCS>,
    pub input_folded_col: ArithCol<F, MvPCS, UvPCS>,
    pub output_folded_col: ArithCol<F, MvPCS, UvPCS>,
    pub super_set_multiplicity_tr_p: TrackedPoly<F, MvPCS, UvPCS>,
    pub instr: GroupByConfig,
}
impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for StatCheckProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, new_prover: Prover<F, MvPCS, UvPCS>) -> Self {
        StatCheckProverInput {
            query_input_table: self.query_input_table.deep_clone(new_prover.clone()),
            query_output_table: self.query_output_table.deep_clone(new_prover.clone()),
            input_folded_col: self.input_folded_col.deep_clone(new_prover.clone()),
            output_folded_col: self.output_folded_col.deep_clone(new_prover.clone()),
            super_set_multiplicity_tr_p: self
                .super_set_multiplicity_tr_p
                .deep_clone(new_prover.clone()),
            instr: self.instr.clone(),
        }
    }
}
pub struct StatCheckVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub query_output_table_comm: TableComm<F, MvPCS, UvPCS>,
    pub query_input_table_comm: TableComm<F, MvPCS, UvPCS>,
    pub input_folded_col_comm: ColCom<F, MvPCS, UvPCS>,
    pub output_folded_col_comm: ColCom<F, MvPCS, UvPCS>,
    pub super_set_multiplicity_tr_com: TrackedOracle<F, MvPCS, UvPCS>,
    pub instr: GroupByConfig,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for StatCheckPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = StatCheckProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierOutput = ();
    type VerifierInput = StatCheckVerifierInput<F, MvPCS, UvPCS>;

    #[timed]
    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<Self::ProverOutput> {
        // Honest prover check is not implemented for this PIOP

        // TODO: Implement the honest prover check
        Ok(())
    }

    #[timed]
    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        for (col_ind, stat_type) in input.instr.agg_instr.iter() {
            match stat_type {
                AggregationType::Count => {
                    prove_count_stat(
                        prover,
                        input.super_set_multiplicity_tr_p.clone(),
                        input.query_output_table.col(*col_ind),
                    )?;
                },
                AggregationType::Sum => {
                    prove_sum_stat(
                        prover,
                        input.input_folded_col.clone(),
                        input.query_input_table.col(*col_ind),
                        input.output_folded_col.clone(),
                        input.query_output_table.col(*col_ind),
                    )?;
                },
                AggregationType::Max => {
                    prove_max_min_stat(
                        prover,
                        AggregationType::Max,
                        input.super_set_multiplicity_tr_p.clone(),
                        input.input_folded_col.clone(),
                        input.query_input_table.col(*col_ind),
                        input.output_folded_col.clone(),
                        input.query_output_table.col(*col_ind),
                    )?;
                },
                AggregationType::Min => {
                    prove_max_min_stat(
                        prover,
                        AggregationType::Min,
                        input.super_set_multiplicity_tr_p.clone(),
                        input.input_folded_col.clone(),
                        input.query_input_table.col(*col_ind),
                        input.output_folded_col.clone(),
                        input.query_output_table.col(*col_ind),
                    )?;
                },
                AggregationType::Avg => {
                    todo!()
                },
                _ => unimplemented!(),
            }
        }
        Ok(())
    }

    #[timed]
    fn verify(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        input
            .instr
            .agg_instr
            .iter()
            .try_for_each(|(col_ind, stat_type)| {
                match stat_type {
                    AggregationType::Count => verify_count_stat(
                        verifier,
                        input.super_set_multiplicity_tr_com.clone(),
                        input.query_output_table_comm.col(*col_ind),
                    )?,
                    AggregationType::Sum => verify_sum_stat(
                        verifier,
                        input.input_folded_col_comm.clone(),
                        input.query_input_table_comm.col(*col_ind),
                        input.output_folded_col_comm.clone(),
                        input.query_output_table_comm.col(*col_ind),
                    )?,
                    AggregationType::Max => verify_max_min_stat(
                        verifier,
                        AggregationType::Max,
                        input.super_set_multiplicity_tr_com.clone(),
                        input.input_folded_col_comm.clone(),
                        input.query_input_table_comm.col(*col_ind),
                        input.output_folded_col_comm.clone(),
                        input.query_output_table_comm.col(*col_ind),
                    )?,
                    AggregationType::Min => verify_max_min_stat(
                        verifier,
                        AggregationType::Min,
                        input.super_set_multiplicity_tr_com.clone(),
                        input.input_folded_col_comm.clone(),
                        input.query_input_table_comm.col(*col_ind),
                        input.output_folded_col_comm.clone(),
                        input.query_output_table_comm.col(*col_ind),
                    )?,
                    AggregationType::Avg => todo!(),
                    _ => unimplemented!(),
                }
                Ok::<(), SnarkError>(())
            })?;
        Ok(())
    }
}

#[timed]
fn prove_count_stat<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    prover: &mut Prover<F, MvPCS, UvPCS>,
    super_set_multiplicity_tr_p: TrackedPoly<F, MvPCS, UvPCS>,
    stat_col: ArithCol<F, MvPCS, UvPCS>,
) -> SnarkResult<()> {
    let witness_tr_poly = &super_set_multiplicity_tr_p - &stat_col.activated_data_poly();
    prover.add_mv_zerocheck_claim(witness_tr_poly.get_id())?;
    Ok(())
}

#[timed]
fn verify_count_stat<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    verifier: &mut Verifier<F, MvPCS, UvPCS>,
    super_set_multiplicity_tr_comm: TrackedOracle<F, MvPCS, UvPCS>,
    stat_col_comm: ColCom<F, MvPCS, UvPCS>,
) -> SnarkResult<()> {
    let witness_tr_comm = &super_set_multiplicity_tr_comm - (&stat_col_comm.effective_comm());
    verifier.add_zerocheck_claim(witness_tr_comm.id);
    Ok(())
}

#[timed]
fn prove_sum_stat<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    prover: &mut Prover<F, MvPCS, UvPCS>,
    input_table_folded_col: ArithCol<F, MvPCS, UvPCS>,
    input_table_tarcol: ArithCol<F, MvPCS, UvPCS>,
    output_table_folded_col: ArithCol<F, MvPCS, UvPCS>,
    output_table_tarcol: ArithCol<F, MvPCS, UvPCS>,
) -> SnarkResult<()> {
    let multiplicity_check_prover_input = MultiplicityCheckProverInput {
        fxs: vec![input_table_folded_col.clone()],
        gxs: vec![output_table_folded_col.clone()],
        mfxs: vec![Some(input_table_tarcol.data_poly().clone())],
        mgxs: vec![Some(output_table_tarcol.data_poly().clone())],
    };

    MultiplicityCheck::<F, MvPCS, UvPCS>::prove(prover, multiplicity_check_prover_input)
}

#[timed]
fn verify_sum_stat<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    verifier: &mut Verifier<F, MvPCS, UvPCS>,
    input_table_folded_col_comm: ColCom<F, MvPCS, UvPCS>,
    input_table_tarcol_comm: ColCom<F, MvPCS, UvPCS>,
    output_table_folded_col_comm: ColCom<F, MvPCS, UvPCS>,
    output_table_tarcol_comm: ColCom<F, MvPCS, UvPCS>,
) -> SnarkResult<()> {
    let multiplicity_check_verifier_input = MultiplicityCheckVerifierInput {
        fxs: vec![input_table_folded_col_comm.clone()],
        gxs: vec![output_table_folded_col_comm.clone()],
        mfxs: vec![Some(input_table_tarcol_comm.inner)],
        mgxs: vec![Some(output_table_tarcol_comm.inner)],
    };

    MultiplicityCheck::<F, MvPCS, UvPCS>::verify(verifier, multiplicity_check_verifier_input)
}

#[timed]
fn prove_max_min_stat<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>(
    prover: &mut Prover<F, MvPCS, UvPCS>,
    stat_type: AggregationType,
    common_mset_supp_m: TrackedPoly<F, MvPCS, UvPCS>,
    input_table_folded_col: ArithCol<F, MvPCS, UvPCS>,
    input_table_tarcol: ArithCol<F, MvPCS, UvPCS>,
    output_table_folded_col: ArithCol<F, MvPCS, UvPCS>,
    output_table_tarcol: ArithCol<F, MvPCS, UvPCS>,
) -> SnarkResult<()> {
    // Broadcast those stats back into the input elements of the category
    let broadcasted_stat_evals = broadcast_stat_evals(
        &input_table_folded_col,
        &input_table_tarcol,
        &output_table_folded_col,
        &output_table_tarcol,
    );
    let broadcasted_stat_poly = MLE::from_evaluations_vec(
        input_table_folded_col.num_vars(),
        broadcasted_stat_evals,
    );
    let broadcasted_stat_tr_poly = prover.track_and_commit_mat_mv_poly(&broadcasted_stat_poly)?;
    let broadcast_col = ArithCol::new(
        input_table_tarcol.data_type().clone(),
        broadcasted_stat_tr_poly.clone(),
        input_table_tarcol.actvtr_poly().cloned(),
    );
    // Prove that the broadcasted column is computed correctly
    // First check that the output statistics foded with the output categories is
    // the support of the broadcasted column folded with the input categories
    let broadcast_folding_challs: Vec<F> = (0..2)
        .map(|_| prover.get_and_append_challenge(b"broadcast").unwrap())
        .collect();

    let input_target_folded_with_broadcast = fold_polys(
        &[broadcast_col.clone(), input_table_folded_col.clone()],
        &broadcast_folding_challs,
    );

    let output_target_folded_with_broadcast = fold_polys(
        &[
            output_table_tarcol.clone(),
            output_table_folded_col.clone(),
        ],
        &broadcast_folding_challs,
    );

    // Invoke the SuppCheck as a white box
    SuppCheckPIOP::<F, MvPCS, UvPCS>::prove_with_advice(
        prover,
        &input_target_folded_with_broadcast,
        &output_target_folded_with_broadcast,
        &common_mset_supp_m,
    )?;

    // Second check that the maximum value does actually appear in the input data
    let chall = prover.get_and_append_challenge(b"max_min").unwrap();
    let data_poly = input_table_folded_col.data_poly()
        + &(&(&broadcasted_stat_tr_poly - input_table_tarcol.data_poly()) * (chall));
    let super_col = ArithCol::new(
        None,
        data_poly,
        input_table_folded_col.actvtr_poly().cloned(),
    );
    let inclusion_check_prover_input = InclusionCheckProverInput {
        included_col: output_table_folded_col,
        super_col,
    };

    InclusionCheckPIOP::<F, MvPCS, UvPCS>::prove(prover, inclusion_check_prover_input)?;

    // Finally Prover that the broadcasted stats subtracted by the input table
    // target column is non-negative; i.e. the input table target column is less
    // than or equal to the broadcasted stats

    let non_negative_tr_poly =
        &broadcasted_stat_tr_poly - input_table_tarcol.data_poly();
    let sign_check_piop_prover_input = SignCheckProverInput {
        col: ArithCol::new(
            input_table_tarcol.data_type().clone(),
            non_negative_tr_poly,
            input_table_tarcol.actvtr_poly().cloned(),
        ),
        sign: match stat_type {
            AggregationType::Max => col_toolbox::sign_check::Sign::NoneNegative,
            AggregationType::Min => col_toolbox::sign_check::Sign::NonePositive,
            _ => unreachable!(),
        },
    };

    SignCheckPIOP::<F, MvPCS, UvPCS>::prove(prover, sign_check_piop_prover_input)?;
    Ok(())
}

#[timed]
fn verify_max_min_stat<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    verifier: &mut Verifier<F, MvPCS, UvPCS>,
    stat_type: AggregationType,
    common_mset_supp_m: TrackedOracle<F, MvPCS, UvPCS>,
    input_table_folded_col_comm: ColCom<F, MvPCS, UvPCS>,
    input_table_tarcol_comm: ColCom<F, MvPCS, UvPCS>,
    output_table_folded_col_comm: ColCom<F, MvPCS, UvPCS>,
    output_table_tarcol_comm: ColCom<F, MvPCS, UvPCS>,
) -> SnarkResult<()> {
    let broadcasted_stat_oracle_id = verifier.peek_next_id();
    let broadcasted_stat_tr_comm = verifier.track_mv_com_by_id(broadcasted_stat_oracle_id)?;
    let broadcast_col_comm = ColCom {
        data_type: input_table_tarcol_comm.data_type.clone(),
        inner: broadcasted_stat_tr_comm.clone(),
        actv: input_table_tarcol_comm.actv.clone(),
        num_vars: input_table_tarcol_comm.num_vars,
    };
    // Prove that the broadcasted column is computed correctly
    // First check that the output statistics foded with the output categories is
    // the support of the broadcasted column folded with the input categories
    let broadcast_folding_challs: Vec<F> = (0..2)
        .map(|_| verifier.get_and_append_challenge(b"broadcast").unwrap())
        .collect();

    let input_target_folded_with_broadcast = fold_coms(
        &[
            broadcast_col_comm.clone(),
            input_table_folded_col_comm.clone(),
        ],
        &broadcast_folding_challs,
    );

    let output_target_folded_with_broadcast = fold_coms(
        &[
            output_table_tarcol_comm.clone(),
            output_table_folded_col_comm.clone(),
        ],
        &broadcast_folding_challs,
    );

    // Invoke the SuppCheck as a white box
    SuppCheckPIOP::<F, MvPCS, UvPCS>::verify_with_advice(
        verifier,
        &input_target_folded_with_broadcast,
        &output_target_folded_with_broadcast,
        &common_mset_supp_m,
    )?;

    // Second check that the maximum value does actually appear in the input data
    let chall = verifier.get_and_append_challenge(b"max_min").unwrap();
    let data_poly = &input_table_folded_col_comm.inner
        + &(&(&broadcasted_stat_tr_comm - &input_table_tarcol_comm.inner) * (chall));
    let super_col_comm = ColCom::new(
        None,
        data_poly,
        input_table_folded_col_comm.actv,
        input_table_folded_col_comm.num_vars,
    );
    let inclusion_check_verifier_input = InclusionCheckVerifierInput {
        included_col_comm: output_table_folded_col_comm,
        super_col_comm,
    };

    InclusionCheckPIOP::<F, MvPCS, UvPCS>::verify(verifier, inclusion_check_verifier_input)?;
    // Finally Prover that the broadcasted stats subtracted by the input table
    // target column is non-negative; i.e. the input table target column is less
    // than or equal to the broadcasted stats

    let non_negative_comm = &broadcasted_stat_tr_comm - &input_table_tarcol_comm.inner;
    let sign_check_piop_verifier_input = SignCheckVerifierInput {
        col_comm: ColCom {
            data_type: input_table_tarcol_comm.data_type.clone(),
            inner: non_negative_comm,
            actv: input_table_tarcol_comm.actv.clone(),
            num_vars: input_table_tarcol_comm.num_vars,
        },
        sign: match stat_type {
            AggregationType::Max => col_toolbox::sign_check::Sign::NoneNegative,
            AggregationType::Min => col_toolbox::sign_check::Sign::NonePositive,
            _ => unreachable!(),
        },
    };
    SignCheckPIOP::<F, MvPCS, UvPCS>::verify(verifier, sign_check_piop_verifier_input)?;
    Ok(())
}

#[timed]
fn build_output_category_stat_map<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    output_table_tarcol: &ArithCol<F, MvPCS, UvPCS>,
    output_table_folded_col: &ArithCol<F, MvPCS, UvPCS>,
) -> BTreeMap<F, F> {
    let mut output_category_stat_map = BTreeMap::new();
    let output_table_target_eval = output_table_tarcol.data_poly().evaluations();
    let output_table_folded_evals = output_table_folded_col.data_poly().evaluations();
    match output_table_folded_col.actvtr_poly() {
        Some(actv) => {
            let actv_evals = actv.evaluations();
            // Only consider the active categories
            output_table_folded_evals
                .iter()
                .enumerate()
                .for_each(|(i, category)| {
                    if actv_evals[i].is_one() {
                        output_category_stat_map.insert(*category, output_table_target_eval[i]);
                    }
                });
        },
        None => output_table_folded_evals
            .iter()
            .enumerate()
            .for_each(|(i, category)| {
                output_category_stat_map.insert(*category, output_table_target_eval[i]);
            }),
    };
    output_category_stat_map
}

#[timed]
fn broadcast_stat_evals<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
>(
    input_table_folded_col: &ArithCol<F, MvPCS, UvPCS>,
    input_table_tarcol: &ArithCol<F, MvPCS, UvPCS>,
    output_table_folded_col: &ArithCol<F, MvPCS, UvPCS>,
    output_table_tarcol: &ArithCol<F, MvPCS, UvPCS>,
) -> Vec<F> {
    // Create a map from the output categories to their corresponding stats

    let output_category_stat_map =
        build_output_category_stat_map(output_table_tarcol, output_table_folded_col);
    let mut broadcasted_stat_evals = input_table_tarcol.data_poly().evaluations().clone();
    let evals = input_table_folded_col.data_poly().evaluations();
    match input_table_folded_col.actvtr_poly() {
        Some(actv) => {
            // Only consider the active categories
            let actv_evals = actv.evaluations();
            cfg_iter_mut!(broadcasted_stat_evals)
                .zip(cfg_iter!(evals))
                .zip(cfg_iter!(actv_evals))
                .for_each(|((stat, category), &actv)| {
                    if actv.is_one() {
                        // Only broadcast the stats for the active categories
                        *stat = match output_category_stat_map.get(category) {
                            Some(stat) => *stat,
                            None => {
                                panic!("Category not found in output category stat map");
                            },
                        };
                    }
                });
        },
        None => cfg_iter_mut!(broadcasted_stat_evals)
            .zip(cfg_iter!(evals))
            .for_each(|(stat, category)| {
                *stat = *output_category_stat_map.get(category).unwrap();
            }),
    };
    broadcasted_stat_evals
}
