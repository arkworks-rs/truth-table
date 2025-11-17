//! Important: There are certain structures imposed on the input, output tables
//! and the witness Input table schema: (key, other attributes...)
//! Output table schema: (key, Left attributes, Right attributes...)

////////////// imports //////////////

use arithmetic::{
    col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::ArgProver,
    verifier::{Verifier, structs::oracle::Oracle},
};
use col_toolbox::{
    bezout_based_multi_col_supp_check::{
        BezoutMultiColSuppCheckPIOP, BezoutMultiColSuppCheckProverInput,
        BezoutMultiColSuppCheckVerifierInput,
    },
    inclusion_check::{InclusionCheckPIOP, InclusionCheckProverInput, InclusionCheckVerifierInput},
    no_dup_check::{NoDupCheckProverInput, NoDupCheckVerifierInput, NoDupPIOP},
    set_intersec::{SetInterUnionCheckPIOP, SetInterUnionProverInput, SetInterUnionVerifierInput},
};
use derivative::Derivative;
use std::{env, marker::PhantomData};
#[cfg(test)]
mod test;

/// InnerJoin Prover
pub struct InnerJoinPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    PhantomData<F>,
    PhantomData<MvPCS>,
    PhantomData<UvPCS>,
);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct InnerJoinProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub left_table: TrackedTable<F, MvPCS, UvPCS>,
    pub right_table: TrackedTable<F, MvPCS, UvPCS>,
    pub out_table: TrackedTable<F, MvPCS, UvPCS>,
    pub left_key_support_table: TrackedTable<F, MvPCS, UvPCS>,
    pub right_key_support_table: TrackedTable<F, MvPCS, UvPCS>,
    pub out_key_support_table: TrackedTable<F, MvPCS, UvPCS>,
    pub all_key_support_table: TrackedTable<F, MvPCS, UvPCS>,
    pub join_left_source: TrackedCol<F, MvPCS, UvPCS>,
    pub join_right_source: TrackedCol<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for InnerJoinProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: ArgProver<F, MvPCS, UvPCS>) -> Self {
        Self {
            left_table: self.left_table.deep_clone(prover.clone()),
            right_table: self.right_table.deep_clone(prover.clone()),
            out_table: self.out_table.deep_clone(prover.clone()),
            left_key_support_table: self.left_key_support_table.deep_clone(prover.clone()),
            right_key_support_table: self.right_key_support_table.deep_clone(prover.clone()),
            out_key_support_table: self.out_key_support_table.deep_clone(prover.clone()),
            all_key_support_table: self.all_key_support_table.deep_clone(prover.clone()),
            join_left_source: self.join_left_source.deep_clone(prover.clone()),
            join_right_source: self.join_right_source.deep_clone(prover.clone()),
        }
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "MvPCS: PCS<F>"), PartialEq(bound = "MvPCS: PCS<F>"))]
pub struct InnerJoinVerifierInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub left_tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub right_tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub out_tracked_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub left_key_support_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub right_key_support_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub out_key_support_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub all_key_support_table_oracle: TrackedTableOracle<F, MvPCS, UvPCS>,
    pub join_left_source_table_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
    pub join_right_source_table_oracle: TrackedColOracle<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for InnerJoinPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = InnerJoinProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierInput = InnerJoinVerifierInput<F, MvPCS, UvPCS>;
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(_input: Self::ProverInput) -> SnarkResult<()> {
        // TODO: honest-prover check
        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        debug_assert!(
            input.left_key_support_table.num_data_tracked_cols()
                == input.right_key_support_table.num_data_tracked_cols()
        );

        debug_assert!(
            input.all_key_support_table.num_data_tracked_cols()
                == input.out_key_support_table.num_data_tracked_cols()
        );

        debug_assert!(
            input.out_key_support_table.num_data_tracked_cols()
                == input.right_key_support_table.num_data_tracked_cols()
        );

        let num_key_cols = input.left_key_support_table.num_data_tracked_cols();
        let key_cols_indices = (0..num_key_cols).collect::<Vec<usize>>();
        // Support Check on left_key_support, log output
        let left_key_multi_col_supp_prover_input = BezoutMultiColSuppCheckProverInput {
            orig_tracked_table: input
                .left_table
                .tracked_subtable_by_indices(&key_cols_indices),
            supp_tracked_table: input.left_key_support_table.clone(),
        };
        let left_key_multi_col_supp_prover_output =
            BezoutMultiColSuppCheckPIOP::prove(prover, left_key_multi_col_supp_prover_input)?;

        // Support Check on right_key_support, log output
        let right_key_multi_col_supp_prover_input = BezoutMultiColSuppCheckProverInput {
            orig_tracked_table: input
                .right_table
                .tracked_subtable_by_indices(&key_cols_indices),
            supp_tracked_table: input.right_key_support_table.clone(),
        };

        let right_key_multi_col_supp_prover_output =
            BezoutMultiColSuppCheckPIOP::prove(prover, right_key_multi_col_supp_prover_input)?;

        // Support Check on the out table
        let out_key_multi_col_supp_prover_input = BezoutMultiColSuppCheckProverInput {
            orig_tracked_table: input
                .out_table
                .tracked_subtable_by_indices(&key_cols_indices),
            supp_tracked_table: input.out_key_support_table.clone(),
        };

        let out_key_multi_col_supp_prover_output =
            BezoutMultiColSuppCheckPIOP::prove(prover, out_key_multi_col_supp_prover_input)?;

        ////////////////////////////////
        let key_challenges = (0..num_key_cols)
            .map(|_| prover.get_and_append_challenge(b"key_challenge").unwrap())
            .collect::<Vec<F>>();

        let left_key_support = input
            .left_key_support_table
            .fold_all_data_columns(&key_challenges);

        let right_key_support = input
            .right_key_support_table
            .fold_all_data_columns(&key_challenges);

        let out_key_support = input
            .out_key_support_table
            .fold_all_data_columns(&key_challenges);
        let all_key_support = input
            .all_key_support_table
            .fold_all_data_columns(&key_challenges);
        // (SetInterCheck) Multiplicity check on [left_key_support,
        // right_key_support] // and [all_key_support] with activator + 1
        let set_inter_union_prover_input = SetInterUnionProverInput {
            col_left: left_key_support.clone(),
            col_right: right_key_support.clone(),
            col_inter: out_key_support.clone(),
            col_union: all_key_support.clone(),
        };

        SetInterUnionCheckPIOP::prove(prover, set_inter_union_prover_input)?;

        // Zero Check on act(out_keys)(left_key - out_keys)
        let left_minus_out =
            &left_key_support.data_tracked_poly() - &out_key_support.data_tracked_poly();
        let zero_poly = match out_key_support.activator_tracked_poly() {
            Some(act) => &act * &left_minus_out,
            None => left_minus_out,
        };
        prover.add_mv_zerocheck_claim(zero_poly.id())?;
        // Zero Check on act(out_keys)(right_key - out_keys)
        let right_minus_out =
            &right_key_support.data_tracked_poly() - &out_key_support.data_tracked_poly();
        let zero_poly = match out_key_support.activator_tracked_poly() {
            Some(act) => &act * &right_minus_out,
            None => right_minus_out,
        };
        prover.add_mv_zerocheck_claim(zero_poly.id())?;

        // Zero Check on act(all_keys)(multicity_L * multiplicty_R - multiplicity_O)
        let mlmlr_minus_mo = &(&left_key_multi_col_supp_prover_output.multiplicity
            * (&right_key_multi_col_supp_prover_output.multiplicity))
            - (&out_key_multi_col_supp_prover_output.multiplicity);
        let zero_poly = match input.out_key_support_table.activator_tracked_poly() {
            Some(act) => &act * &mlmlr_minus_mo,
            None => mlmlr_minus_mo,
        };

        prover.add_mv_zerocheck_claim(zero_poly.id())?;

        // Random Challenge r picked from verifier
        // TODO: Go and add the functionality for adding a vector of challenges in
        // the // ark-piop crate
        let r_vec = [
            prover.get_and_append_challenge(b"r1")?,
            prover.get_and_append_challenge(b"r2")?,
        ];
        let folded = &(&input.join_left_source.data_tracked_poly() * r_vec[0])
            + &(&input.join_right_source.data_tracked_poly() * r_vec[1]);
        let folded_sources =
            TrackedCol::new(folded, input.out_table.activator_tracked_poly(), None);

        // NoDupCheck on source_L + r(source_R)
        let no_dup_prover_input = NoDupCheckProverInput {
            col: folded_sources.clone(),
        };
        NoDupPIOP::prove(prover, no_dup_prover_input)?;
        let alpha_vec = (0..(input.right_table.num_data_tracked_cols() + 1))
            .map(|_| prover.get_and_append_challenge(b"alpha").unwrap())
            .collect::<Vec<F>>();

        let input_right_table_folded_col = input
            .right_table
            .fold_all_data_columns(&alpha_vec[0..&alpha_vec.len() - 1]);
        let right_ind_poly = prover.track_mat_mv_poly(MLE::from_evaluations_vec(
            input.right_table.log_size(),
            (0..(1 << input.right_table.log_size()))
                .map(|i| F::from(i as u64))
                .collect(),
        ));
        let input_right_folded_col = TrackedCol::new(
            &input_right_table_folded_col.data_tracked_poly().clone() + &right_ind_poly,
            input_right_table_folded_col.activator_tracked_poly(),
            None,
        );

        let mut output_right_indices = (0..num_key_cols).collect::<Vec<usize>>();
        output_right_indices.extend_from_slice(
            &(num_key_cols..(input.right_table.num_data_tracked_cols()))
                .map(|i| i + input.left_table.num_data_tracked_cols() - num_key_cols)
                .collect::<Vec<usize>>(),
        );
        let output_right_table_folded_col = input
            .out_table
            .fold(&output_right_indices, &alpha_vec[0..&alpha_vec.len() - 1]);
        let output_right_folded_col = TrackedCol::new(
            &output_right_table_folded_col.data_tracked_poly().clone()
                + &input.join_right_source.data_tracked_poly(),
            output_right_table_folded_col.activator_tracked_poly(),
            None,
        );

        // Right multiplicity check
        let inclusion_check_prover_input = InclusionCheckProverInput {
            included_cols: vec![output_right_folded_col.clone()],
            super_col: input_right_folded_col.clone(),
        };

        log_inclusion_diff("right", &output_right_folded_col, &input_right_folded_col);

        dbg!(0);
        InclusionCheckPIOP::prove(prover, inclusion_check_prover_input)?;

        let beta_vec = (0..(input.left_table.num_data_tracked_cols() + 1))
            .map(|_| prover.get_and_append_challenge(b"beta").unwrap())
            .collect::<Vec<F>>();

        let input_left_table_folded_col = input
            .left_table
            .fold_all_data_columns(&beta_vec[0..&beta_vec.len() - 1]);
        let left_ind_poly = prover.track_mat_mv_poly(MLE::from_evaluations_vec(
            input.left_table.log_size(),
            (0..(1 << input.left_table.log_size()))
                .map(|i| F::from(i as u64))
                .collect(),
        ));
        let input_left_folded_col = TrackedCol::new(
            &input_left_table_folded_col.data_tracked_poly().clone() + &left_ind_poly,
            input_left_table_folded_col.activator_tracked_poly(),
            None,
        );

        let output_left_indices =
            (0..(input.left_table.num_data_tracked_cols())).collect::<Vec<usize>>();
        let output_left_table_folded_col = input
            .out_table
            .fold(&output_left_indices, &beta_vec[0..&beta_vec.len() - 1]);

        let output_left_folded_col = TrackedCol::new(
            &output_left_table_folded_col.data_tracked_poly().clone()
                + &input.join_left_source.data_tracked_poly(),
            output_left_table_folded_col.activator_tracked_poly(),
            None,
        );
        // Right multiplicity check
        let inclusion_check_prover_input = InclusionCheckProverInput {
            included_cols: vec![output_left_folded_col.clone()],
            super_col: input_left_folded_col.clone(),
        };
        log_inclusion_diff("left", &output_left_folded_col, &input_left_folded_col);
        dbg!(1);
        InclusionCheckPIOP::prove(prover, inclusion_check_prover_input)?;

        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        debug_assert!(
            input
                .left_key_support_table_oracle
                .num_data_tracked_col_oracles()
                == input
                    .right_key_support_table_oracle
                    .num_data_tracked_col_oracles()
        );

        debug_assert!(
            input
                .all_key_support_table_oracle
                .num_data_tracked_col_oracles()
                == input
                    .out_key_support_table_oracle
                    .num_data_tracked_col_oracles()
        );

        debug_assert!(
            input
                .out_key_support_table_oracle
                .num_data_tracked_col_oracles()
                == input
                    .right_key_support_table_oracle
                    .num_data_tracked_col_oracles()
        );

        let num_key_cols = input
            .left_key_support_table_oracle
            .num_data_tracked_col_oracles();
        let key_cols_indices = (0..num_key_cols).collect::<Vec<usize>>();
        // Support Check on left_key_support, log output
        let left_key_multi_col_supp_verifier_input = BezoutMultiColSuppCheckVerifierInput {
            orig_tracked_table_oracle: input
                .left_tracked_table_oracle
                .tracked_subtable_by_indices(&key_cols_indices),
            supp_tracked_table_oracle: input.left_key_support_table_oracle.clone(),
        };

        let left_key_multi_col_supp_verifier_output =
            BezoutMultiColSuppCheckPIOP::verify(verifier, left_key_multi_col_supp_verifier_input)?;

        // Support Check on right_key_support, log output
        let right_key_multi_col_supp_verifier_input = BezoutMultiColSuppCheckVerifierInput {
            orig_tracked_table_oracle: input
                .right_tracked_table_oracle
                .tracked_subtable_by_indices(&key_cols_indices),
            supp_tracked_table_oracle: input.right_key_support_table_oracle.clone(),
        };

        let right_key_multi_col_supp_verifier_output =
            BezoutMultiColSuppCheckPIOP::verify(verifier, right_key_multi_col_supp_verifier_input)?;

        // Support Check on the out table
        let out_key_multi_col_supp_verifier_input = BezoutMultiColSuppCheckVerifierInput {
            orig_tracked_table_oracle: input
                .out_tracked_table_oracle
                .tracked_subtable_by_indices(&key_cols_indices),
            supp_tracked_table_oracle: input.out_key_support_table_oracle.clone(),
        };

        let out_key_multi_col_supp_verifier_output =
            BezoutMultiColSuppCheckPIOP::verify(verifier, out_key_multi_col_supp_verifier_input)?;

        ////////////////////////////////
        let key_challenges = (0..num_key_cols)
            .map(|_| verifier.get_and_append_challenge(b"key_challenge").unwrap())
            .collect::<Vec<F>>();

        let left_key_support = input
            .left_key_support_table_oracle
            .fold_all_data_oracles(&key_challenges);

        let right_key_support = input
            .right_key_support_table_oracle
            .fold_all_data_oracles(&key_challenges);

        let out_key_support = input
            .out_key_support_table_oracle
            .fold_all_data_oracles(&key_challenges);
        let all_key_support = input
            .all_key_support_table_oracle
            .fold_all_data_oracles(&key_challenges);
        // (SetInterCheck) Multiplicity check on [left_key_support,
        // right_key_support] // and [all_key_support] with activator + 1
        let set_inter_union_verifier_input = SetInterUnionVerifierInput {
            col_left: left_key_support.clone(),
            col_right: right_key_support.clone(),
            col_inter: out_key_support.clone(),
            col_union: all_key_support.clone(),
        };

        SetInterUnionCheckPIOP::verify(verifier, set_inter_union_verifier_input)?;

        // Zero Check on act(out_keys)(left_key - out_keys)
        let left_minus_out =
            &left_key_support.data_tracked_oracle() - &out_key_support.data_tracked_oracle();
        let zero_poly = match out_key_support.activator_tracked_oracle() {
            Some(act) => &act * &left_minus_out,
            None => left_minus_out,
        };
        verifier.add_zerocheck_claim(zero_poly.id());

        // Zero Check on act(out_keys)(right_key - out_keys)
        let right_minus_out =
            &right_key_support.data_tracked_oracle() - &out_key_support.data_tracked_oracle();
        let zero_poly = match out_key_support.activator_tracked_oracle() {
            Some(act) => &act * &right_minus_out,
            None => right_minus_out,
        };
        verifier.add_zerocheck_claim(zero_poly.id());
        // Zero Check on act(all_keys)(multicity_L * multiplicty_R - multiplicity_O)
        let mlmlr_minus_mo = &(&left_key_multi_col_supp_verifier_output.multiplicity
            * (&right_key_multi_col_supp_verifier_output.multiplicity))
            - (&out_key_multi_col_supp_verifier_output.multiplicity);
        let zero_poly = match &input.out_key_support_table_oracle.activator_tracked_poly() {
            Some(act) => act * &mlmlr_minus_mo,
            None => mlmlr_minus_mo,
        };
        verifier.add_zerocheck_claim(zero_poly.id());

        // Fold source_r and source_l

        let r_vec = [
            verifier.get_and_append_challenge(b"r1")?,
            verifier.get_and_append_challenge(b"r2")?,
        ];
        let folded = &(&input.join_left_source_table_oracle.data_tracked_oracle() * (r_vec[0]))
            + &(&input.join_right_source_table_oracle.data_tracked_oracle() * r_vec[1]);
        let folded_sources_cm = TrackedColOracle::new(
            folded,
            input
                .out_tracked_table_oracle
                .activator_tracked_poly()
                .clone(),
            None,
        );
        let no_dup_verifier_input = NoDupCheckVerifierInput {
            tracked_col_oracle: folded_sources_cm.clone(),
        };
        NoDupPIOP::verify(verifier, no_dup_verifier_input)?;
        // Folding of key_out and source_R
        let alpha_vec = (0..(input
            .right_tracked_table_oracle
            .num_data_tracked_col_oracles()
            + 1))
            .map(|_| verifier.get_and_append_challenge(b"alpha").unwrap())
            .collect::<Vec<F>>();

        let input_right_table_folded_tracked_col_oracle = input
            .right_tracked_table_oracle
            .fold_all_data_oracles(&alpha_vec[0..&alpha_vec.len() - 1]);
        let nv = input.right_tracked_table_oracle.log_size();
        let right_ind_closure = Box::new(move |point: Vec<F>| {
            let mut eval = F::zero();
            for (i, coord) in point.iter().take(nv).enumerate() {
                eval += *coord * F::from(1 << i);
            }
            Ok(eval)
        });
        let right_ind_oracle =
            verifier.track_oracle(Oracle::new_multivariate(nv, right_ind_closure));

        let input_right_folded_tracked_col_oracle = TrackedColOracle::new(
            &input_right_table_folded_tracked_col_oracle
                .data_tracked_oracle()
                .clone()
                + &(right_ind_oracle),
            input_right_table_folded_tracked_col_oracle.activator_tracked_oracle(),
            None,
        );
        let mut output_right_indices = (0..num_key_cols).collect::<Vec<usize>>();
        output_right_indices.extend_from_slice(
            &(num_key_cols
                ..(input
                    .right_tracked_table_oracle
                    .num_data_tracked_col_oracles()))
                .map(|i| {
                    i + input
                        .left_tracked_table_oracle
                        .num_data_tracked_col_oracles()
                        - num_key_cols
                })
                .collect::<Vec<usize>>(),
        );
        let output_right_table_folded_tracked_col_oracle = input
            .out_tracked_table_oracle
            .fold(&output_right_indices, &alpha_vec[0..&alpha_vec.len() - 1]);

        let output_right_folded_tracked_col_oracle = TrackedColOracle::new(
            &output_right_table_folded_tracked_col_oracle
                .data_tracked_oracle()
                .clone()
                + &(input.join_right_source_table_oracle.data_tracked_oracle()),
            output_right_table_folded_tracked_col_oracle.activator_tracked_oracle(),
            None,
        );
        // Right multiplicity check

        let inclusion_check_verifier_input = InclusionCheckVerifierInput {
            included_tracked_col_oracles: vec![output_right_folded_tracked_col_oracle.clone()],
            super_tracked_col_oracle: input_right_folded_tracked_col_oracle.clone(),
        };

        InclusionCheckPIOP::verify(verifier, inclusion_check_verifier_input)?;

        let beta_vec = (0..(input
            .left_tracked_table_oracle
            .num_data_tracked_col_oracles()
            + 1))
            .map(|_| verifier.get_and_append_challenge(b"beta").unwrap())
            .collect::<Vec<F>>();

        let input_left_table_folded_tracked_col_oracle = input
            .left_tracked_table_oracle
            .fold_all_data_oracles(&beta_vec[0..&beta_vec.len() - 1]);
        let nv = input.left_tracked_table_oracle.log_size();
        let left_ind_closure = move |point: Vec<F>| {
            let mut eval = F::zero();
            for (i, coord) in point.iter().take(nv).enumerate() {
                eval += *coord * F::from(1 << i);
            }
            Ok(eval)
        };
        let left_ind_oracle = verifier.track_oracle(Oracle::new_multivariate(nv, left_ind_closure));

        let input_left_folded_tracked_col_oracle = TrackedColOracle::new(
            &input_left_table_folded_tracked_col_oracle
                .data_tracked_oracle()
                .clone()
                + &(left_ind_oracle),
            input_left_table_folded_tracked_col_oracle.activator_tracked_oracle(),
            None,
        );
        let output_left_indices = (0..(input
            .left_tracked_table_oracle
            .num_data_tracked_col_oracles()))
            .collect::<Vec<usize>>();
        let output_left_table_folded_tracked_col_oracle = input
            .out_tracked_table_oracle
            .fold(&output_left_indices, &beta_vec[0..&beta_vec.len() - 1]);

        let output_left_folded_tracked_col_oracle = TrackedColOracle::new(
            &output_left_table_folded_tracked_col_oracle
                .data_tracked_oracle()
                .clone()
                + &(input.join_left_source_table_oracle.data_tracked_oracle()),
            output_left_table_folded_tracked_col_oracle.activator_tracked_oracle(),
            None,
        );
        // Right multiplicity check
        let inclusion_check_verifier_input = InclusionCheckVerifierInput {
            included_tracked_col_oracles: vec![output_left_folded_tracked_col_oracle.clone()],
            super_tracked_col_oracle: input_left_folded_tracked_col_oracle.clone(),
        };

        InclusionCheckPIOP::verify(verifier, inclusion_check_verifier_input)?;

        Ok(())
    }
}

fn log_inclusion_diff<F, MvPCS, UvPCS>(
    label: &str,
    included: &TrackedCol<F, MvPCS, UvPCS>,
    super_col: &TrackedCol<F, MvPCS, UvPCS>,
) where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    if env::var("JOIN_INCL_DEBUG").is_err() {
        return;
    }

    let included_data_poly = included.data_tracked_poly();
    let super_data_poly = super_col.data_tracked_poly();
    let included_evals = included_data_poly.evaluations().to_vec();
    let super_evals = super_data_poly.evaluations().to_vec();

    let included_act_evals = included
        .activator_tracked_poly()
        .map(|poly| poly.evaluations().to_vec());
    let super_act_evals = super_col
        .activator_tracked_poly()
        .map(|poly| poly.evaluations().to_vec());

    let mut mismatch_total = 0usize;
    let mut samples = Vec::new();
    let len = included_evals.len().min(super_evals.len());
    for i in 0..len {
        let included_active = included_act_evals
            .as_ref()
            .is_none_or(|act| act[i] != F::zero());
        let super_active = super_act_evals
            .as_ref()
            .is_none_or(|act| act[i] != F::zero());

        if !(included_active && super_active) {
            continue;
        }

        if included_evals[i] != super_evals[i] {
            mismatch_total += 1;
            if samples.len() < 5 {
                samples.push(format!(
                    "(idx={}, included={:?}, super={:?})",
                    i, included_evals[i], super_evals[i]
                ));
            }
        }
    }

    println!(
        "[join inclusion debug] label={} len_included={} len_super={} mismatch_total={} samples={:?}",
        label,
        included_evals.len(),
        super_evals.len(),
        mismatch_total,
        samples
    );
}
