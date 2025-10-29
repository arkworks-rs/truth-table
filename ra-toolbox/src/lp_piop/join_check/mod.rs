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
    prover::{Prover, structs::polynomial::TrackedPoly},
    verifier::{
        Verifier,
        structs::oracle::{Oracle, TrackedOracle},
    },
};
use ark_std::{end_timer, start_timer};
use col_toolbox::{
    multiplicity_check::{
        MultiplicityCheck, MultiplicityCheckProverInput, MultiplicityCheckVerifierInput,
    },
    no_dup_check::{NoDupCheckProverInput, NoDupCheckVerifierInput, NoDupPIOP},
    set_intersec::{SetInterUnionCheckPIOP, SetInterUnionProverInput, SetInterUnionVerifierInput},
    supp_check::{SuppCheckPIOP, SuppCheckProverInput, SuppCheckVerifierInput},
};
use derivative::Derivative;
use std::{marker::PhantomData, sync::Arc};
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
    pub left_key_support: TrackedCol<F, MvPCS, UvPCS>,
    pub right_key_support: TrackedCol<F, MvPCS, UvPCS>,
    pub out_key_support: TrackedCol<F, MvPCS, UvPCS>,
    pub all_key_support: TrackedCol<F, MvPCS, UvPCS>,
    pub join_left_source: TrackedCol<F, MvPCS, UvPCS>,
    pub join_right_source: TrackedCol<F, MvPCS, UvPCS>,
    pub right_table_multiplicity: TrackedPoly<F, MvPCS, UvPCS>,
    pub left_table_multiplicity: TrackedPoly<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for InnerJoinProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            left_table: self.left_table.deep_clone(prover.clone()),
            right_table: self.right_table.deep_clone(prover.clone()),
            out_table: self.out_table.deep_clone(prover.clone()),
            left_key_support: self.left_key_support.deep_clone(prover.clone()),
            right_key_support: self.right_key_support.deep_clone(prover.clone()),
            out_key_support: self.out_key_support.deep_clone(prover.clone()),
            all_key_support: self.all_key_support.deep_clone(prover.clone()),
            join_left_source: self.join_left_source.deep_clone(prover.clone()),
            join_right_source: self.join_right_source.deep_clone(prover.clone()),
            left_table_multiplicity: self.left_table_multiplicity.deep_clone(prover.clone()),
            right_table_multiplicity: self.right_table_multiplicity.deep_clone(prover),
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
    pub left_key_support_comm: TrackedColOracle<F, MvPCS, UvPCS>,
    pub right_key_support_comm: TrackedColOracle<F, MvPCS, UvPCS>,
    pub out_key_support_comm: TrackedColOracle<F, MvPCS, UvPCS>,
    pub all_key_support_comm: TrackedColOracle<F, MvPCS, UvPCS>,
    pub join_left_source_comm: TrackedColOracle<F, MvPCS, UvPCS>,
    pub join_right_source_comm: TrackedColOracle<F, MvPCS, UvPCS>,
    pub right_table_multiplicity: TrackedOracle<F, MvPCS, UvPCS>,
    pub left_table_multiplicity: TrackedOracle<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for InnerJoinPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = InnerJoinProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierInput = InnerJoinVerifierInput<F, MvPCS, UvPCS>;
    type VerifierOutput = ();

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        // TODO: honest-prover check
        Ok(())
    }

    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        // TODO: Check if the activator in the Source_l, Source_r are consistent with
        // the table out

        // Support Check on left_key_support, log output
        let supp_left_prover_input = SuppCheckProverInput {
            col: input.left_table.tracked_col_by_ind(0),
            supp: input.left_key_support.clone(),
        };
        let left_supp_check_output = SuppCheckPIOP::prove(prover, supp_left_prover_input)?;

        // Support Check on right_key_support, log output
        let supp_right_prover_input = SuppCheckProverInput {
            col: input.right_table.tracked_col_by_ind(0),
            supp: input.right_key_support.clone(),
        };
        let right_supp_check_output = SuppCheckPIOP::prove(prover, supp_right_prover_input)?;

        // Support Check on the out table
        let supp_out_prover_input = SuppCheckProverInput {
            col: input.out_table.tracked_col_by_ind(0),
            supp: input.out_key_support.clone(),
        };
        let out_supp_check_output = SuppCheckPIOP::prove(prover, supp_out_prover_input)?;

        // (SetInterCheck) Multiplicity check on [left_key_support,
        // right_key_support] // and [all_key_support] with activator + 1
        let set_inter_union_prover_input = SetInterUnionProverInput {
            col_left: input.left_key_support.clone(),
            col_right: input.right_key_support.clone(),
            col_inter: input.out_key_support.clone(),
            col_union: input.all_key_support.clone(),
        };

        SetInterUnionCheckPIOP::prove(prover, set_inter_union_prover_input)?;

        // Zero Check on act(out_keys)(left_key - out_keys)
        let left_minus_out = &input.left_key_support.data_tracked_poly()
            - &input.out_key_support.data_tracked_poly();
        let zero_poly = match input.out_key_support.activator_tracked_poly() {
            Some(act) => &act * &left_minus_out,
            None => left_minus_out,
        };
        prover.add_mv_zerocheck_claim(zero_poly.id())?;

        // Zero Check on act(out_keys)(right_key - out_keys)
        let right_minus_out = &input.right_key_support.data_tracked_poly()
            - &input.out_key_support.data_tracked_poly();
        let zero_poly = match input.out_key_support.activator_tracked_poly() {
            Some(act) => &act * &right_minus_out,
            None => right_minus_out,
        };
        prover.add_mv_zerocheck_claim(zero_poly.id())?;
        // Zero Check on act(all_keys)(multicity_L * multiplicty_R - multiplicity_O)
        let mlmlr_minus_mo = &(&left_supp_check_output.super_set_multiplicity_tr_p
            * (&right_supp_check_output.super_set_multiplicity_tr_p))
            - (&out_supp_check_output.super_set_multiplicity_tr_p);
        let zero_poly = match input.out_key_support.activator_tracked_poly() {
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

        let mut output_right_indices = vec![0];
        output_right_indices.extend_from_slice(
            &(1..(input.right_table.num_data_tracked_cols()))
                .map(|i| i + input.left_table.num_data_tracked_cols() - 1)
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
        let right_multiplicity_prover_input = MultiplicityCheckProverInput {
            fxs: vec![output_right_folded_col.clone()],
            gxs: vec![input_right_folded_col.clone()],
            mfxs: vec![None],
            mgxs: vec![Some(input.right_table_multiplicity.clone())],
        };

        MultiplicityCheck::prove(prover, right_multiplicity_prover_input)?;

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
        let left_multiplicity_prover_input = MultiplicityCheckProverInput {
            fxs: vec![output_left_folded_col.clone()],
            gxs: vec![input_left_folded_col.clone()],
            mfxs: vec![None],
            mgxs: vec![Some(input.left_table_multiplicity.clone())],
        };

        MultiplicityCheck::prove(prover, left_multiplicity_prover_input)?;

        Ok(())
    }

    fn verify_inner(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        // Parse the config
        // Support Check on left_key_support, log output
        let supp_left_verifier_input = SuppCheckVerifierInput {
            col: input.left_tracked_table_oracle.tracked_col_oracle_by_ind(0),
            supp: input.left_key_support_comm.clone(),
        };
        let left_supp_check_output = SuppCheckPIOP::verify(verifier, supp_left_verifier_input)?;

        // Support Check on right_key_support, log output
        let supp_right_verifier_input = SuppCheckVerifierInput {
            col: input
                .right_tracked_table_oracle
                .tracked_col_oracle_by_ind(0),
            supp: input.right_key_support_comm.clone(),
        };
        let right_supp_check_output = SuppCheckPIOP::verify(verifier, supp_right_verifier_input)?;

        // Support Check on the out table
        let supp_out_verifier_input = SuppCheckVerifierInput {
            col: input.out_tracked_table_oracle.tracked_col_oracle_by_ind(0),
            supp: input.out_key_support_comm.clone(),
        };
        let out_supp_check_output = SuppCheckPIOP::verify(verifier, supp_out_verifier_input)?;

        // Set Intersection Union Check
        let set_inter_union_verifier_input = SetInterUnionVerifierInput {
            col_left: input.left_key_support_comm.clone(),
            col_right: input.right_key_support_comm.clone(),
            col_inter: input.out_key_support_comm.clone(),
            col_union: input.all_key_support_comm.clone(),
        };

        SetInterUnionCheckPIOP::verify(verifier, set_inter_union_verifier_input)?;

        // Zero Check on act(out_keys)(left_key - out_keys)
        let left_minus_out = &input.left_key_support_comm.data_tracked_oracle()
            - &input.out_key_support_comm.data_tracked_oracle();
        let zero_poly = match &input.out_key_support_comm.activator_tracked_oracle() {
            Some(act) => act * &left_minus_out,
            None => left_minus_out,
        };
        verifier.add_zerocheck_claim(zero_poly.id());

        // Zero Check on act(out_keys)(right_key - out_keys)
        let right_minus_out = &input.right_key_support_comm.data_tracked_oracle()
            - &input.out_key_support_comm.data_tracked_oracle();
        let zero_poly = match &input.out_key_support_comm.activator_tracked_oracle() {
            Some(act) => act * &right_minus_out,
            None => right_minus_out,
        };
        verifier.add_zerocheck_claim(zero_poly.id());

        // Zero Check on act(all_keys)(multicity_L * multiplicty_R - multiplicity_O)
        let mlmlr_minus_mo = &(&left_supp_check_output.super_set_multiplicity_tr_com
            * (&right_supp_check_output.super_set_multiplicity_tr_com))
            - (&out_supp_check_output.super_set_multiplicity_tr_com);
        let zero_poly = match &input.out_key_support_comm.activator_tracked_oracle() {
            Some(act) => act * &mlmlr_minus_mo,
            None => mlmlr_minus_mo,
        };
        verifier.add_zerocheck_claim(zero_poly.id());

        // Fold source_r and source_l

        let r_vec = [
            verifier.get_and_append_challenge(b"r1")?,
            verifier.get_and_append_challenge(b"r2")?,
        ];
        let folded = &(&input.join_left_source_comm.data_tracked_oracle() * (r_vec[0]))
            + &(&input.join_right_source_comm.data_tracked_oracle() * r_vec[1]);
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
            .fold_all_data_columns(&alpha_vec[0..&alpha_vec.len() - 1]);
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
        let mut output_right_indices = vec![0];
        output_right_indices.extend_from_slice(
            &(1..(input
                .right_tracked_table_oracle
                .num_data_tracked_col_oracles()))
                .map(|i| {
                    i + input
                        .left_tracked_table_oracle
                        .num_data_tracked_col_oracles()
                        - 1
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
                + &(input.join_right_source_comm.data_tracked_oracle()),
            output_right_table_folded_tracked_col_oracle.activator_tracked_oracle(),
            None,
        );
        // Right multiplicity check
        let right_multiplicity_verifier_input = MultiplicityCheckVerifierInput {
            fxs: vec![output_right_folded_tracked_col_oracle],
            gxs: vec![input_right_folded_tracked_col_oracle.clone()],
            mfxs: vec![None],
            mgxs: vec![Some(input.right_table_multiplicity.clone())],
        };
        MultiplicityCheck::verify(verifier, right_multiplicity_verifier_input)?;

        let beta_vec = (0..(input
            .left_tracked_table_oracle
            .num_data_tracked_col_oracles()
            + 1))
            .map(|_| verifier.get_and_append_challenge(b"beta").unwrap())
            .collect::<Vec<F>>();

        let input_left_table_folded_tracked_col_oracle = input
            .left_tracked_table_oracle
            .fold_all_data_columns(&beta_vec[0..&beta_vec.len() - 1]);
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
                + &(input.join_left_source_comm.data_tracked_oracle()),
            output_left_table_folded_tracked_col_oracle.activator_tracked_oracle(),
            None,
        );
        // Right multiplicity check
        let left_multiplicity_verifier_input = MultiplicityCheckVerifierInput {
            fxs: vec![output_left_folded_tracked_col_oracle],
            gxs: vec![input_left_folded_tracked_col_oracle.clone()],
            mfxs: vec![None],
            mgxs: vec![Some(input.left_table_multiplicity.clone())],
        };
        MultiplicityCheck::verify(verifier, left_multiplicity_verifier_input)?;

        Ok(())
    }
}
