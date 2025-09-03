//! Important: There are certain structures imposed on the input, output tables
//! and the witness Input table schema: (key, other attributes...)
//! Output table schema: (key, Left attributes, Right attributes...)

////////////// imports //////////////

use arithmetic::{
    col::{ArithCol, ColCom},
    table::{ArithTable, TableComm},
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{Prover, structs::TrackedPoly},
    timed,
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
    no_dup_check::NoDupPIOP,
    set_intersec::{SetInterUnionCheckPIOP, SetInterUnionProverInput, SetInterUnionVerifierInput},
    supp_check::{SuppCheckPIOP, SuppCheckProverInput, SuppCheckVerifierInput},
};
use derivative::Derivative;
use rayon::vec;
use std::{marker::PhantomData, sync::Arc};
#[cfg(test)]
mod test;

/// InnerJoin Prover
pub struct InnerJoinPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    PhantomData<F>,
    PhantomData<MvPCS>,
    PhantomData<UvPCS>,
);

pub struct InnerJoinProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub left_table: ArithTable<F, MvPCS, UvPCS>,
    pub right_table: ArithTable<F, MvPCS, UvPCS>,
    pub out_table: ArithTable<F, MvPCS, UvPCS>,
    pub left_key_support: ArithCol<F, MvPCS, UvPCS>,
    pub right_key_support: ArithCol<F, MvPCS, UvPCS>,
    pub out_key_support: ArithCol<F, MvPCS, UvPCS>,
    pub all_key_support: ArithCol<F, MvPCS, UvPCS>,
    pub join_left_source: ArithCol<F, MvPCS, UvPCS>,
    pub join_right_source: ArithCol<F, MvPCS, UvPCS>,
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
    pub left_table_comm: TableComm<F, MvPCS, UvPCS>,
    pub right_table_comm: TableComm<F, MvPCS, UvPCS>,
    pub out_table_comm: TableComm<F, MvPCS, UvPCS>,
    pub left_key_support_comm: ColCom<F, MvPCS, UvPCS>,
    pub right_key_support_comm: ColCom<F, MvPCS, UvPCS>,
    pub out_key_support_comm: ColCom<F, MvPCS, UvPCS>,
    pub all_key_support_comm: ColCom<F, MvPCS, UvPCS>,
    pub join_left_source_comm: ColCom<F, MvPCS, UvPCS>,
    pub join_right_source_comm: ColCom<F, MvPCS, UvPCS>,
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

    #[timed]
    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        // TODO: honest-prover check
        Ok(())
    }

    #[timed]
    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        // TODO: Check if the activator in the Source_l, Source_r are consistent with
        // the table out

        // Support Check on left_key_support, log output
        let supp_left_prover_input = SuppCheckProverInput {
            col: input.left_table.get_col(0),
            supp: input.left_key_support.clone(),
        };
        let left_supp_check_output = SuppCheckPIOP::prove(prover, supp_left_prover_input)?;

        // Support Check on right_key_support, log output
        let supp_right_prover_input = SuppCheckProverInput {
            col: input.right_table.get_col(0),
            supp: input.right_key_support.clone(),
        };
        let right_supp_check_output = SuppCheckPIOP::prove(prover, supp_right_prover_input)?;

        // Support Check on the out table
        let supp_out_prover_input = SuppCheckProverInput {
            col: input.out_table.get_col(0),
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
        let left_minus_out = &input
            .left_key_support
            .get_data_poly()
            .sub_poly(input.out_key_support.get_data_poly());
        let zero_poly = match input.out_key_support.get_actvtr_poly() {
            Some(act) => &act.mul_poly(left_minus_out),
            None => left_minus_out,
        };
        prover.add_mv_zerocheck_claim(zero_poly.get_id())?;

        // Zero Check on act(out_keys)(right_key - out_keys)
        let right_minus_out = &input
            .right_key_support
            .get_data_poly()
            .sub_poly(input.out_key_support.get_data_poly());
        let zero_poly = match input.out_key_support.get_actvtr_poly() {
            Some(act) => &act.mul_poly(right_minus_out),
            None => right_minus_out,
        };
        prover.add_mv_zerocheck_claim(zero_poly.get_id())?;
        // Zero Check on act(all_keys)(multicity_L * multiplicty_R - multiplicity_O)
        let mlmlr_minus_mo = (left_supp_check_output
            .super_set_multiplicity_tr_p
            .mul_poly(&right_supp_check_output.super_set_multiplicity_tr_p))
        .sub_poly(&out_supp_check_output.super_set_multiplicity_tr_p);
        let zero_poly = match input.out_key_support.get_actvtr_poly() {
            Some(act) => &act.mul_poly(&mlmlr_minus_mo),
            None => &mlmlr_minus_mo,
        };
        prover.add_mv_zerocheck_claim(zero_poly.get_id())?;

        // Random Challenge r picked from verifier
        // TODO: Go and add the functionality for adding a vector of challenges in
        // the // ark-piop crate
        let r_vec = vec![
            prover.get_and_append_challenge(b"r1")?,
            prover.get_and_append_challenge(b"r2")?,
        ];
        let folded = (input.join_left_source.get_data_poly().mul_scalar(r_vec[0]))
            .add_poly(&input.join_right_source.get_data_poly().mul_scalar(r_vec[1]));
        let folded_sources = ArithCol::new(
            None,
            folded,
            input.join_left_source.get_actvtr_poly().cloned(),
        );

        // NoDupCheck on source_L + r(source_R)
        NoDupPIOP::prove(prover, &folded_sources)?;
        let alpha_vec = (0..(input.right_table.num_cols() + 1))
            .map(|_| prover.get_and_append_challenge(b"alpha").unwrap())
            .collect::<Vec<F>>();

        let input_right_table_folded_col = input
            .right_table
            .fold_all(&alpha_vec[0..&alpha_vec.len() - 1]);
        let right_ind_poly = prover.track_mat_mv_poly(MLE::from_evaluations_vec(
            input.right_table.num_vars(),
            (0..(1 << input.right_table.num_vars()))
                .map(|i| F::from(i as u64))
                .collect(),
        ));
        let input_right_folded_col = ArithCol::new(
            None,
            input_right_table_folded_col
                .get_data_poly()
                .clone()
                .add_poly(&right_ind_poly),
            input_right_table_folded_col.get_actvtr_poly().cloned(),
        );

        let mut output_right_indices = vec![0];
        output_right_indices.extend_from_slice(
            &(1..(input.right_table.num_cols()))
                .map(|i| i + input.left_table.num_cols() - 1)
                .collect::<Vec<usize>>(),
        );
        let output_right_table_folded_col = input
            .out_table
            .fold(&output_right_indices, &alpha_vec[0..&alpha_vec.len() - 1]);

        let output_right_folded_col = ArithCol::new(
            None,
            output_right_table_folded_col
                .get_data_poly()
                .clone()
                .add_poly(input.join_right_source.get_data_poly()),
            output_right_table_folded_col.get_actvtr_poly().cloned(),
        );
        // Right multiplicity check
        let right_multiplicity_prover_input = MultiplicityCheckProverInput {
            fxs: vec![output_right_folded_col.clone()],
            gxs: vec![input_right_folded_col.clone()],
            mfxs: vec![None],
            mgxs: vec![Some(input.right_table_multiplicity.clone())],
        };

        MultiplicityCheck::prove(prover, right_multiplicity_prover_input)?;

        let beta_vec = (0..(input.left_table.num_cols() + 1))
            .map(|_| prover.get_and_append_challenge(b"beta").unwrap())
            .collect::<Vec<F>>();

        let input_left_table_folded_col =
            input.left_table.fold_all(&beta_vec[0..&beta_vec.len() - 1]);
        let left_ind_poly = prover.track_mat_mv_poly(MLE::from_evaluations_vec(
            input.left_table.num_vars(),
            (0..(1 << input.left_table.num_vars()))
                .map(|i| F::from(i as u64))
                .collect(),
        ));
        let input_left_folded_col = ArithCol::new(
            None,
            input_left_table_folded_col
                .get_data_poly()
                .clone()
                .add_poly(&left_ind_poly),
            input_left_table_folded_col.get_actvtr_poly().cloned(),
        );

        let output_left_indices = (0..(input.left_table.num_cols())).collect::<Vec<usize>>();
        let output_left_table_folded_col = input
            .out_table
            .fold(&output_left_indices, &beta_vec[0..&beta_vec.len() - 1]);

        let output_left_folded_col = ArithCol::new(
            None,
            output_left_table_folded_col
                .get_data_poly()
                .clone()
                .add_poly(input.join_left_source.get_data_poly()),
            output_left_table_folded_col.get_actvtr_poly().cloned(),
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

    #[timed]
    fn verify(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        // Parse the config
        // Support Check on left_key_support, log output
        let supp_left_verifier_input = SuppCheckVerifierInput {
            col: input.left_table_comm.col(0),
            supp: input.left_key_support_comm.clone(),
        };
        let left_supp_check_output = SuppCheckPIOP::verify(verifier, supp_left_verifier_input)?;

        // Support Check on right_key_support, log output
        let supp_right_verifier_input = SuppCheckVerifierInput {
            col: input.right_table_comm.col(0),
            supp: input.right_key_support_comm.clone(),
        };
        let right_supp_check_output = SuppCheckPIOP::verify(verifier, supp_right_verifier_input)?;

        // Support Check on the out table
        let supp_out_verifier_input = SuppCheckVerifierInput {
            col: input.out_table_comm.col(0),
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
        let left_minus_out = &input.left_key_support_comm.inner - &input.out_key_support_comm.inner;
        let zero_poly = match &input.out_key_support_comm.actv {
            Some(act) => act * &left_minus_out,
            None => left_minus_out,
        };
        verifier.add_zerocheck_claim(zero_poly.id);

        // Zero Check on act(out_keys)(right_key - out_keys)
        let right_minus_out =
            &input.right_key_support_comm.inner - &input.out_key_support_comm.inner;
        let zero_poly = match &input.out_key_support_comm.actv {
            Some(act) => act * &right_minus_out,
            None => right_minus_out,
        };
        verifier.add_zerocheck_claim(zero_poly.id);

        // Zero Check on act(all_keys)(multicity_L * multiplicty_R - multiplicity_O)
        let mlmlr_minus_mo = &(&left_supp_check_output.super_set_multiplicity_tr_com
            * (&right_supp_check_output.super_set_multiplicity_tr_com))
            - (&out_supp_check_output.super_set_multiplicity_tr_com);
        let zero_poly = match &input.out_key_support_comm.actv {
            Some(act) => act * &mlmlr_minus_mo,
            None => mlmlr_minus_mo,
        };
        verifier.add_zerocheck_claim(zero_poly.id);

        // Fold source_r and source_l

        let r_vec = vec![
            verifier.get_and_append_challenge(b"r1")?,
            verifier.get_and_append_challenge(b"r2")?,
        ];
        let folded = &(&input.join_left_source_comm.inner * (r_vec[0]))
            + &(&input.join_right_source_comm.inner * r_vec[1]);
        let folded_sources_cm = ColCom::new(
            None,
            folded,
            input.join_left_source_comm.actv.clone(),
            input.join_left_source_comm.num_vars,
        );
        NoDupPIOP::verify(verifier, &folded_sources_cm)?;
        // Folding of key_out and source_R
        let alpha_vec = (0..(input.right_table_comm.num_cols() + 1))
            .map(|_| verifier.get_and_append_challenge(b"alpha").unwrap())
            .collect::<Vec<F>>();

        let input_right_table_folded_col_com = input
            .right_table_comm
            .fold_all(&alpha_vec[0..&alpha_vec.len() - 1]);
        let nv = input.right_table_comm.num_vars();
        let right_ind_closure = Arc::new(move |point: Vec<F>| {
            let mut eval = F::zero();
            for (i, coord) in point.iter().take(nv).enumerate() {
                eval += *coord * F::from(1 << i);
            }
            dbg!(eval);
            Ok(eval)
        });
        let right_ind_oracle =
            verifier.track_oracle(Oracle::Multivariate(right_ind_closure.clone()));

        let input_right_folded_col_com = ColCom::new(
            None,
            &input_right_table_folded_col_com.inner.clone() + &(right_ind_oracle),
            input_right_table_folded_col_com.actv,
            input_right_table_folded_col_com.num_vars,
        );
        let mut output_right_indices = vec![0];
        output_right_indices.extend_from_slice(
            &(1..(input.right_table_comm.num_cols()))
                .map(|i| i + input.left_table_comm.num_cols() - 1)
                .collect::<Vec<usize>>(),
        );
        let output_right_table_folded_col_com = input
            .out_table_comm
            .fold(&output_right_indices, &alpha_vec[0..&alpha_vec.len() - 1]);

        let output_right_folded_col_com = ColCom::new(
            None,
            &output_right_table_folded_col_com.inner.clone()
                + &(input.join_right_source_comm.inner),
            output_right_table_folded_col_com.actv,
            output_right_table_folded_col_com.num_vars,
        );
        // Right multiplicity check
        let right_multiplicity_verifier_input = MultiplicityCheckVerifierInput {
            fxs: vec![output_right_folded_col_com],
            gxs: vec![input_right_folded_col_com.clone()],
            mfxs: vec![None],
            mgxs: vec![Some(input.right_table_multiplicity.clone())],
        };
        MultiplicityCheck::verify(verifier, right_multiplicity_verifier_input)?;

        let beta_vec = (0..(input.left_table_comm.num_cols() + 1))
            .map(|_| verifier.get_and_append_challenge(b"beta").unwrap())
            .collect::<Vec<F>>();

        let input_left_table_folded_col_com = input
            .left_table_comm
            .fold_all(&beta_vec[0..&beta_vec.len() - 1]);
        let nv = input.left_table_comm.num_vars();
        let left_ind_closure = Arc::new(move |point: Vec<F>| {
            let mut eval = F::zero();
            for (i, coord) in point.iter().take(nv).enumerate() {
                eval += *coord * F::from(1 << i);
            }
            dbg!(eval);
            Ok(eval)
        });
        let left_ind_oracle = verifier.track_oracle(Oracle::Multivariate(left_ind_closure.clone()));

        let input_left_folded_col_com = ColCom::new(
            None,
            &input_left_table_folded_col_com.inner.clone() + &(left_ind_oracle),
            input_left_table_folded_col_com.actv,
            input_left_table_folded_col_com.num_vars,
        );
        let output_left_indices =
            (0..(input.left_table_comm.num_cols())).collect::<Vec<usize>>();
        let output_left_table_folded_col_com = input
            .out_table_comm
            .fold(&output_left_indices, &beta_vec[0..&beta_vec.len() - 1]);

        let output_left_folded_col_com = ColCom::new(
            None,
            &output_left_table_folded_col_com.inner.clone() + &(input.join_left_source_comm.inner),
            output_left_table_folded_col_com.actv,
            output_left_table_folded_col_com.num_vars,
        );
        // Right multiplicity check
        let left_multiplicity_verifier_input = MultiplicityCheckVerifierInput {
            fxs: vec![output_left_folded_col_com],
            gxs: vec![input_left_folded_col_com.clone()],
            mfxs: vec![None],
            mgxs: vec![Some(input.left_table_multiplicity.clone())],
        };
        MultiplicityCheck::verify(verifier, left_multiplicity_verifier_input)?;

        Ok(())
    }
}
