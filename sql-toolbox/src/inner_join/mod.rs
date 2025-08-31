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
    prover::Prover,
    timed,
    verifier::Verifier,
};
use ark_std::{end_timer, start_timer};
use col_toolbox::{
    fold_check::{FoldCheckPIOP, FoldCheckProverInput, FoldCheckVerifierInput},
    no_dup_check::NoDupPIOP,
    set_intersec::{SetInterUnionCheckPIOP, SetInterUnionProverInput, SetInterUnionVerifierInput},
    supp_check::{SuppCheckPIOP, SuppCheckProverInput, SuppCheckVerifierInput},
};
use derivative::Derivative;
use std::marker::PhantomData;

/// InnerJoin Prover

pub struct InnerJoinPIOP<F: PrimeField, MvPCS: PCS<F>, UvPCS: PCS<F>>(
    PhantomData<F>,
    PhantomData<MvPCS>,
    PhantomData<UvPCS>,
);

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct InnerJoinConfig {
    pub left_key_idx: usize,
    pub right_key_idx: usize,
    pub out_key_idx: usize,
}

pub struct InnerJoinProverInput<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    pub left_table_comm: ArithTable<F, MvPCS, UvPCS>,
    pub right_table: ArithTable<F, MvPCS, UvPCS>,
    pub out_table: ArithTable<F, MvPCS, UvPCS>,
    pub keys: InnerJoinConfig,
    pub left_key_support: ArithCol<F, MvPCS, UvPCS>,
    pub right_key_support: ArithCol<F, MvPCS, UvPCS>,
    pub out_key_support: ArithCol<F, MvPCS, UvPCS>,
    pub all_key_support: ArithCol<F, MvPCS, UvPCS>,
    pub join_left_source: ArithCol<F, MvPCS, UvPCS>,
    pub join_right_source: ArithCol<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    DeepClone<F, MvPCS, UvPCS> for InnerJoinProverInput<F, MvPCS, UvPCS>
{
    fn deep_clone(&self, prover: Prover<F, MvPCS, UvPCS>) -> Self {
        Self {
            left_table_comm: self.left_table_comm.deep_clone(prover.clone()),
            right_table: self.right_table.deep_clone(prover.clone()),
            out_table: self.out_table.deep_clone(prover.clone()),
            keys: self.keys.clone(),
            left_key_support: self.left_key_support.deep_clone(prover.clone()),
            right_key_support: self.right_key_support.deep_clone(prover.clone()),
            out_key_support: self.out_key_support.deep_clone(prover.clone()),
            all_key_support: self.all_key_support.deep_clone(prover.clone()),
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
    pub left_table_comm: TableComm<F, MvPCS, UvPCS>,
    pub right_table_comm: TableComm<F, MvPCS, UvPCS>,
    pub out_table_comm: TableComm<F, MvPCS, UvPCS>,
    pub keys: InnerJoinConfig,
    pub left_key_support_comm: ColCom<F, MvPCS, UvPCS>,
    pub right_key_support_comm: ColCom<F, MvPCS, UvPCS>,
    pub out_key_support_comm: ColCom<F, MvPCS, UvPCS>,
    pub all_key_support_comm: ColCom<F, MvPCS, UvPCS>,
    pub join_left_source_comm: ColCom<F, MvPCS, UvPCS>,
    pub join_right_source_comm: ColCom<F, MvPCS, UvPCS>,
}

impl<F: PrimeField, MvPCS: PCS<F, Poly = MLE<F>>, UvPCS: PCS<F, Poly = LDE<F>>>
    PIOP<F, MvPCS, UvPCS> for InnerJoinPIOP<F, MvPCS, UvPCS>
{
    type ProverInput = InnerJoinProverInput<F, MvPCS, UvPCS>;
    type ProverOutput = ();
    type VerifierInput = InnerJoinVerifierInput<F, MvPCS, UvPCS>;
    type VerifierOutput = ();
    fn honest_prover_check(input: Self::ProverInput) -> SnarkResult<()> {
        // TODO: honest-prover check
        unimplemented!()
    }
    #[timed]
    fn prove_inner(
        prover: &mut Prover<F, MvPCS, UvPCS>,
        input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        // TODO: Check if the activator in the Source_l, Source_r are consistent with
        // the table out

        // Parse the config
        let conf = input.keys.clone();
        // Support Check on left_key_support, log output
        let supp_left_prover_input = SuppCheckProverInput {
            col: input.left_table_comm.get_col(conf.left_key_idx),
            supp: input.left_key_support.clone(),
        };
        let left_supp_check_output = SuppCheckPIOP::prove(prover, supp_left_prover_input)?;

        // Support Check on right_key_support, log output
        let supp_right_prover_input = SuppCheckProverInput {
            col: input.right_table.get_col(conf.right_key_idx),
            supp: input.right_key_support.clone(),
        };
        let right_supp_check_output = SuppCheckPIOP::prove(prover, supp_right_prover_input)?;

        // Support Check on the out table
        let supp_out_prover_input = SuppCheckProverInput {
            col: input.out_table.get_col(conf.out_key_idx),
            supp: input.out_key_support.clone(),
        };
        let out_supp_check_output = SuppCheckPIOP::prove(prover, supp_out_prover_input)?;

        // (SetInterCheck) Multiplicity check on [left_key_support, right_key_support]
        // and [all_key_support] with activator + 1
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
        // TODO: Go and add the functionality for adding a vector of challenges in the
        // ark-piop crate
        let r_vec = vec![
            prover.get_and_append_challenge(b"r1")?,
            prover.get_and_append_challenge(b"r2")?,
        ];
        let folded = (input.join_left_source.get_data_poly().mul_scalar(r_vec[0]))
            .add_poly(&input.join_right_source.get_data_poly().mul_scalar(r_vec[1]));
        let folded_col = ArithCol::new(
            None,
            folded,
            input.join_left_source.get_actvtr_poly().cloned(),
        );
        let fold_check_piop_prover_input = FoldCheckProverInput {
            in_cols: vec![input.join_left_source, input.join_right_source],
            folded_col: folded_col.clone(),
            challs: r_vec,
        };
        FoldCheckPIOP::prove(prover, fold_check_piop_prover_input)?;

        // NoDupCheck on source_L + r(source_R)
        NoDupPIOP::prove(prover, &folded_col)?;

        Ok(())
    }

    #[timed]
    fn verify(
        verifier: &mut Verifier<F, MvPCS, UvPCS>,
        input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        // Parse the config
        let conf = input.keys.clone();
        // Support Check on left_key_support, log output
        let supp_left_verifier_input = SuppCheckVerifierInput {
            col: input.left_table_comm.col(conf.left_key_idx),
            supp: input.left_key_support_comm.clone(),
        };
        let left_supp_check_output = SuppCheckPIOP::verify(verifier, supp_left_verifier_input)?;

        // Support Check on right_key_support, log output
        let supp_right_verifier_input = SuppCheckVerifierInput {
            col: input.right_table_comm.col(conf.right_key_idx),
            supp: input.right_key_support_comm.clone(),
        };
        let right_supp_check_output = SuppCheckPIOP::verify(verifier, supp_right_verifier_input)?;

        // Support Check on the out table
        let supp_out_verifier_input = SuppCheckVerifierInput {
            col: input.out_table_comm.col(conf.out_key_idx),
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
            + &(&input.join_right_source_comm.inner * (r_vec[1]));
        let folded_cm = ColCom::new(
            None,
            folded,
            input.join_left_source_comm.actv.clone(),
            input.join_left_source_comm.num_vars,
        );
        let fold_check_piop_prover_input = FoldCheckVerifierInput {
            in_cms: vec![input.join_left_source_comm, input.join_right_source_comm],
            folded_cm: folded_cm.clone(),
            challs: r_vec,
        };
        FoldCheckPIOP::verify(verifier, fold_check_piop_prover_input)?;
        NoDupPIOP::verify(verifier, &folded_cm)?;
        // TODO: implement the verifier logic
        Ok(())
    }
}
