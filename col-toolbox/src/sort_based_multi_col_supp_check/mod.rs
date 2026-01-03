#[cfg(test)]
mod test;

use crate::{
    lookup::{
        HintedLookupPIOP, HintedLookupProverInput,
        HintedLookupVerifierInput,
    },
    no_zeros_check::{NoZerosCheck, NoZerosCheckProverInput, NoZerosCheckVerifierInput},
    sort_based_multi_col_nodup::{
        SortBasedMultiNoDup, SortBasedMultiNoDupProverInput, SortBasedMultiNoDupVerifierInput,
    },
};
use arithmetic::{
    col::TrackedCol, col_oracle::TrackedColOracle, table::TrackedTable,
    table_oracle::TrackedTableOracle,
};
use ark_piop::{
    SnarkBackend,
    errors::SnarkResult,
    pcs::PCS,
    piop::{DeepClone, PIOP},
    prover::{ArgProver, structs::polynomial::TrackedPoly},
    verifier::{ArgVerifier, structs::oracle::TrackedOracle},
};
use derivative::Derivative;
use std::marker::PhantomData;

pub struct MultiColSuppCheckPIOP<B: SnarkBackend>(#[doc(hidden)] PhantomData<B>);

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct MultiColSuppCheckProverInput<B: SnarkBackend> {
    pub orig_tracked_table: TrackedTable<B>,
    pub supp_tracked_table: TrackedTable<B>,
    pub contig_lex_sorted_supp_tracked_table: TrackedTable<B>,
    pub shifted_contig_lex_sorted_supp_tracked_table: TrackedTable<B>,
    pub tie_indicator_tracked_table: Option<TrackedTable<B>>,
    pub multiplicity: TrackedPoly<B>,
}

impl<B: SnarkBackend> DeepClone<B> for MultiColSuppCheckProverInput<B> {
    fn deep_clone(&self, new_prover: ArgProver<B>) -> Self {
        MultiColSuppCheckProverInput {
            orig_tracked_table: self.orig_tracked_table.deep_clone(new_prover.clone()),
            supp_tracked_table: self.supp_tracked_table.deep_clone(new_prover.clone()),
            contig_lex_sorted_supp_tracked_table: self
                .contig_lex_sorted_supp_tracked_table
                .deep_clone(new_prover.clone()),
            shifted_contig_lex_sorted_supp_tracked_table: self
                .shifted_contig_lex_sorted_supp_tracked_table
                .deep_clone(new_prover.clone()),
            tie_indicator_tracked_table: self
                .tie_indicator_tracked_table
                .as_ref()
                .map(|table| table.deep_clone(new_prover.clone())),

            multiplicity: self.multiplicity.deep_clone(new_prover),
        }
    }
}

pub struct MultiColSuppCheckVerifierInput<B: SnarkBackend> {
    pub orig_tracked_table_oracle: TrackedTableOracle<B>,
    pub supp_tracked_table_oracle: TrackedTableOracle<B>,
    pub contig_lex_sorted_supp_tracked_table_oracle: TrackedTableOracle<B>,
    pub shifted_contig_lex_sorted_supp_tracked_table_oracle: TrackedTableOracle<B>,
    pub tie_indicator_tracked_table_oracle: Option<TrackedTableOracle<B>>,
    pub multiplicity: TrackedOracle<B>,
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct MultiColSuppCheckProverOutput<B: SnarkBackend> {
    pub orig_folded_tracked_col: TrackedCol<B>,
    pub supp_folded_tracked_col: TrackedCol<B>,
}
#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct MultiColSuppCheckVerifierOutput<B: SnarkBackend> {
    pub orig_folded_tracked_col_oracle: TrackedColOracle<B>,
    pub supp_folded_tracked_col_oracle: TrackedColOracle<B>,
}

impl<B: SnarkBackend> PIOP<B> for MultiColSuppCheckPIOP<B> {
    type ProverInput = MultiColSuppCheckProverInput<B>;
    type VerifierInput = MultiColSuppCheckVerifierInput<B>;
    type ProverOutput = MultiColSuppCheckProverOutput<B>;
    type VerifierOutput = MultiColSuppCheckVerifierOutput<B>;

    #[cfg(feature = "honest-prover")]
    fn honest_prover_check(_input: Self::ProverInput) -> SnarkResult<()> {
        // TODO

        Ok(())
    }

    fn prove_inner(
        prover: &mut ArgProver<B>,
        prover_input: Self::ProverInput,
    ) -> SnarkResult<Self::ProverOutput> {
        let table_folding_challs = (0..prover_input.orig_tracked_table.num_data_tracked_cols())
            .map(|_| prover.get_and_append_challenge(b"a").unwrap())
            .collect::<Vec<B::F>>();

        let orig_table_folded_col = prover_input
            .orig_tracked_table
            .fold_all_data_columns(&table_folding_challs);

        let supp_table_folded_col = prover_input
            .supp_tracked_table
            .fold_all_data_columns(&table_folding_challs);

        let multicol_lookup_prover_input = HintedLookupProverInput {
            included_cols: vec![orig_table_folded_col.clone()],
            super_col: supp_table_folded_col.clone(),
            super_col_multiplicities: vec![prover_input.multiplicity.clone()],
        };

        HintedLookupPIOP::<B>::prove(prover, multicol_lookup_prover_input)?;

        let supp_no_dups_checker = TrackedCol::new(
            prover_input.multiplicity.clone(),
            prover_input.supp_tracked_table.activator_tracked_poly(),
            None,
        );
        let no_zeros_check_prover_input = NoZerosCheckProverInput {
            col: supp_no_dups_checker,
        };
        NoZerosCheck::<B>::prove(prover, no_zeros_check_prover_input)?;

        let multi_col_no_dup_prover_input = SortBasedMultiNoDupProverInput {
            tracked_table: prover_input.supp_tracked_table.clone(),
            contig_lex_sorted_tracked_table: prover_input
                .contig_lex_sorted_supp_tracked_table
                .clone(),
            tie_indicator_tracked_table: prover_input.tie_indicator_tracked_table.clone(),
            shift_tracked_table: prover_input
                .shifted_contig_lex_sorted_supp_tracked_table
                .clone(),
        };

        SortBasedMultiNoDup::<B>::prove(prover, multi_col_no_dup_prover_input)?;
        // let multi_col_no_dup_prover_input = BezoutBasedMultiNoDupProverInput {
        //     tracked_table: prover_input.supp_tracked_table.clone(),
        //     contig_lex_sorted_tracked_table: prover_input
        //         .contig_lex_sorted_supp_tracked_table
        //         .clone(),
        //     tie_indicator_tracked_table:
        // prover_input.tie_indicator_tracked_table.clone(),
        //     shift_tracked_table: prover_input
        //         .shifted_contig_lex_sorted_supp_tracked_table
        //         .clone(),
        // };

        // BezoutBasedMultiNoDup::<B>::prove(prover,
        // multi_col_no_dup_prover_input)?;
        let multi_col_supp_check_prover_output = MultiColSuppCheckProverOutput {
            orig_folded_tracked_col: orig_table_folded_col,
            supp_folded_tracked_col: supp_table_folded_col,
        };
        Ok(multi_col_supp_check_prover_output)
    }

    fn verify_inner(
        verifier: &mut ArgVerifier<B>,
        verifier_input: Self::VerifierInput,
    ) -> SnarkResult<Self::VerifierOutput> {
        let table_folding_challs = (0..verifier_input
            .orig_tracked_table_oracle
            .num_data_tracked_col_oracles())
            .map(|_| verifier.get_and_append_challenge(b"a").unwrap())
            .collect::<Vec<B::F>>();

        let orig_table_folded_col = verifier_input
            .orig_tracked_table_oracle
            .fold_all_data_oracles(&table_folding_challs);

        let supp_table_folded_col = verifier_input
            .supp_tracked_table_oracle
            .fold_all_data_oracles(&table_folding_challs);

        let multicol_lookup_verifier_input = HintedLookupVerifierInput {
            included_tracked_col_oracles: vec![orig_table_folded_col.clone()],
            super_tracked_col_oracle: supp_table_folded_col.clone(),
            super_col_multiplicities: vec![verifier_input.multiplicity.clone()],
        };

        HintedLookupPIOP::<B>::verify(verifier, multicol_lookup_verifier_input)?;

        let supp_no_dups_checker = TrackedColOracle::new(
            verifier_input.multiplicity.clone(),
            verifier_input
                .supp_tracked_table_oracle
                .activator_tracked_poly(),
            None,
        );
        let no_zeros_check_verifier_input = NoZerosCheckVerifierInput {
            tracked_col_oracle: supp_no_dups_checker,
        };
        NoZerosCheck::<B>::verify(verifier, no_zeros_check_verifier_input)?;

        let multi_col_no_dup_verifier_input = SortBasedMultiNoDupVerifierInput {
            tracked_table_oracle: verifier_input.supp_tracked_table_oracle.clone(),
            contig_lex_sorted_tracked_table_oracle: verifier_input
                .contig_lex_sorted_supp_tracked_table_oracle
                .clone(),
            tie_indicator_tracked_table_oracle: verifier_input
                .tie_indicator_tracked_table_oracle
                .clone(),
            shift_tracked_table_oracle: verifier_input
                .shifted_contig_lex_sorted_supp_tracked_table_oracle
                .clone(),
        };

        SortBasedMultiNoDup::<B>::verify(verifier, multi_col_no_dup_verifier_input.clone())?;

        // let multi_col_no_dup_verifier_input = BezoutBasedMultiNoDupVerifierInput {
        //     tracked_table_oracle: verifier_input.supp_tracked_table_oracle.clone(),
        //     contig_lex_sorted_tracked_table_oracle: verifier_input
        //         .contig_lex_sorted_supp_tracked_table_oracle
        //         .clone(),
        //     tie_indicator_tracked_table_oracle: verifier_input
        //         .tie_indicator_tracked_table_oracle
        //         .clone(),
        //     shift_tracked_table_oracle: verifier_input
        //         .shifted_contig_lex_sorted_supp_tracked_table_oracle
        //         .clone(),
        // };

        // BezoutBasedMultiNoDup::<B>::verify(
        //     verifier,
        //     multi_col_no_dup_verifier_input,
        // )?;

        let multi_col_supp_check_verifier_output = MultiColSuppCheckVerifierOutput {
            orig_folded_tracked_col_oracle: orig_table_folded_col,
            supp_folded_tracked_col_oracle: supp_table_folded_col,
        };
        Ok(multi_col_supp_check_verifier_output)
    }
}
