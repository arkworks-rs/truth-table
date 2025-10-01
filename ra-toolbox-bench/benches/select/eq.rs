use crate::{exec_custom_query, prepare_table, F, K, P};
use arithmetic::table::{ArithTable, ArithTableOracle};
use ark_piop::{piop::PIOP, prover::Prover, test_utils::bench_prelude, verifier::Verifier};
use sql_toolbox::select::{
    structs::{SelectConfig, SelectProverInput, SelectVerifierInput, WhereClause},
    SelectCheckPIOP,
};
use tokio::runtime::Runtime;
use std::sync::Arc;

const TABLE_QUERY: &str = "SELECT PRODUCTION_YEAR, ID FROM 'parquets/title-sanitized.parquet'";
const AUX_QUERY: &str = "SELECT CASE WHEN PRODUCTION_YEAR = 2000 THEN 1 ELSE 0 END AS SELECTED FROM 'parquets/title-sanitized.parquet';";

#[allow(clippy::type_complexity)]
fn prepare_prover_inputs() -> (
    Prover<F, P, K>,
    Verifier<F, P, K>,
    ArithTable<F, P, K>,
    ArithTable<F, P, K>,
    SelectProverInput<F, P, K>,
) {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let (mut prover, verifier) = bench_prelude::<F, P, K>().unwrap();
        let table = prepare_table(TABLE_QUERY, &mut prover).await;

        let aux_table = exec_custom_query(AUX_QUERY, &mut prover, false).await;

        let select_conf = SelectConfig {
            where_clause: WhereClause::Eq(0, F::from(2000u64)),
        };

        let mut output_cols: Vec<_> = table
            .columns()
            .map(|(field, poly)| (field.clone(), poly.clone()))
            .collect();
        if let Some(actv_poly) = aux_table.data_polys().first() {
            output_cols.push((
                Arc::new(datafusion::arrow::datatypes::Field::new(
                    "activator",
                    datafusion::arrow::datatypes::DataType::Boolean,
                    true,
                )),
                actv_poly.clone(),
            ));
        }
        let output_table = ArithTable::new(table.schema(), output_cols, table.size());
        let prover_input = SelectProverInput {
            input_table: table.clone(),
            output_table: output_table.clone(),
            select_conf: select_conf.clone(),
        };

        Ok::<_, anyhow::Error>((prover, verifier, table, output_table, prover_input))
    })
    .unwrap()
}

// ------------------------
// Verifier Input Preparation
// ------------------------

fn prepare_verifier_inputs() -> (Verifier<F, P, K>, SelectVerifierInput<F, P, K>) {
    let (mut prover, mut verifier, input_table, output_table, prover_input) =
        prepare_prover_inputs();
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        // Generate proof
        SelectCheckPIOP::<F, P, K>::prove(&mut prover, prover_input.clone())?;
        let proof = prover.build_proof().unwrap();
        verifier.set_proof(proof);

        // Commit tables
        let input_arith_table_oracle = ArithTableOracle::from(input_table, &mut verifier)?;
        let output_actv = output_table
            .actvtr_poly()
            .map(|actv| verifier.track_mv_com_by_id(actv.id()).unwrap());

        let mut output_oracles = input_arith_table_oracle.data_oracles();
        if let Some(activator_oracle) = output_actv {
            let activator_field = input_arith_table_oracle
                .schema()
                .as_ref()
                .and_then(|schema| {
                    schema
                        .fields()
                        .iter()
                        .find(|field| field.name() == "activator")
                        .cloned()
                })
                .unwrap_or_else(|| {
                    Arc::new(datafusion::arrow::datatypes::Field::new(
                        "activator",
                        datafusion::arrow::datatypes::DataType::Boolean,
                        true,
                    ))
                });
            output_oracles.insert(activator_field, activator_oracle);
        }

        let output_arith_table_oracle = ArithTableOracle::new(
            input_arith_table_oracle.schema(),
            output_oracles,
            None,
            input_arith_table_oracle.log_size(),
        );

        let verifier_input = SelectVerifierInput {
            input_arith_table_oracle,
            output_arith_table_oracle,
            select_conf: prover_input.select_conf,
        };

        Ok::<_, anyhow::Error>((verifier, verifier_input))
    })
    .unwrap()
}

// ------------------------
// Benchmarks
// ------------------------

#[divan::bench(sample_count = 1, sample_size = 1)]
fn prove(bencher: divan::Bencher) {
    bencher.with_inputs(prepare_prover_inputs).bench_values(
        |(mut prover, _, _, _, prover_input)| {
            SelectCheckPIOP::<F, P, K>::prove(&mut prover, prover_input).unwrap();
            prover.build_proof().unwrap();
        },
    );
}

#[divan::bench(max_time = 1)]
fn verify(bencher: divan::Bencher) {
    bencher
        .with_inputs(prepare_verifier_inputs)
        .bench_values(|(mut verifier, verifier_input)| {
            SelectCheckPIOP::<F, P, K>::verify(&mut verifier, verifier_input).unwrap();
            verifier.verify().unwrap();
        });
}
