use crate::{F, K, P, exec_custom_query, prepare_table};
use arithmetic::table::{ArithTable, TableComm};
use ark_piop::{
    errors::SnarkResult, piop::PIOP, prover::Prover, test_utils::bench_prelude, verifier::Verifier,
};
use datafusion::sql::sqlparser::ast::Table;
#[cfg(feature = "parallel")]
use rayon::result;
use sql_toolbox::select::{
    SelectCheckPIOP,
    structs::{SelectConfig, SelectProverInput, SelectVerifierInput, WhereClause},
};
use tokio::runtime::Runtime;

const TABLE_QUERY: &str = "SELECT PRODUCTION_YEAR, ID FROM 'imdb_parquet/title-sanitized.parquet'";
// const AUX_QUERY: &str = "SELECT PRODUCTION_YEAR, ID AS COUNT FROM
// 'imdb_parquet/title-sanitized.parquet' WHERE  PRODUCTION_YEAR=2000";
const AUX_QUERY: &str = "SELECT CASE WHEN PRODUCTION_YEAR >= 2000 THEN 1 ELSE 0 END AS SELECTED FROM 'imdb_parquet/title-sanitized.parquet';";

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
            where_clause: WhereClause::Geq(0, F::from(2000u64)),
        };

        let output_table = ArithTable::new(
            table.schema(),
            table.data_polys(),
            Some(aux_table.data_polys()[0].clone()),
            table.size(),
        );
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
        let input_table_comm = TableComm::from(input_table, &mut verifier);
        let output_actv = output_table
            .actvtr_poly()
            .map(|actv| verifier.track_mv_com_by_id(actv.get_id()).unwrap());

        let output_table_comm = TableComm::new(
            input_table_comm.schema(),
            input_table_comm.col_vals(),
            output_actv,
            input_table_comm.num_vars(),
        );

        let verifier_input = SelectVerifierInput {
            input_table_comm,
            output_table_comm,
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
