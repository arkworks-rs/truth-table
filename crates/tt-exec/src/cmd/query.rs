use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::Args;
use datafusion::{
    arrow::util::pretty::pretty_format_batches,
    prelude::{ParquetReadOptions, SessionContext},
};

use super::{
    Runnable,
    common::{ParquetArg, QueryArg},
};

#[derive(Args, Debug)]
pub struct Query {
    #[command(flatten)]
    pub query: QueryArg,

    #[command(flatten)]
    pub parquet: ParquetArg,

    /// Print how long the command takes to execute
    #[arg(long)]
    pub timed: bool,

    /// Print the logical plan as Graphviz DOT
    #[arg(long = "logical-plan-graphviz")]
    pub logical_plan_graphviz: bool,
}

#[async_trait::async_trait(?Send)]
impl Runnable for Query {
    async fn run(self) -> Result<()> {
        let sql = self.query.resolve_sql()?;
        let inputs = self.parquet.parquet.clone();

        if inputs.is_empty() {
            bail!("at least one --parquet-path must be supplied");
        }

        let parquet_files = expand_parquet_inputs(&inputs)?;
        execute_query(&parquet_files, &sql, self.logical_plan_graphviz).await
    }
}

impl super::TimedCommand for Query {
    fn is_timed(&self) -> bool {
        self.timed
    }
}

async fn execute_query(
    parquet_files: &[PathBuf],
    sql: &str,
    logical_plan_graphviz: bool,
) -> Result<()> {
    let ctx = SessionContext::new();
    let mut table_names = HashSet::new();

    for path in parquet_files {
        let table_name = path
            .file_stem()
            .context("parquet file must have a valid name")?
            .to_string_lossy()
            .to_string();
        if !table_names.insert(table_name.clone()) {
            bail!(
                "duplicate table name detected for {} – ensure filenames are unique",
                table_name
            );
        }

        ctx.register_parquet(
            &table_name,
            path.to_str().context("parquet path must be valid UTF-8")?,
            ParquetReadOptions::default(),
        )
        .await
        .with_context(|| format!("failed to register parquet {}", path.display()))?;
    }

    let plan = ctx
        .state()
        .create_logical_plan(sql)
        .await
        .context("failed to create logical plan")?;

    if logical_plan_graphviz {
        // Show the logical plan before execution for debugging.
        println!("{}", plan.display_graphviz());
    }

    let df = ctx
        .execute_logical_plan(plan)
        .await
        .context("failed to plan query")?;
    let batches = df.collect().await.context("failed to execute query")?;

    if batches.is_empty() {
        println!("Query returned 0 rows.");
    } else {
        let formatted = pretty_format_batches(&batches).context("failed to format query output")?;
        println!("{formatted}");
    }

    Ok(())
}

fn expand_parquet_inputs(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for raw in paths {
        let path = raw.canonicalize().with_context(|| {
            format!(
                "failed to canonicalize parquet input path {}",
                raw.display()
            )
        })?;

        if path.is_file() {
            files.push(path);
        } else if path.is_dir() {
            let mut found = false;
            let mut dir_entries =
                fs::read_dir(&path)?.collect::<std::result::Result<Vec<_>, _>>()?;
            dir_entries.sort_by_key(|entry| entry.path());
            for entry in dir_entries {
                let file_path = entry.path();
                if is_parquet_file(&file_path) {
                    files.push(file_path);
                    found = true;
                }
            }
            if !found {
                bail!(
                    "directory {} does not contain any .parquet files",
                    path.display()
                );
            }
        } else {
            bail!("parquet input path {} does not exist", path.display());
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

fn is_parquet_file(path: &Path) -> bool {
    path.is_file()
        && path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("parquet"))
            .unwrap_or(false)
}
