use clap::Parser;
use datafusion::prelude::{ParquetReadOptions, SessionContext};
use duckdb::Connection;
use std::{env, path::PathBuf, str::FromStr};

#[derive(Parser, Debug)]
#[command(
    name = "run_tpch",
    about = "Print TPC-H SQL (and optional DataFusion logical plan)"
)]
struct Cli {
    /// Query number 1..22 or the string "all"
    which: String,

    /// Also print the DataFusion logical plan (requires Parquet files)
    #[arg(long)]
    plan: bool,

    /// Also print the Treeviz DOT for the logical plan
    #[arg(long)]
    treeviz: bool,

    /// Directory containing TPC-H parquet files (nation.parquet,
    /// region.parquet, ...) If omitted and --plan is set, tries
    /// tpch-data/test-data then tpch-data/bench-data
    #[arg(long)]
    data_dir: Option<PathBuf>,
}

fn duckdb_fetch(qnum: Option<u8>) -> Option<Vec<(i64, String)>> {
    let conn = Connection::open_in_memory().ok()?;
    conn.execute("INSTALL tpch", []).ok()?;
    conn.execute("LOAD tpch", []).ok()?;
    if let Some(n) = qnum {
        let mut stmt = conn
            .prepare("SELECT query_nr, query FROM tpch_queries() WHERE query_nr = ?")
            .ok()?;
        let mut rows = stmt.query([n as i64]).ok()?;
        let mut out = Vec::new();
        while let Ok(Some(row)) = rows.next() {
            let nr: i64 = row.get(0).ok()?;
            let sql: String = row.get(1).ok()?;
            out.push((nr, sql));
        }
        if out.is_empty() { None } else { Some(out) }
    } else {
        let mut stmt = conn.prepare("FROM tpch_queries() ORDER BY query_nr").ok()?;
        let mut rows = stmt.query([]).ok()?;
        let mut out = Vec::new();
        while let Ok(Some(row)) = rows.next() {
            let nr: i64 = row.get(0).ok()?;
            let sql: String = row.get(1).ok()?;
            out.push((nr, sql));
        }
        if out.is_empty() { None } else { Some(out) }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let first = cli.which.clone();
    let want_plan = cli.plan || cli.treeviz; // treeviz implies planning
    let want_treeviz = cli.treeviz;
    let data_dir = cli.data_dir.clone();

    let infer_data_dir = || -> PathBuf {
        if let Some(d) = data_dir.clone() {
            return d;
        }
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let td = base.join("test-data");
        if td.exists() {
            td
        } else {
            base.join("bench-data")
        }
    };

    if first.eq_ignore_ascii_case("all") {
        let queries = duckdb_fetch(None).unwrap_or_else(|| {
            eprintln!("DuckDB TPCH extension not available.");
            std::process::exit(1)
        });
        if !want_plan {
            for (nr, sql) in queries {
                println!("-- Q{}\n{}\n", nr, sql);
            }
            return;
        }
        // With plan: set up DataFusion and print both SQL and logical plan
        let dir = infer_data_dir();
        let ctx = SessionContext::new();
        for (name, file) in [
            ("nation", dir.join("nation.parquet")),
            ("region", dir.join("region.parquet")),
            ("part", dir.join("part.parquet")),
            ("supplier", dir.join("supplier.parquet")),
            ("partsupp", dir.join("partsupp.parquet")),
            ("customer", dir.join("customer.parquet")),
            ("orders", dir.join("orders.parquet")),
            ("lineitem", dir.join("lineitem.parquet")),
        ] {
            if !file.exists() {
                eprintln!(
                    "Missing table {} at {} (required for --plan)",
                    name,
                    file.display()
                );
                std::process::exit(1);
            }
            ctx.register_parquet(name, file.to_str().unwrap(), ParquetReadOptions::default())
                .await
                .expect("register parquet");
        }
        for (nr, sql) in queries {
            println!("-- Q{}\n{}\n", nr, sql);
            let plan = ctx.state().create_logical_plan(&sql).await.unwrap();
            if cli.plan {
                println!("-- Q{} Logical Plan\n{}\n", nr, plan.display_indent());
            }
            if want_treeviz {
                println!("-- Q{} Treeviz DOT\n{}\n", nr, plan.display_graphviz());
            }
        }
        return;
    }

    // Single query number path
    let qnum = match u8::from_str(&first) {
        Ok(n) if (1..=22).contains(&n) => n,
        _ => {
            eprintln!("Usage: run_tpch <1..22>|all [--plan] [--data-dir DIR]");
            std::process::exit(2)
        }
    };
    let rows = duckdb_fetch(Some(qnum)).unwrap_or_else(|| {
        eprintln!("DuckDB TPCH extension not available.");
        std::process::exit(1)
    });
    let (_nr, sql) = rows.into_iter().next().expect("query present");
    if !want_plan {
        // Print only SQL for single query
        println!("{}", sql);
        return;
    }

    let dir = infer_data_dir();
    let ctx = SessionContext::new();
    for (name, file) in [
        ("nation", dir.join("nation.parquet")),
        ("region", dir.join("region.parquet")),
        ("part", dir.join("part.parquet")),
        ("supplier", dir.join("supplier.parquet")),
        ("partsupp", dir.join("partsupp.parquet")),
        ("customer", dir.join("customer.parquet")),
        ("orders", dir.join("orders.parquet")),
        ("lineitem", dir.join("lineitem.parquet")),
    ] {
        if !file.exists() {
            eprintln!(
                "Missing table {} at {} (required for --plan)",
                name,
                file.display()
            );
            std::process::exit(1);
        }
        ctx.register_parquet(name, file.to_str().unwrap(), ParquetReadOptions::default())
            .await
            .expect("register parquet");
    }
    let plan = ctx.state().create_logical_plan(&sql).await.unwrap();
    if cli.plan {
        println!("{}\n-- Logical Plan\n{}", sql, plan.display_indent());
    } else {
        // Still print SQL above if only treeviz was requested
        println!("{}", sql);
    }
    if want_treeviz {
        println!("\n-- Treeviz DOT\n{}", plan.display_graphviz());
    }
}
