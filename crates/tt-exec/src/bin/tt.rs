use anyhow::Result;
use clap::{
    Parser, Subcommand,
    builder::styling::{AnsiColor, Effects, Styles},
};

use tt_exec::cmd::{self, Runnable, TimedCommand};

/// Define CLI styles
fn cli_styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::Cyan.on_default() | Effects::BOLD)
        .usage(AnsiColor::Cyan.on_default() | Effects::BOLD)
        .literal(AnsiColor::Green.on_default())
        .placeholder(AnsiColor::Yellow.on_default())
}

/// Truthtable CLI struct
#[derive(Parser)]
#[command(
    name = "tt",
    version,
    about = "TruthTable command line interface",
    styles = cli_styles()
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Truthtable CLI commands
#[derive(Subcommand)]
enum Commands {
    /// Generate proving/verifying keys
    Setup(cmd::setup::Setup),
    /// Commit a table to an oracle
    Commit(cmd::commit::Commit),
    /// Generate a proof for a query
    Prove(cmd::prove::Prove),
    /// Verify a proof for a query
    Verify(cmd::verify::Verify),
    /// Generate TPC-H Parquet data (for testing and benchmarking purposes)
    DataGen(cmd::data_gen::DataGen),
    /// Run a SQL query against Parquet files
    Query(cmd::query::Query),
}

/// Dispatch the truth table command
async fn dispatch<C>(cmd: C) -> Result<()>
where
    C: Runnable + TimedCommand + Send,
{
    let timed = cmd.is_timed();
    let mut cmd = Some(cmd);
    // Run the command with or without timing
    if timed {
        cmd.take()
            .expect("command already consumed")
            .run_timed()
            .await
    } else {
        cmd.take().expect("command already consumed").run().await
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // Dispatch based on the command
    match cli.command {
        Commands::Setup(cmd) => dispatch(cmd).await?,
        Commands::Commit(cmd) => dispatch(cmd).await?,
        Commands::Prove(cmd) => dispatch(cmd).await?,
        Commands::Verify(cmd) => dispatch(cmd).await?,
        Commands::DataGen(cmd) => dispatch(cmd).await?,
        Commands::Query(cmd) => dispatch(cmd).await?,
    }

    Ok(())
}
