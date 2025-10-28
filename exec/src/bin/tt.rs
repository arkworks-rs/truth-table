use anyhow::Result;
use clap::{
    Parser, Subcommand,
    builder::styling::{AnsiColor, Effects, Styles},
};

use exec::cmd::{self, Runnable, TimedCommand};

fn cli_styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::Cyan.on_default() | Effects::BOLD)
        .usage(AnsiColor::Cyan.on_default() | Effects::BOLD)
        .literal(AnsiColor::Green.on_default())
        .placeholder(AnsiColor::Yellow.on_default())
}

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

#[derive(Subcommand)]
enum Commands {
    Setup(cmd::setup::Setup),
    Commit(cmd::commit::Commit),
    Prove(cmd::prove::Prove),
    Verify(cmd::verify::Verify),
}

async fn dispatch<C>(cmd: C) -> Result<()>
where
    C: Runnable + TimedCommand + Send,
{
    let timed = cmd.is_timed();
    let mut cmd = Some(cmd);
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

    match cli.command {
        Commands::Setup(cmd) => dispatch(cmd).await?,
        Commands::Commit(cmd) => dispatch(cmd).await?,
        Commands::Prove(cmd) => dispatch(cmd).await?,
        Commands::Verify(cmd) => dispatch(cmd).await?,
    }

    Ok(())
}
