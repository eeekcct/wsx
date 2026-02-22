use anyhow::{Result, bail};
use clap::{Parser, Subcommand};

use crate::commands;

#[derive(Debug, Parser)]
#[command(
    version = env!("VERSION"),
    about = "Workspace switch executor",
    long_about = None,
    long_version = concat!(
        "version ",
        env!("VERSION"),
        "\n",
        "  commit: ",
        env!("COMMIT"),
        "\n",
        "  built at: ",
        env!("DATE"),
        "\n",
        "  rust version: ",
        env!("RUSTC_VERSION"),
        "\n",
        "  platform: ",
        env!("OS"),
        "/",
        env!("ARCH")
    )
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[arg(value_name = "workspace")]
    pub workspace: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    List,
    Up,
    Down,
    Logs {
        #[arg(value_name = "target")]
        target: Option<String>,

        #[arg(long)]
        lines: Option<usize>,

        #[arg(long = "no-follow", default_value_t = false)]
        no_follow: bool,
    },
    Exec {
        #[arg(value_name = "cmd", num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    Status,
    Select {
        #[arg(value_name = "target")]
        target: String,
    },
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    if cli.workspace.is_some() && cli.command.is_some() {
        bail!("workspace argument and subcommand cannot be used together")
    }

    commands::run(cli)
}
