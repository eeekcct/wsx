mod cli;
mod commands;
mod config;
mod env;
mod logs;
mod paths;
mod process;
mod state;

fn main() {
    if let Err(err) = cli::run() {
        eprintln!("Error: {err:#}");
        std::process::exit(1);
    }
}
