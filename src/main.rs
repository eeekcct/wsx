mod cli;
mod commands;
mod config;
mod env;
mod logs;
mod paths;
mod process;
mod state;
mod telemetry;

fn main() {
    if let Err(err) = telemetry::init_logging().and_then(|()| cli::run()) {
        if traxer::is_initialized() {
            traxer::error!("Error: {err:#}");
        } else {
            eprintln!("Error: {err:#}");
        }
        std::process::exit(1);
    }
}
