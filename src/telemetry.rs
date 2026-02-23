use anyhow::{Context, Result};
use traxer::{Config, Policy};

pub fn init_logging() -> Result<()> {
    let level = std::env::var("WSX_LOG")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "info".to_string());

    let cfg = Config::new("wsx")
        .policy(Policy::default_auto())
        .with_filter_directives(level);

    traxer::try_init(cfg).context("failed to initialize traxer logging")
}
