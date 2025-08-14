use anyhow::{bail, Context, Result};
use regex::Regex;
use std::fs;
use std::path::Path;

use crate::config::{AppConfig, DomainConfig};

fn is_valid_domain(name: &str) -> bool {
	// Basic FQDN regex
	let re = Regex::new(r"^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+[A-Za-z]{2,}$").unwrap();
	re.is_match(name)
}

fn validate_domain(cfg: &AppConfig, d: &DomainConfig) -> Result<()> {
	if !is_valid_domain(&d.name) {
		bail!("Invalid domain name: {}", d.name);
	}
	let webroot = Path::new(&d.webroot);
	if !webroot.exists() {
		bail!("Webroot does not exist for {}: {}", d.name, d.webroot);
	}
	if let Some(ref proxy) = d.proxy {
		let parsed = url::Url::parse(proxy)
			.with_context(|| format!("Invalid proxy URL for {}: {}", d.name, proxy))?;
		if parsed.scheme() != "http" && parsed.scheme() != "https" {
			bail!("Unsupported proxy scheme for {}: {}", d.name, parsed.scheme());
		}
	}
	Ok(())
}

pub fn validate_config(cfg: &AppConfig) -> Result<()> {
	if cfg.domains.is_empty() {
		bail!("No domains configured");
	}
	for d in &cfg.domains {
		validate_domain(cfg, d)?;
	}
	Ok(())
}