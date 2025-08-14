use std::fs;
use std::path::PathBuf;

use crate::config::AppConfig;

pub fn cert_paths_for_host(cfg: &AppConfig, host: &str) -> Option<(PathBuf, PathBuf, PathBuf)> {
	let domain = cfg.domains.iter().find(|d| d.name == host)?;
	let dir = PathBuf::from(&cfg.certificates.path).join(&domain.name);
	Some((dir.join("fullchain.pem"), dir.join("chain.pem"), dir.join("privkey.pem")))
}

pub fn renewal_date_header_for_host(cfg: &AppConfig, host: &str) -> String {
	if let Some((fullchain, _chain, _key)) = cert_paths_for_host(cfg, host) {
		if let Ok(pem) = fs::read_to_string(&fullchain) {
			if let Some(date) = not_after_date_str(&pem) {
				return date;
			}
		}
	}
	"-".to_string()
}

fn not_after_date_str(cert_pem: &str) -> Option<String> {
	use openssl::x509::X509;
	let x509 = X509::from_pem(cert_pem.as_bytes()).ok()?;
	let not_after = x509.not_after();
	let s = format!("{}", not_after);
	let tm = time::strptime(&s, "%h %e %H:%M:%S %Y %Z").ok()?;
	Some(time::strftime("%Y-%m-%d", &tm).ok()?)
}

pub fn days_left_for_host(cfg: &AppConfig, host: &str) -> Option<i64> {
	if let Some((fullchain, _chain, _key)) = cert_paths_for_host(cfg, host) {
		if let Ok(pem) = fs::read_to_string(&fullchain) {
			return days_left_from_pem(&pem);
		}
	}
	None
}

pub fn days_left_from_pem(cert_pem: &str) -> Option<i64> {
	use openssl::x509::X509;
	let x509 = X509::from_pem(cert_pem.as_bytes()).ok()?;
	let not_after = x509.not_after();
	let s = format!("{}", not_after);
	let tm = time::strptime(&s, "%h %e %H:%M:%S %Y %Z").ok()?;
	let expires_str = time::strftime("%Y-%m-%d %H:%M:%S", &tm).ok()?;
	let expires = chrono::NaiveDateTime::parse_from_str(&expires_str, "%Y-%m-%d %H:%M:%S").ok()?;
	let now = chrono::Utc::now().naive_utc();
	Some((expires - now).num_days())
}