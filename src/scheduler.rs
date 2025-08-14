use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use std::fs;
use std::path::PathBuf;
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{error, info, warn};

use crate::acme::issue_http01_for_domain;
use crate::config::AppConfig;

pub async fn start_scheduler(cfg: AppConfig) -> Result<JobScheduler> {
	let scheduler = JobScheduler::new().await?;
	let threshold_days = cfg.certificates.renewal_threshold_days;

	let job = Job::new_async("0 0 */6 * * *", move |_uuid, _l| {
		let cfg = cfg.clone();
		Box::pin(async move {
			if let Err(err) = check_and_renew(&cfg).await {
				error!("Renewal job failed: {}", err);
			}
		})
	})?;

	scheduler.add(job).await?;
	scheduler.start().await?;
	info!("Scheduler started; renewal threshold {} days", threshold_days);
	Ok(scheduler)
}

fn read_cert_days_left(cert_pem: &str) -> Result<i64> {
	use openssl::x509::X509;
	let x509 = X509::from_pem(cert_pem.as_bytes()).context("Failed to parse PEM")?;
	let not_after = x509.not_after();
	// Convert ASN1_TIME to chrono by parsing string representation
	let s = format!("{}", not_after);
	let tm = time::strptime(&s, "%h %e %H:%M:%S %Y %Z").context("Failed to parse ASN1 time")?;
	let expires = chrono::NaiveDateTime::parse_from_str(
		&time::strftime("%Y-%m-%d %H:%M:%S", &tm).unwrap(),
		"%Y-%m-%d %H:%M:%S",
	)?;
	let now = Utc::now().naive_utc();
	let diff = expires - now;
	Ok(diff.num_days())
}

async fn check_and_renew(cfg: &AppConfig) -> Result<()> {
	for domain in &cfg.domains {
		let domain_dir = PathBuf::from(&cfg.certificates.path).join(&domain.name);
		let fullchain_path = domain_dir.join("fullchain.pem");
		if !fullchain_path.exists() {
			warn!("No certificate for {}, skipping expiry check", domain.name);
			continue;
		}
		let pem = fs::read_to_string(&fullchain_path)
			.with_context(|| format!("Failed to read {}", fullchain_path.display()))?;
		let days_left = read_cert_days_left(&pem).unwrap_or(-1);
		info!("{}: {} days left", domain.name, days_left);
		if days_left < cfg.certificates.renewal_threshold_days {
			info!("Renewing certificate for {} ({} days left < {})", domain.name, days_left, cfg.certificates.renewal_threshold_days);
			if let Err(err) = issue_http01_for_domain(cfg, &domain.name) {
				error!("Failed to renew {}: {}", domain.name, err);
			}
		}
	}
	Ok(())
}