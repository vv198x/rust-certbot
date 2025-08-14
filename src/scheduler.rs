use anyhow::Result;
use chrono::{Duration, Utc};
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{error, info};

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

async fn check_and_renew(cfg: &AppConfig) -> Result<()> {
	for domain in &cfg.domains {
		// TODO: Inspect current cert expiry date from filesystem; here we just log intent
		let now = Utc::now();
		let renew_after = now + Duration::days(cfg.certificates.renewal_threshold_days);
		info!("Would check domain {} for expiry before {}", domain.name, renew_after);
	}
	Ok(())
}