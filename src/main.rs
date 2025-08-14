use actix_web::{web, App, HttpServer};
use anyhow::Context;
use rust_certbot::config;
use rust_certbot::routes::{acme_challenge, health, version};
use rust_certbot::scheduler;
use std::env;
use std::time::Duration;
use tokio::signal;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
	// Logging / tracing setup
	let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
	tracing_subscriber::fmt().with_env_filter(env_filter).init();

	let config_path = env::var("RUST_CERTBOT_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
	let app_config = config::AppConfig::load_from_path(&config_path)
		.with_context(|| format!("Failed to load config from {}", config_path))?;
	info!("Starting rust-certbot {} on {}", env!("CARGO_PKG_VERSION"), app_config.address());

	let data_cfg = web::Data::new(app_config.clone());

	let server = HttpServer::new(move || {
		App::new()
			.app_data(data_cfg.clone())
			.service(health)
			.service(version)
			.route(
				"/.well-known/acme-challenge/{token}",
				web::get().to(acme_challenge),
			)
	})
	.bind(app_config.address())?
	.shutdown_timeout(5)
	.worker_max_blocking_threads(4)
	.run();

	// Start scheduler in background
	let _sched = scheduler::start_scheduler(app_config.clone()).await?;

	// Graceful shutdown with Ctrl+C
	let srv_handle = server.handle();
	tokio::spawn(async move {
		if let Err(err) = signal::ctrl_c().await {
			error!("Failed to listen for Ctrl+C: {}", err);
			return;
		}
		info!("Received shutdown signal, stopping server...");
		srv_handle.stop(true).await;
	});

	server.await?;
	// Allow some time for cleanup
	tokio::time::sleep(Duration::from_millis(200)).await;
	Ok(())
}