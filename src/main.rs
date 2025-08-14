use actix_web::{web, App, HttpServer};
use anyhow::Context;
use rust_certbot::config;
use rust_certbot::routes::{acme_challenge, health, version};
use rust_certbot::scheduler;
use rust_certbot::validation;
use std::env;
use std::time::Duration;
use tokio::signal;
use tracing::{error, info, Level};
use tracing_subscriber::EnvFilter;

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
	let config_path = env::var("RUST_CERTBOT_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
	let app_config = config::AppConfig::load_from_path(&config_path)
		.with_context(|| format!("Failed to load config from {}", config_path))?;

	// Ensure directories exist
	std::fs::create_dir_all(&app_config.certificates.path).ok();
	std::fs::create_dir_all(&app_config.certificates.backup_path).ok();
	for d in &app_config.domains {
		let p = std::path::Path::new(&d.webroot).join(".well-known").join("acme-challenge");
		std::fs::create_dir_all(p).ok();
	}

	// Logging setup: file if configured, else stdout
	let level = app_config.logging.level.clone();
	let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
	if let Some(ref logfile) = app_config.logging.file {
		let (dir, file) = match std::path::Path::new(logfile).parent() {
			Some(p) if p.to_string_lossy().len() > 0 => (p.to_path_buf(), std::path::Path::new(logfile).file_name().unwrap().to_os_string()),
			_ => (std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")), std::ffi::OsString::from(logfile)),
		};
		let _ = std::fs::create_dir_all(&dir);
		let file_appender = tracing_appender::rolling::never(dir, file);
		let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
		tracing_subscriber::fmt()
			.with_env_filter(env_filter)
			.with_writer(non_blocking)
			.init();
	} else {
		tracing_subscriber::fmt().with_env_filter(env_filter).init();
	}

	// Validate configuration
	validation::validate_config(&app_config)?;

	info!("Starting rust-certbot {} on {}", env!("CARGO_PKG_VERSION"), app_config.address());

	let data_cfg = web::Data::new(app_config.clone());
	let enable_proxy = app_config.proxy.enabled;
	let proxy_cfg = app_config.clone();

	let server = HttpServer::new(move || {
		let mut app = App::new()
			.app_data(data_cfg.clone())
			.service(health)
			.service(version)
			.service(rust_certbot::routes::metrics)
			.service(rust_certbot::routes::ready)
			.service(rust_certbot::routes::live)
			.service(rust_certbot::routes::domains)
			.route(
				"/.well-known/acme-challenge/{token}",
				web::get().to(acme_challenge),
			)
			.route(
				"/admin/issue",
				web::post().to(rust_certbot::routes::issue_now),
			);
		if enable_proxy {
			app = app.service(rust_certbot::proxy::proxy_service(proxy_cfg.clone()));
		}
		app
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