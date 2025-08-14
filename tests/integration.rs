use actix_web::{test, web, App};
use rust_certbot::config::AppConfig;
use rust_certbot::routes::{health, version, acme_challenge};

fn sample_config() -> AppConfig {
	let cfg_toml = r#"
[server]
host = "127.0.0.1"
port = 0

[[domains]]
name = "example.com"
webroot = "./web"

[acme]
provider = "lets-encrypt"
email = "admin@example.com"
staging = true

[certificates]
path = "./cert"
backup_path = "./backups"
renewal_threshold_days = 30

[proxy]
enabled = false

[logging]
level = "info"
"#;
	let cfg: AppConfig = toml::from_str(cfg_toml).unwrap();
	cfg
}

#[actix_web::test]
async fn test_health_and_version() {
	let cfg = sample_config();
	let app = test::init_service(
		App::new()
			.app_data(web::Data::new(cfg))
			.service(health)
			.service(version)
	).await;

	let req = test::TestRequest::get().uri("/health").to_request();
	let resp = test::call_service(&app, req).await;
	assert!(resp.status().is_success());

	let req = test::TestRequest::get().uri("/version").to_request();
	let resp = test::call_service(&app, req).await;
	assert!(resp.status().is_success());
}

#[actix_web::test]
async fn test_acme_challenge_path() {
	std::fs::create_dir_all("./web/.well-known/acme-challenge").unwrap();
	std::fs::write("./web/.well-known/acme-challenge/token123", b"proof").unwrap();

	let cfg = sample_config();
	let app = test::init_service(
		App::new()
			.app_data(web::Data::new(cfg))
			.route("/.well-known/acme-challenge/{token}", web::get().to(acme_challenge))
	).await;

	let req = test::TestRequest::get().uri("/.well-known/acme-challenge/token123").to_request();
	let resp = test::call_service(&app, req).await;
	assert!(resp.status().is_success());
}