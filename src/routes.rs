use actix_files::NamedFile;
use actix_web::{get, web, HttpRequest, HttpResponse, Responder};
use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::config::AppConfig;
use crate::acme::issue_http01_for_domain;

#[derive(Serialize)]
pub struct VersionResponse {
	pub version: &'static str,
}

#[get("/health")]
pub async fn health() -> impl Responder {
	HttpResponse::Ok().finish()
}

#[get("/version")]
pub async fn version() -> impl Responder {
	let resp = VersionResponse { version: env!("CARGO_PKG_VERSION") };
	HttpResponse::Ok().json(resp)
}

#[get("/live")]
pub async fn live() -> impl Responder {
	HttpResponse::Ok().finish()
}

#[get("/domains")]
pub async fn domains(cfg: web::Data<AppConfig>) -> impl Responder {
	let items: Vec<_> = cfg
		.domains
		.iter()
		.map(|d| {
			let days_left = crate::cert_utils::days_left_for_host(&cfg, &d.name);
			serde_json::json!({
				"name": d.name,
				"webroot": d.webroot,
				"proxy": d.proxy,
				"days_left": days_left,
			})
		})
		.collect();
	HttpResponse::Ok().json(serde_json::json!({"domains": items}))
}

#[get("/metrics")]
pub async fn metrics(cfg: web::Data<AppConfig>) -> impl Responder {
	let mut body = String::from("rust_certbot_up 1\n");
	for d in &cfg.domains {
		if let Some(days) = crate::cert_utils::days_left_for_host(&cfg, &d.name) {
			body.push_str(&format!("rust_certbot_days_left{{domain=\"{}\"}} {}\n", d.name, days));
		}
	}
	HttpResponse::Ok().body(body)
}

#[get("/ready")]
pub async fn ready(cfg: web::Data<AppConfig>) -> impl Responder {
	let ok = !cfg.domains.is_empty();
	if ok { HttpResponse::Ok().finish() } else { HttpResponse::ServiceUnavailable().finish() }
}

pub async fn acme_challenge(
	path: web::Path<String>,
	cfg: web::Data<AppConfig>,
	req: HttpRequest,
) -> actix_web::Result<NamedFile> {
	let token = path.into_inner();
	// Try to resolve webroot by Host header, fallback to first domain
	let host = req
		.headers()
		.get("host")
		.and_then(|v| v.to_str().ok())
		.map(|s| s.split(':').next().unwrap_or(s))
		.map(|s| s.to_string());
	let webroot = host
		.as_deref()
		.and_then(|h| cfg.domains.iter().find(|d| d.name == h))
		.map(|d| d.webroot.clone())
		.or_else(|| cfg.domains.get(0).map(|d| d.webroot.clone()))
		.unwrap_or_else(|| "./web".to_string());
	let mut full_path = PathBuf::from(webroot);
	full_path.push(".well-known");
	full_path.push("acme-challenge");
	full_path.push(token);
	Ok(NamedFile::open(full_path)?)
}

#[derive(serde::Deserialize)]
pub struct IssueRequest {
	pub domain: String,
}

pub async fn issue_now(
	cfg: web::Data<AppConfig>,
	payload: web::Json<IssueRequest>,
) -> impl Responder {
	match issue_http01_for_domain(&cfg, &payload.domain) {
		Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status":"ok"})),
		Err(err) => HttpResponse::InternalServerError().json(serde_json::json!({"error": err.to_string()})),
	}
}