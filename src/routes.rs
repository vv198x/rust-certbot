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