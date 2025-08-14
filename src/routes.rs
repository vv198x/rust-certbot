use actix_files::NamedFile;
use actix_web::{get, web, HttpResponse, Responder};
use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::config::AppConfig;

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
) -> actix_web::Result<NamedFile> {
	let token = path.into_inner();
	// Resolve to first domain's webroot or default ./web/letsencrypt
	let webroot = cfg
		.domains
		.get(0)
		.map(|d| d.webroot.clone())
		.unwrap_or_else(|| "./web/letsencrypt".to_string());
	// Token files are expected to be directly under .well-known/acme-challenge
	let mut full_path = PathBuf::from(webroot);
	let challenge_dir = Path::new(&full_path);
	if challenge_dir.is_dir() {
		// User may have provided root of web; ensure letsencrypt path
		full_path.push(".well-known");
		full_path.push("acme-challenge");
	}
	full_path.push(token);
	Ok(NamedFile::open(full_path)?)
}