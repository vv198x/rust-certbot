use actix_web::{dev::HttpServiceFactory, web, HttpRequest, HttpResponse};
use anyhow::Result;
use awc::Client;
use chrono::NaiveDate;
use std::time::Duration;
use tracing::info;

use crate::config::AppConfig;

fn renewal_header_for_domain(_cfg: &AppConfig, _host: &str) -> String {
	// Placeholder: could read from stored metadata or map
	"-".to_string()
}

pub fn proxy_service(cfg: AppConfig) -> impl HttpServiceFactory {
	let client = Client::builder()
		.timeout(Duration::from_secs(cfg.proxy.timeout.unwrap_or(30) as u64))
		.finish();
	let cfg_data = web::Data::new(cfg);

	actix_web::web::scope("")
		.app_data(cfg_data.clone())
		.default_service(web::to(move |req: HttpRequest, body: web::Bytes| {
			let client = client.clone();
			let cfg = cfg_data.clone();
			async move {
				let host = req
					.headers()
					.get("host")
					.and_then(|v| v.to_str().ok())
					.map(|s| s.split(':').next().unwrap_or(s))
					.unwrap_or("")
					.to_string();

				let domain_cfg = cfg
					.domains
					.iter()
					.find(|d| d.name == host)
					.cloned();
				if let Some(dc) = domain_cfg {
					if let Some(upstream) = dc.proxy.clone() {
						let path_q = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("");
						let url = format!("{}{}", upstream, path_q);
						let mut fwd = client.request_from(url, req.head()).no_decompress();
						for (h, v) in req.headers().iter() {
							if h.as_str().eq_ignore_ascii_case("host") { continue; }
							fwd = fwd.append_header((h.clone(), v.clone()));
						}
						let mut resp = fwd.send_body(body).await.map_err(|e| {
							actix_web::error::ErrorBadGateway(format!("Upstream error: {}", e))
						})?;
						let mut client_resp = HttpResponse::build(resp.status());
						for (h, v) in resp.headers() {
							client_resp.append_header((h.clone(), v.clone()));
						}
						client_resp.append_header(("X-Cert-Renewal", renewal_header_for_domain(&cfg, &host)));
						let bytes = resp.body().limit(10 * 1024 * 1024).await.map_err(|e| actix_web::error::ErrorBadGateway(format!("Read body error: {}", e)))?;
						return Ok::<_, actix_web::Error>(client_resp.body(bytes));
					}
				}
				Ok::<_, actix_web::Error>(HttpResponse::NotFound().finish())
			}
		}))
}