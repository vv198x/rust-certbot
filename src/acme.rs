use anyhow::{anyhow, Context, Result};
use acme_lib::persist::FilePersist;
use acme_lib::{create_p384_key, Account, Directory, DirectoryUrl};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::config::{AppConfig, DomainConfig};

pub struct AcmeClient {
	pub account: Account<FilePersist>,
}

impl AcmeClient {
	pub fn new(cfg: &AppConfig) -> Result<Self> {
		let dir_url = if cfg.acme.staging {
			DirectoryUrl::LetsEncryptStaging
		} else {
			DirectoryUrl::LetsEncrypt
		};

		let mut persist_dir = PathBuf::from(cfg.certificates.path.clone());
		persist_dir.push("acme-account");
		let persist = FilePersist::new(persist_dir);
		let dir = Directory::from_url(persist, dir_url)?;
		let account = dir.account(&cfg.acme.email)?;
		Ok(Self { account })
	}

	pub fn create_http01_order(&self, domain: &DomainConfig) -> Result<()> {
		let _order = self.account.new_order(&domain.name, &[])?;
		Ok(())
	}
}

fn ensure_dir(path: &Path) -> Result<()> {
	fs::create_dir_all(path).with_context(|| format!("Failed to create dir {}", path.display()))?;
	Ok(())
}

fn write_atomically(path: &Path, content: &[u8], mode: Option<u32>) -> Result<()> {
	let parent = path.parent().ok_or_else(|| anyhow!("No parent for {}", path.display()))?;
	ensure_dir(parent)?;
	let tmp_path = parent.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
	{
		let mut f = fs::File::create(&tmp_path)?;
		f.write_all(content)?;
	}
	if let Some(m) = mode {
		let mut perms = fs::metadata(&tmp_path)?.permissions();
		perms.set_mode(m);
		fs::set_permissions(&tmp_path, perms)?;
	}
	fs::rename(&tmp_path, path)?;
	Ok(())
}

fn timestamp_dir_name() -> String {
	chrono::Utc::now().format("%Y%m%d%H%M%S").to_string()
}

fn backup_existing_cert_files(cfg: &AppConfig, domain: &str) -> Result<()> {
	let domain_dir = PathBuf::from(&cfg.certificates.path).join(domain);
	let fullchain_path = domain_dir.join("fullchain.pem");
	let chain_path = domain_dir.join("chain.pem");
	let key_path = domain_dir.join("privkey.pem");

	let backup_base = PathBuf::from(&cfg.certificates.backup_path)
		.join(domain)
		.join(timestamp_dir_name());
	ensure_dir(&backup_base)?;

	let mut copied_any = false;
	for (src, name) in [
		(fullchain_path.as_path(), "fullchain.pem"),
		(chain_path.as_path(), "chain.pem"),
		(key_path.as_path(), "privkey.pem"),
	] {
		if src.exists() {
			let dst = backup_base.join(name);
			fs::copy(src, &dst)
				.with_context(|| format!("Failed to backup {} to {}", src.display(), dst.display()))?;
			copied_any = true;
		}
	}
	if copied_any {
		info!("Created backup for {} at {}", domain, backup_base.display());
	}
	Ok(())
}

pub fn issue_http01_for_domain(cfg: &AppConfig, domain_name: &str) -> Result<()> {
	let domain_cfg = cfg
		.domains
		.iter()
		.find(|d| d.name == domain_name)
		.cloned()
		.ok_or_else(|| anyhow!("Domain {} not found in config", domain_name))?;

	let client = AcmeClient::new(cfg)?;
	let mut ord_new = client.account.new_order(&domain_cfg.name, &[])?;

	// Loop validations
	let ord_csr = loop {
		if let Some(ord_csr) = ord_new.confirm_validations() {
			break ord_csr;
		}

		let auths = ord_new.authorizations()?;
		if auths.is_empty() {
			return Err(anyhow!("No authorizations returned for {}", domain_cfg.name));
		}
		let chall = auths[0].http_challenge();
		let token = chall.http_token();
		let proof = chall.http_proof();
		// Write challenge file under webroot/.well-known/acme-challenge
		let mut path = PathBuf::from(&domain_cfg.webroot);
		path.push(".well-known");
		path.push("acme-challenge");
		path.push(token);
		write_atomically(&path, proof.as_bytes(), Some(0o644))?;
		info!("Wrote HTTP-01 challenge for {} at {}", domain_cfg.name, path.display());
		chall.validate(5000)?;
		ord_new.refresh()?;
	};

	let pkey_pri = create_p384_key();
	let ord_cert = ord_csr.finalize_pkey(pkey_pri, 5000)?;
	let cert = ord_cert.download_and_save_cert()?;

	// Backup current certs if present
	backup_existing_cert_files(cfg, &domain_cfg.name)?;

	let domain_dir = PathBuf::from(&cfg.certificates.path).join(&domain_cfg.name);
	ensure_dir(&domain_dir)?;
	let fullchain_path = domain_dir.join("fullchain.pem");
	let chain_path = domain_dir.join("chain.pem");
	let key_path = domain_dir.join("privkey.pem");

	write_atomically(&fullchain_path, cert.certificate().as_bytes(), Some(0o644))?;
	// acme-lib Certificate does not expose separate chain; store same as certificate for now
	write_atomically(&chain_path, cert.certificate().as_bytes(), Some(0o644))?;
	write_atomically(&key_path, cert.private_key().as_bytes(), Some(0o600))?;

	info!("Issued and saved certificate for {} in {}", domain_cfg.name, domain_dir.display());
	Ok(())
}