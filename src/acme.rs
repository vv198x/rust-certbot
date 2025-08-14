use anyhow::Result;
use acme_lib::persist::FilePersist;
use acme_lib::{Account, Directory, DirectoryUrl};
use std::path::PathBuf;

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

		let mut persist_dir = PathBuf::from(
			cfg.certificates
				.path
				.clone(),
		);
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