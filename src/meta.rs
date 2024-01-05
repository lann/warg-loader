use anyhow::Context;
use reqwest::StatusCode;
use serde::Deserialize;

use crate::Error;

const WELL_KNOWN_PATH: &str = ".well-known/warg/registry.json";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryMeta {
    pub oci_registry: Option<String>,
}

impl RegistryMeta {
    pub async fn fetch(domain: &str) -> Result<Option<Self>, Error> {
        let url = format!("https://{domain}/{WELL_KNOWN_PATH}");
        Self::fetch_url(&url)
            .await
            .with_context(|| format!("error fetching registry metadata from {url:?}"))
            .map_err(Error::RegistryMeta)
    }

    async fn fetch_url(url: &str) -> anyhow::Result<Option<Self>> {
        tracing::debug!("Fetching registry metadata from {url:?}");
        let resp = reqwest::get(url).await?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = resp.error_for_status()?;
        Ok(Some(resp.json().await?))
    }
}
