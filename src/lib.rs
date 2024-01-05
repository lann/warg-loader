mod config;
mod label;
mod meta;
mod package;
mod release;
mod toml;

use std::collections::HashMap;

use bytes::Bytes;
use config::BasicCredentials;
use futures_util::{AsyncWrite, TryStream, TryStreamExt};
use oci_distribution::{
    errors::OciDistributionError, manifest::WASM_LAYER_MEDIA_TYPE, secrets::RegistryAuth,
    Reference as OciReference,
};
use secrecy::ExposeSecret;
pub use semver::Version;
use tokio_util::compat::FuturesAsyncWriteCompatExt;

/// Re-exported to ease configuration.
pub use oci_distribution::client as oci_client;

pub use crate::{
    config::ClientConfig,
    package::PackageRef,
    release::{ContentHash, Release},
};
use crate::{
    config::RegistryConfig,
    label::{InvalidLabel, Label},
    meta::RegistryMeta,
};

/// A read-only registry client.
pub struct Client {
    config: ClientConfig,
    oci_clients: HashMap<String, OciClient>,
}

struct OciClient {
    client: oci_distribution::Client,
    registry: String,
    credentials: Option<BasicCredentials>,
}

impl OciClient {
    fn auth(&self) -> RegistryAuth {
        match &self.credentials {
            Some(BasicCredentials { username, password }) => {
                RegistryAuth::Basic(username.clone(), password.expose_secret().clone())
            }
            None => RegistryAuth::Anonymous,
        }
    }
}

impl Client {
    /// Returns a new client with the given [`ClientConfig`].
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            oci_clients: Default::default(),
        }
    }

    /// Returns a new client configured from the default config file path.
    /// Returns Ok(None) if the default config file does not exist.
    pub fn from_default_config_file() -> Result<Option<Self>, Error> {
        Ok(ClientConfig::from_default_file()?.map(Self::new))
    }

    /// Returns a list of all package [`Version`]s available for the given package.
    pub async fn list_all_versions<Pkg>(&mut self, package: Pkg) -> Result<Vec<Version>, Error>
    where
        Pkg: TryInto<PackageRef>,
        Pkg::Error: Into<Error>,
    {
        let package = package.try_into().map_err(Into::into)?;
        let (oci_client, oci_ref) = self.resolve_oci_parts(&package, None).await?;

        tracing::debug!("Listing tags for OCI reference {oci_ref:?}");
        let resp = oci_client
            .client
            .list_tags(&oci_ref, &oci_client.auth(), None, None)
            .await?;
        tracing::trace!("List tags response: {resp:?}");

        // Return only tags that parse as valid semver versions.
        let versions = resp
            .tags
            .iter()
            .flat_map(|tag| match Version::parse(tag) {
                Ok(version) => Some(version),
                Err(err) => {
                    tracing::warn!("Ignoring invalid version tag {tag:?}: {err:?}");
                    None
                }
            })
            .collect();
        Ok(versions)
    }

    /// Returns a [`Release`] for the given package version.
    pub async fn get_release<Pkg>(
        &mut self,
        package: Pkg,
        version: impl IntoVersion,
    ) -> Result<Release, Error>
    where
        Pkg: TryInto<PackageRef>,
        Pkg::Error: Into<Error>,
    {
        let package = package.try_into().map_err(Into::into)?;
        let version = version.into_version()?;
        let (oci_client, oci_ref) = self.resolve_oci_parts(&package, Some(&version)).await?;

        tracing::debug!("Fetching image manifest for OCI reference {oci_ref:?}");
        let (manifest, _digest) = oci_client
            .client
            .pull_image_manifest(&oci_ref, &oci_client.auth())
            .await?;
        tracing::trace!("Got manifest {manifest:?}");

        let wasm_layers = manifest
            .layers
            .into_iter()
            .filter(|layer| layer.media_type == WASM_LAYER_MEDIA_TYPE)
            .collect::<Vec<_>>();
        if wasm_layers.len() != 1 {
            return Err(Error::InvalidPackageManifest(format!(
                "expected 1 wasm layer; got {}",
                wasm_layers.len()
            )));
        }
        let content = wasm_layers[0].digest.parse()?;
        Ok(Release { version, content })
    }

    /// Copies content into the given [`AsyncWrite`].
    pub async fn copy_content<Pkg>(
        &mut self,
        package: Pkg,
        content: &ContentHash,
        out: impl AsyncWrite + Unpin,
    ) -> Result<(), Error>
    where
        Pkg: TryInto<PackageRef>,
        Pkg::Error: Into<Error>,
    {
        let package = package.try_into().map_err(Into::into)?;
        let (oci_client, oci_ref) = self.resolve_oci_parts(&package, None).await?;

        oci_client
            .client
            .auth(
                &oci_ref,
                &oci_client.auth(),
                oci_distribution::RegistryOperation::Pull,
            )
            .await?;
        oci_client
            .client
            .pull_blob(&oci_ref, &content.to_string(), out.compat_write())
            .await?;
        Ok(())
    }

    /// Returns a [`TryStream`] of content chunks.
    pub async fn stream_content<Pkg>(
        &mut self,
        package: Pkg,
        content: &ContentHash,
    ) -> Result<impl TryStream<Ok = Bytes, Error = Error>, Error>
    where
        Pkg: TryInto<PackageRef>,
        Pkg::Error: Into<Error>,
    {
        let package = package.try_into().map_err(Into::into)?;
        let (oci_client, oci_ref) = self.resolve_oci_parts(&package, None).await?;

        oci_client
            .client
            .auth(
                &oci_ref,
                &oci_client.auth(),
                oci_distribution::RegistryOperation::Pull,
            )
            .await?;
        let stream = oci_client
            .client
            .pull_blob_stream(&oci_ref, &content.to_string())
            .await?;
        Ok(stream.map_err(Into::into))
    }

    // Convenience method for resolving OCI client, reference, and auth for a package.
    async fn resolve_oci_parts(
        &mut self,
        package: &PackageRef,
        version: Option<&Version>,
    ) -> Result<(&mut OciClient, OciReference), Error> {
        let registry = self.config.resolve_package_registry(package)?.to_owned();
        let oci_client = self.get_oci_client(&registry).await?;
        let repo = format!("{}/{}", package.namespace(), package.name());
        let tag = version
            .map(|v| v.to_string())
            .unwrap_or_else(|| "latest".to_owned());
        let reference = OciReference::with_tag(oci_client.registry.to_owned(), repo, tag);

        Ok((oci_client, reference))
    }

    async fn get_oci_client(&mut self, registry: &str) -> Result<&mut OciClient, Error> {
        if !self.oci_clients.contains_key(registry) {
            tracing::debug!("Building new OCI client for {registry:?}");

            let RegistryConfig {
                oci_client_config,
                oci_credentials: oci_client_credentials,
            } = self
                .config
                .registry_configs
                .get(registry)
                .cloned()
                .unwrap_or_default();
            let client = oci_distribution::Client::new(oci_client_config.unwrap_or_default());

            // Check registry metadata for OCI registry override
            let oci_registry = match RegistryMeta::fetch(registry).await {
                Ok(Some(meta)) => meta.oci_registry,
                Ok(None) => None,
                Err(err) => {
                    tracing::warn!("{err}");
                    None
                }
            }
            .unwrap_or_else(|| registry.to_string());

            let client = OciClient {
                client,
                registry: oci_registry,
                credentials: oci_client_credentials.clone(),
            };
            self.oci_clients.insert(registry.to_owned(), client);
        }
        Ok(self.oci_clients.get_mut(registry).unwrap())
    }
}

pub trait IntoVersion {
    fn into_version(self) -> Result<Version, Error>;
}

impl IntoVersion for Version {
    fn into_version(self) -> Result<Version, Error> {
        Ok(self)
    }
}

impl IntoVersion for &str {
    fn into_version(self) -> Result<Version, Error> {
        Ok(Version::parse(self)?)
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid config: {0}")]
    InvalidConfig(anyhow::Error),
    #[error("invalid content hash: {0}")]
    InvalidContentHash(String),
    #[error("invalid label: {0}")]
    InvalidLabel(#[from] InvalidLabel),
    #[error("invalid package ref: {0}")]
    InvalidPackageRef(String),
    #[error("invalid package manifest: {0}")]
    InvalidPackageManifest(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("OCI error: {0}")]
    OciError(#[from] OciDistributionError),
    #[error("no registry configured for namespace {0:?}")]
    NoRegistryForNamespace(Label),
    #[error("registry metadata error: {0}")]
    RegistryMeta(#[source] anyhow::Error),
    #[error("invalid version: {0}")]
    VersionError(#[from] semver::Error),
}
