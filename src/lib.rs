mod label;
mod package;
mod release;

use std::collections::HashMap;

use bytes::Bytes;
use futures_util::{AsyncWrite, TryStream, TryStreamExt};
use label::{InvalidLabel, Label};
use oci_distribution::{
    errors::OciDistributionError, manifest::WASM_LAYER_MEDIA_TYPE,
    secrets::RegistryAuth as OciRegistryAuth, Client as OciClient, Reference as OciReference,
};
pub use package::PackageRef;
pub use release::{ContentHash, Release};
pub use semver::Version;
use tokio_util::compat::FuturesAsyncWriteCompatExt;

/// Re-exported to ease configuration.
pub use oci_distribution::client as oci_client;

/// Configuration for [`Client`].
#[derive(Default)]
pub struct Config {
    /// The default registry name.
    pub default_registry: Option<String>,
    /// Per-namespace registry, overriding `default_registry` (if present).
    pub namespace_registries: HashMap<String, String>,
    /// Per-registry configuration.
    pub registry_configs: HashMap<String, RegistryConfig>,
}

/// Configuration for a specific registry.
#[derive(Default)]
pub struct RegistryConfig {
    /// OCI Distribution client config.
    pub oci_client_config: Option<oci_distribution::client::ClientConfig>,
    /// OCI Distribution client credentials (username, password).
    pub oci_client_credentials: Option<(String, String)>,
}

/// A read-only registry client.
pub struct Client {
    config: Config,
    oci_clients: HashMap<String, OciClient>,
}

impl Client {
    /// Returns a new client with the given [`Config`].
    pub fn new(config: Config) -> Self {
        Self {
            config,
            oci_clients: Default::default(),
        }
    }

    /// Returns a new client with [`Config::default_registry`] set to the
    /// given registry name.
    pub fn with_default_registry(registry: impl Into<String>) -> Self {
        Self::new(Config {
            default_registry: Some(registry.into()),
            ..Default::default()
        })
    }

    /// Returns a list of all package [`Version`]s available for the given package.
    pub async fn list_all_versions<Pkg>(&mut self, package: Pkg) -> Result<Vec<Version>, Error>
    where
        Pkg: TryInto<PackageRef>,
        Pkg::Error: Into<Error>,
    {
        let package = package.try_into().map_err(Into::into)?;
        let (oci_client, oci_ref, oci_auth) = self.resolve_oci_parts(&package, None)?;

        tracing::debug!("Listing tags for OCI reference {oci_ref:?}");
        let resp = oci_client
            .list_tags(&oci_ref, &oci_auth, None, None)
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
        let (oci_client, oci_ref, oci_auth) = self.resolve_oci_parts(&package, Some(&version))?;

        tracing::debug!("Fetching image manifest for OCI reference {oci_ref:?}");
        let (manifest, _digest) = oci_client.pull_image_manifest(&oci_ref, &oci_auth).await?;
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
        let (oci_client, oci_ref, oci_auth) = self.resolve_oci_parts(&package, None)?;

        oci_client
            .auth(
                &oci_ref,
                &oci_auth,
                oci_distribution::RegistryOperation::Pull,
            )
            .await?;
        oci_client
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
        let (oci_client, oci_ref, oci_auth) = self.resolve_oci_parts(&package, None)?;

        oci_client
            .auth(
                &oci_ref,
                &oci_auth,
                oci_distribution::RegistryOperation::Pull,
            )
            .await?;
        let stream = oci_client
            .pull_blob_stream(&oci_ref, &content.to_string())
            .await?;
        Ok(stream.map_err(Into::into))
    }

    // Convenience method for resolving OCI client, reference, and auth for a package.
    fn resolve_oci_parts(
        &mut self,
        package: &PackageRef,
        version: Option<&Version>,
    ) -> Result<(&mut OciClient, OciReference, OciRegistryAuth), Error> {
        let registry = self.registry_for_package(package)?.to_owned();
        let repo = format!("{}/{}", package.namespace(), package.name());
        let tag = version
            .map(|v| v.to_string())
            .unwrap_or_else(|| "latest".to_owned());
        let reference = OciReference::with_tag(registry.to_owned(), repo, tag);
        let auth = self.get_oci_auth(&registry);
        let client = self.get_oci_client(&registry)?;
        Ok((client, reference, auth))
    }

    fn registry_for_package(&self, package: &PackageRef) -> Result<&str, Error> {
        let namespace = package.namespace();
        tracing::debug!("Resolving registry for {namespace:?}");

        if let Some(registry) = self.config.namespace_registries.get(namespace.as_ref()) {
            tracing::debug!("Found namespace-specific registry {registry:?}");
            return Ok(registry);
        }
        if let Some(registry) = &self.config.default_registry {
            tracing::debug!("No namespace-specific registry; using default {registry:?}");
            return Ok(registry);
        }
        Err(Error::NoRegistryForNamespace(namespace.to_owned()))
    }

    fn get_oci_client(&mut self, registry: &str) -> Result<&mut OciClient, Error> {
        if !self.oci_clients.contains_key(registry) {
            tracing::debug!("Building new OCI client for {registry:?}");
            // oci_distribution::ClientConfig doesn't implement Clone, so take it
            let client_config = self
                .config
                .registry_configs
                .get_mut(registry)
                .and_then(|c| c.oci_client_config.take())
                .unwrap_or_default();
            let client = client_config.try_into()?;
            self.oci_clients.insert(registry.to_owned(), client);
        }
        Ok(self.oci_clients.get_mut(registry).unwrap())
    }

    fn get_oci_auth(&self, registry: &str) -> OciRegistryAuth {
        match self.config.registry_configs.get(registry) {
            Some(RegistryConfig {
                oci_client_credentials: Some((username, password)),
                ..
            }) => OciRegistryAuth::Basic(username.clone(), password.clone()),
            _ => OciRegistryAuth::Anonymous,
        }
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
    #[error("invalid version: {0}")]
    VersionError(#[from] semver::Error),
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;

    #[tokio::test]
    async fn smoke_test() {
        const PKG: &str = "test:pkg";
        const VER: &str = "1.0.0";
        const CONTENT_FILE: &str = "warg-pkg.wasm";
        const CONTENT: &[u8] = b"test content";

        eprintln!("{}", "#".repeat(60));
        eprintln!("This test expects:");
        eprintln!("- an OCI distribution server running at localhost:5000");
        eprintln!("- the `oras` tool to be installed");
        eprintln!("{}", "#".repeat(60));

        // Push package with `oras`
        let tempdir = std::env::temp_dir();
        let content_path = tempdir.join(CONTENT_FILE);
        std::fs::write(&content_path, CONTENT).unwrap();
        let status = Command::new("oras")
            .current_dir(tempdir)
            .arg("push")
            .arg(format!(
                "localhost:5000/{pkg}:{VER}",
                pkg = PKG.replace(':', "/")
            ))
            .arg(format!("{CONTENT_FILE}:{WASM_LAYER_MEDIA_TYPE}"))
            .status()
            .unwrap();
        assert!(status.success(), "{status:?}");

        // Fetch package
        let mut client = Client::new(Config {
            default_registry: Some("localhost:5000".into()),
            registry_configs: [(
                "localhost:5000".into(),
                RegistryConfig {
                    oci_client_config: Some(oci_client::ClientConfig {
                        protocol: oci_client::ClientProtocol::Http,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )]
            .into(),
            ..Default::default()
        });

        let versions = client.list_all_versions("test:pkg").await.unwrap();
        let version = versions.into_iter().next().unwrap();
        assert_eq!(version.to_string(), VER);

        let release = client.get_release("test:pkg", version).await.unwrap();
        let content = client
            .stream_content("test:pkg", &release.content)
            .await
            .unwrap()
            .try_collect::<bytes::BytesMut>()
            .await
            .unwrap();
        assert_eq!(content, CONTENT);
    }
}
