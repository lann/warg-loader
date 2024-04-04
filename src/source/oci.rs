use async_trait::async_trait;
use bytes::Bytes;
use docker_credential::{CredentialRetrievalError, DockerCredential};
use futures_util::{stream::BoxStream, StreamExt, TryStreamExt};
use oci_distribution::{client::ClientConfig, secrets::RegistryAuth, Reference};
use secrecy::ExposeSecret;
use semver::Version;

use crate::{
    config::BasicCredentials, meta::RegistryMeta, source::PackageSource, Error, PackageRef, Release,
};

const WASM_LAYER_MEDIA_TYPES: &[&str] = &[
    "application/wasm",
    "application/vnd.wasm.content.layer.v1+wasm",
];

#[derive(Default)]
pub struct OciConfig {
    pub client_config: Option<ClientConfig>,
    pub credentials: Option<BasicCredentials>,
}

impl Clone for OciConfig {
    fn clone(&self) -> Self {
        let client_config = self.client_config.as_ref().map(|cfg| ClientConfig {
            protocol: cfg.protocol.clone(),
            extra_root_certificates: cfg.extra_root_certificates.clone(),
            platform_resolver: None,
            ..*cfg
        });
        Self {
            client_config,
            credentials: self.credentials.clone(),
        }
    }
}

impl std::fmt::Debug for OciConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OciConfig")
            .field("client_config", &self.client_config.as_ref().map(|_| "..."))
            .field("credentials", &self.credentials)
            .finish()
    }
}

pub struct OciSource {
    client: oci_distribution::Client,
    oci_registry: String,
    namespace_prefix: Option<String>,
    credentials: Option<BasicCredentials>,
}

impl OciSource {
    pub fn new(
        registry: String,
        config: OciConfig,
        registry_meta: RegistryMeta,
    ) -> Result<Self, Error> {
        let OciConfig {
            client_config,
            credentials,
        } = config;
        let client = oci_distribution::Client::new(client_config.unwrap_or_default());

        let oci_registry = registry_meta.oci_registry.unwrap_or(registry);

        Ok(Self {
            client,
            oci_registry,
            namespace_prefix: registry_meta.oci_namespace_prefix,
            credentials,
        })
    }

    fn get_auth(&self) -> Result<RegistryAuth, Error> {
        if let Some(BasicCredentials { username, password }) = &self.credentials {
            return Ok(RegistryAuth::Basic(
                username.clone(),
                password.expose_secret().clone(),
            ));
        }

        let server_url = format!("https://{}", self.oci_registry);
        match docker_credential::get_credential(&server_url) {
            Ok(DockerCredential::UsernamePassword(username, password)) => {
                return Ok(RegistryAuth::Basic(username, password));
            }
            Ok(DockerCredential::IdentityToken(_)) => {
                return Err(Error::CredentialError(anyhow::anyhow!(
                    "identity tokens not supported"
                )));
            }
            Err(err @ CredentialRetrievalError::HelperFailure { .. }) => {
                tracing::info!("Docker credential helper failed: {err:?}");
            }
            Err(
                CredentialRetrievalError::ConfigNotFound
                | CredentialRetrievalError::NoCredentialConfigured,
            ) => (),
            Err(err) => return Err(Error::CredentialError(err.into())),
        }

        Ok(RegistryAuth::Anonymous)
    }

    fn make_reference(&self, package: &PackageRef, version: Option<&Version>) -> Reference {
        let repository = format!(
            "{}{}/{}",
            self.namespace_prefix.as_deref().unwrap_or_default(),
            package.namespace(),
            package.name()
        );
        let tag = version
            .map(|ver| ver.to_string())
            .unwrap_or_else(|| "latest".into());
        Reference::with_tag(self.oci_registry.clone(), repository, tag)
    }
}

#[async_trait]
impl PackageSource for OciSource {
    async fn list_all_versions(&mut self, package: &PackageRef) -> Result<Vec<Version>, Error> {
        let reference = self.make_reference(package, None);

        tracing::debug!("Listing tags for OCI reference {reference:?}");
        let resp = self
            .client
            .list_tags(&reference, &self.get_auth()?, None, None)
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

    async fn get_release(
        &mut self,
        package: &PackageRef,
        version: &Version,
    ) -> Result<Release, Error> {
        let reference = self.make_reference(package, Some(version));

        tracing::debug!("Fetching image manifest for OCI reference {reference:?}");
        let (manifest, _digest) = self
            .client
            .pull_image_manifest(&reference, &self.get_auth()?)
            .await?;
        tracing::trace!("Got manifest {manifest:?}");

        // Pending standardization of an OCI manifest/config format, a package
        // artifact must contain exactly one layer with a known wasm media type
        // (other non-wasm layers may be present as well).
        let wasm_layers = manifest
            .layers
            .into_iter()
            .filter(|layer| WASM_LAYER_MEDIA_TYPES.contains(&layer.media_type.as_str()))
            .collect::<Vec<_>>();
        if wasm_layers.len() != 1 {
            return Err(Error::InvalidPackageManifest(format!(
                "expected 1 wasm layer; got {}",
                wasm_layers.len()
            )));
        }
        let version = version.clone();
        let content_digest = wasm_layers[0].digest.parse()?;
        Ok(Release {
            version,
            content_digest,
        })
    }

    async fn stream_content_unvalidated(
        &mut self,
        package: &PackageRef,
        release: &Release,
    ) -> Result<BoxStream<Result<Bytes, Error>>, Error> {
        let reference = self.make_reference(package, None);
        self.client
            .auth(
                &reference,
                &self.get_auth()?,
                oci_distribution::RegistryOperation::Pull,
            )
            .await?;
        let stream = self
            .client
            .pull_blob_stream(&reference, &release.content_digest.to_string())
            .await?;
        Ok(stream.map_err(Into::into).boxed())
    }
}
