use async_trait::async_trait;
use bytes::Bytes;
use docker_credential::{CredentialRetrievalError, DockerCredential};
use futures_util::{stream::BoxStream, StreamExt, TryStreamExt};
use oci_distribution::{secrets::RegistryAuth, Reference};
use secrecy::ExposeSecret;
use semver::Version;

use crate::{
    config::{BasicCredentials, RegistryConfig},
    meta::RegistryMeta,
    Digest, Error, PackageRef, PackageSource, Release,
};

const WASM_LAYER_MEDIA_TYPES: &[&str] = &[
    "application/wasm",
    "application/vnd.wasm.content.layer.v1+wasm",
];

pub struct OciSource {
    client: oci_distribution::Client,
    registry: String,
    namespace_prefix: Option<String>,
    credentials: Option<BasicCredentials>,
}

impl OciSource {
    pub fn new(
        registry: String,
        registry_config: RegistryConfig,
        registry_meta: RegistryMeta,
    ) -> Result<Self, Error> {
        let RegistryConfig {
            oci_client_config,
            oci_credentials: oci_client_credentials,
        } = registry_config;

        let client = oci_distribution::Client::new(oci_client_config.unwrap_or_default());

        let oci_registry = registry_meta.oci_registry.clone().unwrap_or(registry);

        Ok(Self {
            client,
            registry: oci_registry,
            namespace_prefix: registry_meta.oci_namespace_prefix,
            credentials: oci_client_credentials.clone(),
        })
    }

    fn get_auth(&self) -> Result<RegistryAuth, Error> {
        if let Some(BasicCredentials { username, password }) = &self.credentials {
            return Ok(RegistryAuth::Basic(
                username.clone(),
                password.expose_secret().clone(),
            ));
        }

        match docker_credential::get_credential(&self.registry) {
            Ok(DockerCredential::UsernamePassword(username, password)) => {
                return Ok(RegistryAuth::Basic(username, password));
            }
            Ok(DockerCredential::IdentityToken(_)) => {
                return Err(Error::CredentialError(anyhow::anyhow!(
                    "identity tokens not supported"
                )));
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
        Reference::with_tag(self.registry.clone(), repository, tag)
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

    async fn stream_content(
        &mut self,
        package: &PackageRef,
        content: &Digest,
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
            .pull_blob_stream(&reference, &content.to_string())
            .await?;
        Ok(stream.map_err(Into::into).boxed())
    }
}
