mod toml;

use std::collections::HashMap;

use oci_distribution::client::ClientConfig as OciClientConfig;
use secrecy::SecretString;

use crate::{Error, PackageRef};

/// Configuration for [`super::Client`].
#[derive(Clone, Default)]
pub struct ClientConfig {
    /// The default registry name.
    default_registry: Option<String>,
    /// Per-namespace registry, overriding `default_registry` (if present).
    namespace_registries: HashMap<String, String>,
    /// Per-registry configuration.
    pub(crate) registry_configs: HashMap<String, RegistryConfig>,
}

impl ClientConfig {
    pub fn to_client(&self) -> crate::Client {
        crate::Client::new(self.clone())
    }

    pub fn default_registry(&mut self, registry: impl Into<String>) -> &mut Self {
        self.default_registry = Some(registry.into());
        self
    }

    pub fn namespace_registry(
        &mut self,
        namespace: impl Into<String>,
        registry: impl Into<String>,
    ) -> &mut Self {
        self.namespace_registries
            .insert(namespace.into(), registry.into());
        self
    }

    pub fn oci_registry_config(
        &mut self,
        registry: impl Into<String>,
        oci_client_config: Option<OciClientConfig>,
        oci_credentials: Option<BasicCredentials>,
    ) -> Result<&mut Self, Error> {
        if oci_client_config
            .as_ref()
            .is_some_and(|cfg| cfg.platform_resolver.is_some())
        {
            Error::InvalidConfig(anyhow::anyhow!(
                "oci_distribution::client::ClientConfig::platform_resolver not supported"
            ));
        }
        let cfg = RegistryConfig {
            oci_client_config,
            oci_credentials,
        };
        self.registry_configs.insert(registry.into(), cfg);
        Ok(self)
    }

    pub(crate) fn resolve_package_registry(&self, package: &PackageRef) -> Result<&str, Error> {
        let namespace = package.namespace();
        tracing::debug!("Resolving registry for {namespace:?}");

        if let Some(registry) = self.namespace_registries.get(namespace.as_ref()) {
            tracing::debug!("Found namespace-specific registry {registry:?}");
            return Ok(registry);
        }
        if let Some(registry) = &self.default_registry {
            tracing::debug!("No namespace-specific registry; using default {registry:?}");
            return Ok(registry);
        }
        Err(Error::NoRegistryForNamespace(namespace.to_owned()))
    }
}

/// Configuration for a specific registry.
#[derive(Default)]
pub struct RegistryConfig {
    pub oci_client_config: Option<OciClientConfig>,
    pub oci_credentials: Option<BasicCredentials>,
}

impl Clone for RegistryConfig {
    fn clone(&self) -> Self {
        let oci_client_config = self.oci_client_config.as_ref().map(|cfg| OciClientConfig {
            protocol: cfg.protocol.clone(),
            extra_root_certificates: cfg.extra_root_certificates.clone(),
            platform_resolver: None,
            ..*cfg
        });
        Self {
            oci_client_config,
            oci_credentials: self.oci_credentials.clone(),
        }
    }
}

#[derive(Clone)]
pub struct BasicCredentials {
    pub username: String,
    pub password: SecretString,
}
