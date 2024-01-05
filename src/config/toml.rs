use std::{collections::HashMap, path::Path};

use anyhow::Context;
use base64::{
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
    Engine,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::Error;

use super::BasicCredentials;

impl super::ClientConfig {
    pub fn from_toml(s: &str) -> Result<Self, Error> {
        let toml_cfg: TomlConfig = toml::from_str(s)
            .context("error parsing TOML")
            .map_err(Error::InvalidConfig)?;
        toml_cfg.try_into().map_err(Error::InvalidConfig)
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::from_toml(std::fs::read_to_string(path)?.as_str())
    }

    pub fn from_default_file() -> Result<Option<Self>, Error> {
        let Some(config_dir) = dirs::config_dir() else {
            return Ok(None);
        };
        let path = config_dir.join("warg").join("config.toml");
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(Self::from_file(path)?))
    }
}

#[derive(Deserialize)]
struct TomlConfig {
    default_registry: Option<String>,
    namespace_registries: HashMap<String, String>,
    registry: HashMap<String, TomlRegistryConfig>,
}

impl TryFrom<TomlConfig> for super::ClientConfig {
    type Error = anyhow::Error;

    fn try_from(value: TomlConfig) -> Result<Self, Self::Error> {
        let TomlConfig {
            default_registry,
            namespace_registries,
            registry,
        } = value;
        let registry_configs = registry
            .into_iter()
            .map(|(k, v)| Ok((k, v.try_into()?)))
            .collect::<Result<_, Self::Error>>()?;
        Ok(Self {
            default_registry,
            namespace_registries,
            registry_configs,
        })
    }
}

#[derive(Deserialize)]
struct TomlRegistryConfig {
    oci_auth: Option<TomlAuth>,
}

impl TryFrom<TomlRegistryConfig> for super::RegistryConfig {
    type Error = anyhow::Error;

    fn try_from(value: TomlRegistryConfig) -> Result<Self, Self::Error> {
        let TomlRegistryConfig { oci_auth } = value;
        let oci_client_credentials = oci_auth.map(TryInto::try_into).transpose()?;
        Ok(Self {
            oci_client_config: None,
            oci_credentials: oci_client_credentials,
        })
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TomlAuth {
    Base64(SecretString),
    UsernamePassword {
        username: String,
        password: SecretString,
    },
}

const OCI_AUTH_BASE64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

impl TryFrom<TomlAuth> for BasicCredentials {
    type Error = anyhow::Error;

    fn try_from(value: TomlAuth) -> Result<Self, Self::Error> {
        match value {
            TomlAuth::Base64(b64) => {
                fn decode_b64_creds(b64: &str) -> anyhow::Result<BasicCredentials> {
                    let bs = OCI_AUTH_BASE64.decode(b64)?;
                    let s = String::from_utf8(bs)?;
                    let (username, password) = s
                        .split_once(':')
                        .context("expected <username>:<password> but no ':' found")?;
                    Ok(BasicCredentials {
                        username: username.into(),
                        password: password.to_string().into(),
                    })
                }
                decode_b64_creds(b64.expose_secret()).context("invalid base64-encoded creds")
            }
            TomlAuth::UsernamePassword { username, password } => {
                Ok(BasicCredentials { username, password })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::ClientConfig;

    use super::*;

    #[test]
    fn smoke_test() {
        let toml_config = r#"
            default_registry = "example.com"

            [namespace_registries]
            wasi = "wasi.dev"

            [registry."example.com"]
            oci_auth = { username = "open", password = "sesame" }

            [registry."wasi.dev"]
            oci_auth = "cGluZzpwb25n"
        "#;
        let cfg = ClientConfig::from_toml(toml_config).unwrap();

        assert_eq!(cfg.default_registry.as_deref(), Some("example.com"));
        assert_eq!(cfg.namespace_registries["wasi"], "wasi.dev");

        let BasicCredentials { username, password } = &cfg.registry_configs["example.com"]
            .oci_credentials
            .as_ref()
            .unwrap();
        assert_eq!(username, "open");
        assert_eq!(password.expose_secret(), "sesame");

        let BasicCredentials { username, password } = cfg.registry_configs["wasi.dev"]
            .oci_credentials
            .as_ref()
            .unwrap();
        assert_eq!(username, "ping");
        assert_eq!(password.expose_secret(), "pong");
    }
}
