use semver::Version;

use crate::Error;

#[derive(Clone, Debug)]
pub struct Release {
    pub version: Version,
    pub content_digest: ContentDigest,
}

#[derive(Clone, Debug)]
pub enum ContentDigest {
    Sha256(String),
}

impl std::fmt::Display for ContentDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentDigest::Sha256(hex) => write!(f, "sha256:{hex}"),
        }
    }
}

impl<'a> TryFrom<&'a str> for ContentDigest {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let Some(hex) = value.strip_prefix("sha256:") else {
            return Err(Error::InvalidContentDigest(
                "must start with 'sha256:'".into(),
            ));
        };
        let hex = hex.to_lowercase();
        if hex.len() != 64 {
            return Err(Error::InvalidContentDigest(format!(
                "must be 64 hex digits; got {} chars",
                hex.len()
            )));
        }
        if let Some(invalid) = hex.chars().find(|c| !c.is_ascii_hexdigit()) {
            return Err(Error::InvalidContentDigest(format!(
                "must be hex; got {invalid:?}"
            )));
        }
        Ok(Self::Sha256(hex))
    }
}

impl std::str::FromStr for ContentDigest {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}
